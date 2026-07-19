/**
 * BypassAI.online — Core API
 *
 * Routes:
 *   POST /humanize  — full Guardrail + multi-language rewrite pipeline
 *   POST /score     — AI probability score (HuggingFace)
 *   GET  /health    — liveness check
 *
 * Architecture (per the handover doc):
 *   Layer 1 (Guardrail): protect citations & technical terms
 *   Layer 2-3 (Rewrite): 3-mode multi-language pipeline
 *     - Standard: EN → CN → EN
 *     - Creative: EN → FI → EN
 *     - Academic: EN → CN → JP → FI → EN (4 hops, Guardrail preserved)
 *   Layer 4 (Restore): put protected terms back verbatim
 *   Then: AI score check (HuggingFace followsci/bert-ai-text-detector)
 */

export interface Env {
  DEEPSEEK_API_KEY: string;
  HUGGINGFACE_API_KEY: string;
  GOOGLE_TRANSLATE_KEY?: string;
  ALLOWED_ORIGIN: string;
  ENVIRONMENT: string;
}

// ===============================
// CORS — locked to allowed origin only
// ===============================
function corsHeaders(origin: string, allowed: string): HeadersInit {
  // 严格匹配，不允许通配符
  const allowOrigin = origin === allowed ? origin : allowed;
  return {
    "Access-Control-Allow-Origin": allowOrigin,
    "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin",
  };
}

function jsonResponse(data: unknown, status: number, origin: string, env: Env): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      ...corsHeaders(origin, env.ALLOWED_ORIGIN),
    },
  });
}

// ===============================
// Layer 1: Term Protection (Guardrail)
// ===============================
interface GuardrailState {
  processedText: string;
  protectedMap: Map<string, string>;
}

function protectTerms(text: string): GuardrailState {
  const protectedMap = new Map<string, string>();
  let counter = 0;

  // 保护参考文献: [12], [1-3], (Smith et al., 2023)
  const citationRegex = /(\[\d+[\d\s\-,]*\]|\([A-Z][a-z]+(\s+et\s+al\.)?,\s+\d{4}\))/g;
  // 保护专业术语: PCSK9, LDL-C, ASCVD, GPT-4 等
  const techTermRegex = /\b([A-Z]{2,}\d*(-[A-Z0-9]+)*)\b/g;

  let processed = text.replace(citationRegex, (match) => {
    const id = `[[REF_${counter++}]]`;
    protectedMap.set(id, match);
    return id;
  });

  processed = processed.replace(techTermRegex, (match) => {
    const id = `[[TERM_${counter++}]]`;
    protectedMap.set(id, match);
    return id;
  });

  return { processedText: processed, protectedMap };
}

// Layer 4: Term Restoration
function restoreTerms(text: string, protectedMap: Map<string, string>): string {
  let result = text;
  for (const [id, original] of protectedMap.entries()) {
    result = result.split(id).join(original);
  }
  return result;
}

// ===============================
// DeepSeek V3 call
// ===============================
async function callDeepSeek(
  content: string,
  systemPrompt: string,
  apiKey: string,
  timeoutMs = 30000
): Promise<string> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch("https://api.deepseek.com/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model: "deepseek-chat",
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content },
        ],
        temperature: 1.2,
        max_tokens: 4000,
      }),
      signal: controller.signal,
    });

    if (!response.ok) {
      const errBody = await response.text().catch(() => "");
      throw new Error(`DeepSeek ${response.status}: ${errBody.slice(0, 200)}`);
    }

    const data = (await response.json()) as {
      choices?: Array<{ message?: { content?: string } }>;
    };
    const text = data.choices?.[0]?.message?.content;
    if (!text) throw new Error("DeepSeek returned empty content");
    return text.trim();
  } finally {
    clearTimeout(timer);
  }
}

// ===============================
// Translation (NIU Trans → Google fallback)
// ===============================
async function callTranslationAPI(
  text: string,
  fromLang: string,
  toLang: string,
  googleKey?: string
): Promise<string> {
  // Try NIU Trans (free tier, no key)
  try {
    const res = await fetch(
      `https://api.niutrans.com/trans?text=${encodeURIComponent(text)}&from=${fromLang}&to=${toLang}`,
      { signal: AbortSignal.timeout(10000) }
    );
    if (res.ok) {
      const data = (await res.json()) as { data?: string };
      if (data.data) return data.data;
    }
  } catch {
    // fall through to Google
  }

  // Fallback to Google Translate
  if (!googleKey) {
    throw new Error("Translation failed and no Google fallback key configured");
  }

  const res = await fetch(
    `https://translation.googleapis.com/language/translate/v2?key=${googleKey}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        q: text,
        source: fromLang,
        target: toLang,
        format: "text",
      }),
      signal: AbortSignal.timeout(10000),
    }
  );

  if (!res.ok) throw new Error(`Google Translate ${res.status}`);
  const data = (await res.json()) as {
    data?: { translations?: Array<{ translatedText?: string }> };
  };
  return data.data?.translations?.[0]?.translatedText || text;
}

// ===============================
// Layer 2 + 3: Multi-language Pipeline
// ===============================
async function humanizePipeline(
  originalText: string,
  mode: "standard" | "academic" | "creative",
  env: Env
): Promise<string> {
  const { processedText, protectedMap } = protectTerms(originalText);

  let result = processedText;

  try {
    if (mode === "academic") {
      // EN → CN → JP → FI → EN
      const cn = await callDeepSeek(
        result,
        "Translate to simplified Chinese. PRESERVE all [[REF_n]] and [[TERM_n]] placeholders exactly as-is.",
        env.DEEPSEEK_API_KEY
      );
      const jp = await callDeepSeek(
        cn,
        "Translate to Japanese. PRESERVE all placeholders exactly.",
        env.DEEPSEEK_API_KEY
      );
      const fi = await callTranslationAPI(jp, "ja", "fi", env.GOOGLE_TRANSLATE_KEY);
      result = await callDeepSeek(
        fi,
        `Task: Translate Finnish text back to professional English.
Reference (original meaning): "${processedText.slice(0, 500)}"
Style Requirements (CRITICAL):
- HIGH BURSTINESS: Mix short punchy sentences with complex, flowing ones.
- HIGH PERPLEXITY: Use diverse, non-robotic vocabulary. Avoid word repetition.
- FORBIDDEN WORDS: Do NOT use: delve, testament, comprehensive, intricate, showcases, multifaceted, it is worth noting, in conclusion, further research is needed, this essay will explore, it is evident that, the data suggests, the implications are far-reaching, testament to, a nuanced perspective.
- CRUCIAL: Keep ALL [[REF_n]] and [[TERM_n]] placeholders exactly as-is.
- Output ONLY the translated English text, nothing else.`,
        env.DEEPSEEK_API_KEY
      );
    } else if (mode === "creative") {
      // EN → FI → EN (high creativity)
      const fi = await callTranslationAPI(result, "en", "fi", env.GOOGLE_TRANSLATE_KEY);
      result = await callDeepSeek(
        fi,
        `Task: Translate to English with HIGH CREATIVITY.
- Temperature 1.2: Take creative risks with word choice.
- High Burstiness: Mix very short sentences with longer ones.
- Avoid: delve, testament, comprehensive, intricate, showcases.
- Output ONLY the translated English text.`,
        env.DEEPSEEK_API_KEY
      );
    } else {
      // Standard: EN → CN → EN
      const cn = await callDeepSeek(
        result,
        "Translate to Chinese naturally. Keep placeholders as-is.",
        env.DEEPSEEK_API_KEY
      );
      result = await callDeepSeek(
        cn,
        "Translate back to English. Make it sound genuinely human-written. Avoid AI clichés.",
        env.DEEPSEEK_API_KEY
      );
    }

    // Layer 4: Restore protected terms
    return restoreTerms(result, protectedMap);
  } catch (error) {
    console.error("Pipeline error:", error);
    throw new Error(
      `Humanization failed: ${error instanceof Error ? error.message : String(error)}`
    );
  }
}

// ===============================
// AI Score (HuggingFace)
// ===============================
async function getAIScore(text: string, apiKey: string): Promise<number | null> {
  try {
    const res = await fetch(
      "https://api-inference.huggingface.co/models/followsci/bert-ai-text-detector",
      {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${apiKey}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ inputs: text }),
        signal: AbortSignal.timeout(15000),
      }
    );

    if (!res.ok) return null;

    const data = (await res.json()) as Array<Array<{ label: string; score: number }>>;
    // Response shape: [[{label: "LABEL_1" (AI), score: 0.87}, {label: "LABEL_0" (human), score: 0.13}]]
    if (Array.isArray(data) && data[0] && Array.isArray(data[0])) {
      const aiEntry = data[0].find((e) => e.label === "LABEL_1" || /ai/i.test(e.label));
      return aiEntry ? aiEntry.score : null;
    }
    return null;
  } catch (e) {
    console.error("AI Score error:", e);
    return null;
  }
}

// ===============================
// Rate limiter (IP-based, in-memory, best-effort)
// ===============================
const rateLimitMap = new Map<string, { count: number; resetAt: number }>();
const FREE_DAILY_LIMIT = 3;

function checkRateLimit(ip: string): { allowed: boolean; remaining: number; resetAt: number } {
  const now = Date.now();
  const dayMs = 24 * 60 * 60 * 1000;

  const record = rateLimitMap.get(ip);
  if (!record || record.resetAt < now) {
    const resetAt = now + dayMs;
    rateLimitMap.set(ip, { count: 1, resetAt });
    return { allowed: true, remaining: FREE_DAILY_LIMIT - 1, resetAt };
  }

  if (record.count >= FREE_DAILY_LIMIT) {
    return { allowed: false, remaining: 0, resetAt: record.resetAt };
  }

  record.count++;
  return {
    allowed: true,
    remaining: FREE_DAILY_LIMIT - record.count,
    resetAt: record.resetAt,
  };
}

// ===============================
// Worker entry
// ===============================
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const origin = request.headers.get("Origin") || "";
    const url = new URL(request.url);

    // CORS preflight
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: corsHeaders(origin, env.ALLOWED_ORIGIN),
      });
    }

    // Health check
    if (url.pathname === "/health") {
      return jsonResponse({ status: "ok", env: env.ENVIRONMENT }, 200, origin, env);
    }

    // Origin check (for non-preflight requests)
    // 允许 ALLOWED_ORIGIN 和本地开发
    const allowedOrigins = [env.ALLOWED_ORIGIN, "http://localhost:3000", "http://127.0.0.1:3000"];
    if (origin && !allowedOrigins.includes(origin)) {
      return jsonResponse({ error: "Forbidden origin" }, 403, origin, env);
    }

    // ===== POST /humanize =====
    if (url.pathname === "/humanize" && request.method === "POST") {
      const ip = request.headers.get("CF-Connecting-IP") || "unknown";
      const rl = checkRateLimit(ip);
      if (!rl.allowed) {
        return jsonResponse(
          {
            error: "Daily free limit reached. Upgrade to Pro for unlimited rewrites.",
            limit: FREE_DAILY_LIMIT,
            resetAt: new Date(rl.resetAt).toISOString(),
          },
          429,
          origin,
          env
        );
      }

      try {
        const body = (await request.json()) as { text?: string; mode?: string };
        const text = body.text?.trim();
        const mode = (body.mode || "standard") as "standard" | "academic" | "creative";

        if (!text) {
          return jsonResponse({ error: "Text is required" }, 400, origin, env);
        }

        const wordCount = text.split(/\s+/).length;
        if (wordCount > 500) {
          return jsonResponse(
            { error: "Free tier supports up to 500 words. Upgrade to Pro." },
            400,
            origin,
            env
          );
        }

        if (!["standard", "academic", "creative"].includes(mode)) {
          return jsonResponse({ error: `Invalid mode: ${mode}` }, 400, origin, env);
        }

        // 缺 key 时给清晰的错误（而不是沉默地失败）
        if (!env.DEEPSEEK_API_KEY) {
          return jsonResponse(
            {
              error: "Service temporarily unavailable: DeepSeek API key not configured.",
              hint: "Set DEEPSEEK_API_KEY via `wrangler secret put DEEPSEEK_API_KEY`",
            },
            503,
            origin,
            env
          );
        }

        const humanized = await humanizePipeline(text, mode, env);
        const score = env.HUGGINGFACE_API_KEY
          ? await getAIScore(humanized, env.HUGGINGFACE_API_KEY)
          : null;

        return jsonResponse(
          {
            result: humanized,
            aiScore: score !== null ? `${(score * 100).toFixed(1)}%` : "N/A",
            originalWordCount: wordCount,
            remaining: rl.remaining,
          },
          200,
          origin,
          env
        );
      } catch (error) {
        return jsonResponse(
          { error: error instanceof Error ? error.message : "Internal error" },
          500,
          origin,
          env
        );
      }
    }

    // ===== POST /score (lightweight score-only) =====
    if (url.pathname === "/score" && request.method === "POST") {
      try {
        const body = (await request.json()) as { text?: string };
        const text = body.text?.trim();
        if (!text) return jsonResponse({ error: "Text is required" }, 400, origin, env);
        if (!env.HUGGINGFACE_API_KEY) {
          return jsonResponse({ score: null, note: "HUGGINGFACE_API_KEY not set" }, 200, origin, env);
        }
        const score = await getAIScore(text, env.HUGGINGFACE_API_KEY);
        return jsonResponse(
          { score: score !== null ? Math.round(score * 100) : null },
          200,
          origin,
          env
        );
      } catch (error) {
        return jsonResponse(
          { error: error instanceof Error ? error.message : "Internal error" },
          500,
          origin,
          env
        );
      }
    }

    return jsonResponse(
      {
        service: "bypass-ai-api",
        routes: ["POST /humanize", "POST /score", "GET /health"],
      },
      200,
      origin,
      env
    );
  },
};