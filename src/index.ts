/**
 * BypassAI.online — Core API + PayPal Subscriptions (Production-Ready)
 *
 * Webhook reliability:
 * - Signature verification via PayPal's verify-webhook-signature API
 * - Persistent state in Cloudflare KV (survives worker restart)
 * - Returns 5xx on transient errors to trigger PayPal retry
 *
 * Routes:
 *   POST /humanize       — full Guardrail + multi-language rewrite pipeline
 *   POST /score          — AI probability score (HuggingFace)
 *   POST /subscribe      — create PayPal subscription, return approval URL
 *   GET  /subscription/:id — query PayPal for current status
 *   POST /webhooks/paypal — verified PayPal webhook receiver (writes to KV)
 *   GET  /subscription/store/:id — debug: inspect persisted KV state
 *   GET  /health         — liveness check
 */

export interface Env {
  // Humanize
  DEEPSEEK_API_KEY: string;
  HUGGINGFACE_API_KEY: string;
  GOOGLE_TRANSLATE_KEY?: string;

  // PayPal
  PAYPAL_CLIENT_ID: string;
  PAYPAL_CLIENT_SECRET: string;
  PAYPAL_ENV: "sandbox" | "live";
  PAYPAL_PLAN_PRO: string;
  PAYPAL_PLAN_ACADEMIC: string;
  PAYPAL_WEBHOOK_ID: string;
  // Optional: override return/cancel URLs after PayPal checkout (default = ALLOWED_ORIGIN)
  PAYPAL_RETURN_URL?: string;
  PAYPAL_CANCEL_URL?: string;
  // Optional: extra allowed origins (comma-separated), e.g. "https://bodyscore.me,https://www.bodyscore.me"
  EXTRA_ALLOWED_ORIGINS?: string;

  // KV binding
  SUBSCRIPTIONS: KVNamespace;

  ALLOWED_ORIGIN: string;
  ENVIRONMENT: string;
}

const PAYPAL_API = (env: Env) =>
  env.PAYPAL_ENV === "live"
    ? "https://api-m.paypal.com"
    : "https://api-m.sandbox.paypal.com";

// ===============================
// KV key helpers
// ===============================
const KV_KEYS = {
  subscription: (id: string) => `sub:${id}`,
  eventLog: (id: string) => `event:${id}`,
};

// TTL: 90 days for subscriptions (in case user comes back)
const SUBSCRIPTION_TTL_SECONDS = 90 * 24 * 60 * 60;

// ===============================
// CORS
// ===============================
function corsHeaders(origin: string, allowed: string): HeadersInit {
  const allowOrigin = origin === allowed ? origin : allowed;
  return {
    "Access-Control-Allow-Origin": allowOrigin,
    "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, PayPal-Auth-Assertion",
    "Access-Control-Max-Age": "86400",
    Vary: "Origin",
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
// PayPal: get access token (cached)
// ===============================
let cachedToken: { token: string; envId: string; expiresAt: number } | null = null;

async function getPayPalToken(env: Env): Promise<string> {
  // Simple in-memory cache (per Worker instance) — fine because PayPal tokens last ~9h
  const envId = env.PAYPAL_CLIENT_ID;
  if (cachedToken && cachedToken.envId === envId && cachedToken.expiresAt > Date.now() + 60_000) {
    return cachedToken.token;
  }

  const auth = btoa(`${env.PAYPAL_CLIENT_ID}:${env.PAYPAL_CLIENT_SECRET}`);
  const res = await fetch(`${PAYPAL_API(env)}/v1/oauth2/token`, {
    method: "POST",
    headers: {
      Authorization: `Basic ${auth}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: "grant_type=client_credentials",
  });
  if (!res.ok) {
    const err = await res.text().catch(() => "");
    throw new Error(`PayPal auth failed: ${res.status} ${err.slice(0, 200)}`);
  }
  const data = (await res.json()) as { access_token: string; expires_in: number };
  cachedToken = {
    token: data.access_token,
    envId,
    expiresAt: Date.now() + data.expires_in * 1000,
  };
  return data.access_token;
}

// ===============================
// PayPal webhook signature verification
// ===============================
interface WebhookHeaders {
  transmissionId: string;
  transmissionTime: string;
  transmissionSig: string;
  certUrl: string;
  authAlgo: string;
}

function extractWebhookHeaders(request: Request): WebhookHeaders | null {
  const transmissionId = request.headers.get("PAYPAL-TRANSMISSION-ID");
  const transmissionTime = request.headers.get("PAYPAL-TRANSMISSION-TIME");
  const transmissionSig = request.headers.get("PAYPAL-TRANSMISSION-SIG");
  const certUrl = request.headers.get("PAYPAL-CERT-URL");
  const authAlgo = request.headers.get("PAYPAL-AUTH-ALGO");
  if (!transmissionId || !transmissionTime || !transmissionSig || !certUrl || !authAlgo) {
    return null;
  }
  return { transmissionId, transmissionTime, transmissionSig, certUrl, authAlgo };
}

async function verifyWebhookSignature(
  headers: WebhookHeaders,
  rawBody: string,
  env: Env
): Promise<boolean> {
  try {
    const token = await getPayPalToken(env);
    const verifyRes = await fetch(`${PAYPAL_API(env)}/v1/notifications/verify-webhook-signature`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        auth_algo: headers.authAlgo,
        cert_url: headers.certUrl,
        transmission_id: headers.transmissionId,
        transmission_sig: headers.transmissionSig,
        transmission_time: headers.transmissionTime,
        webhook_id: env.PAYPAL_WEBHOOK_ID,
        webhook_event: JSON.parse(rawBody),
      }),
    });
    if (!verifyRes.ok) {
      console.error(`[Webhook Verify] HTTP ${verifyRes.status}`);
      return false;
    }
    const result = (await verifyRes.json()) as { verification_status?: string };
    return result.verification_status === "SUCCESS";
  } catch (e) {
    console.error("[Webhook Verify] Error:", e);
    return false;
  }
}

// ===============================
// Subscription persistence (KV)
// ===============================
interface SubscriptionRecord {
  subscriptionId: string;
  plan: string;
  status: string;
  email?: string;
  createdAt: number;
  updatedAt: number;
  lastEventType: string;
}

async function saveSubscription(env: Env, record: SubscriptionRecord): Promise<void> {
  await env.SUBSCRIPTIONS.put(KV_KEYS.subscription(record.subscriptionId), JSON.stringify(record), {
    expirationTtl: SUBSCRIPTION_TTL_SECONDS,
  });
}

async function getSubscription(env: Env, id: string): Promise<SubscriptionRecord | null> {
  const raw = await env.SUBSCRIPTIONS.get(KV_KEYS.subscription(id));
  if (!raw) return null;
  try {
    return JSON.parse(raw) as SubscriptionRecord;
  } catch {
    return null;
  }
}

// ===============================
// Layer 1: Term Protection (Guardrail)
// ===============================
function protectTerms(text: string): { processedText: string; protectedMap: Map<string, string> } {
  const protectedMap = new Map<string, string>();
  let counter = 0;
  const citationRegex = /(\[\d+[\d\s\-,]*\]|\([A-Z][a-z]+(\s+et\s+al\.)?,\s+\d{4}\))/g;
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

function restoreTerms(text: string, protectedMap: Map<string, string>): string {
  let result = text;
  for (const [id, original] of protectedMap.entries()) {
    result = result.split(id).join(original);
  }
  return result;
}

// ===============================
// DeepSeek + Translation
// ===============================
async function callDeepSeek(content: string, systemPrompt: string, apiKey: string): Promise<string> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 30000);
  try {
    const response = await fetch("https://api.deepseek.com/v1/chat/completions", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${apiKey}` },
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
    const data = (await response.json()) as { choices?: Array<{ message?: { content?: string } }> };
    const text = data.choices?.[0]?.message?.content;
    if (!text) throw new Error("DeepSeek returned empty content");
    return text.trim();
  } finally {
    clearTimeout(timer);
  }
}

async function callTranslationAPI(text: string, fromLang: string, toLang: string, googleKey?: string): Promise<string> {
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
    // fall through
  }
  if (!googleKey) throw new Error("Translation failed and no Google fallback");
  const res = await fetch(`https://translation.googleapis.com/language/translate/v2?key=${googleKey}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ q: text, source: fromLang, target: toLang, format: "text" }),
    signal: AbortSignal.timeout(10000),
  });
  if (!res.ok) throw new Error(`Google Translate ${res.status}`);
  const data = (await res.json()) as { data?: { translations?: Array<{ translatedText?: string }> } };
  return data.data?.translations?.[0]?.translatedText || text;
}

async function humanizePipeline(originalText: string, mode: "standard" | "academic" | "creative", env: Env): Promise<string> {
  const { processedText, protectedMap } = protectTerms(originalText);
  let result = processedText;
  try {
    if (mode === "academic") {
      // Academic: EN → CN → JP → FI → EN (4 hops via DeepSeek for consistency)
      const cn = await callDeepSeek(result, "Translate to simplified Chinese. PRESERVE all [[REF_n]] and [[TERM_n]] placeholders exactly as-is.", env.DEEPSEEK_API_KEY);
      const jp = await callDeepSeek(cn, "Translate to Japanese. PRESERVE all placeholders exactly.", env.DEEPSEEK_API_KEY);
      // Use DeepSeek for FI translation too (avoids NIU Trans 404 / Google Translate API key requirement)
      const fi = await callDeepSeek(jp, "Translate to Finnish (suomi). PRESERVE all [[REF_n]] and [[TERM_n]] placeholders exactly.", env.DEEPSEEK_API_KEY);
      result = await callDeepSeek(fi, `Task: Translate Finnish text back to professional English.
Reference (original meaning): "${processedText.slice(0, 500)}"
Style: HIGH BURSTINESS (mix short punchy sentences with longer flowing ones), HIGH PERPLEXITY (varied vocabulary, avoid repetition).
Avoid these AI clichés: delve, testament, comprehensive, intricate, showcases, multifaceted, it is worth noting, in conclusion, further research is needed.
CRUCIAL: Keep ALL [[REF_n]] and [[TERM_n]] placeholders exactly as-is.
Output ONLY the translated English text.`, env.DEEPSEEK_API_KEY);
    } else if (mode === "creative") {
      // Creative: EN → FI → EN via DeepSeek
      const fi = await callDeepSeek(result, "Translate to Finnish (suomi). PRESERVE all placeholders exactly.", env.DEEPSEEK_API_KEY);
      result = await callDeepSeek(fi, `Task: Translate to English with HIGH CREATIVITY. Vary sentence length, use unexpected word choices, avoid repetition.
Avoid AI clichés: delve, testament, comprehensive, intricate, showcases.
Output ONLY the translated English text.`, env.DEEPSEEK_API_KEY);
    } else {
      // Standard: EN → CN → EN
      const cn = await callDeepSeek(result, "Translate to Chinese naturally. Keep placeholders as-is.", env.DEEPSEEK_API_KEY);
      result = await callDeepSeek(cn, "Translate back to English. Make it sound genuinely human-written. Avoid AI clichés.", env.DEEPSEEK_API_KEY);
    }
    return restoreTerms(result, protectedMap);
  } catch (error) {
    throw new Error(`Humanization failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

async function getAIScore(text: string, apiKey: string): Promise<number | null> {
  try {
    // HF Inference API: api-inference.huggingface.co was deprecated; use router.huggingface.co
    // followsci/bert-ai-text-detector is no longer supported by hf-inference provider,
    // switch to Hello-SimpleAI/chatgpt-detector-roberta (returns label "ChatGPT" / "Human")
    const res = await fetch(
      "https://router.huggingface.co/hf-inference/models/Hello-SimpleAI/chatgpt-detector-roberta",
      {
        method: "POST",
        headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" },
        body: JSON.stringify({ inputs: text }),
        signal: AbortSignal.timeout(15000),
      }
    );
    if (!res.ok) return null;
    const data = (await res.json()) as Array<Array<{ label: string; score: number }>>;
    // Response shape: [[{label: "ChatGPT", score: 0.92}, {label: "Human", score: 0.08}]]
    // We return the "ChatGPT"/AI probability (0-1)
    if (Array.isArray(data) && data[0] && Array.isArray(data[0])) {
      const aiEntry = data[0].find((e) => /chatgpt|ai/i.test(e.label));
      return aiEntry ? aiEntry.score : null;
    }
    return null;
  } catch {
    return null;
  }
}

// Rate limiter (in-memory; for production scale use KV/Durable Objects)
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
  return { allowed: true, remaining: FREE_DAILY_LIMIT - record.count, resetAt: record.resetAt };
}

// ===============================
// Worker entry
// ===============================
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const origin = request.headers.get("Origin") || "";
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(origin, env.ALLOWED_ORIGIN) });
    }

    if (url.pathname === "/health") {
          return jsonResponse(
            {
              status: "ok",
              env: env.ENVIRONMENT,
              paypal: env.PAYPAL_ENV,
              kv: "SUBSCRIPTIONS",
              webhookId: env.PAYPAL_WEBHOOK_ID,
            },
            200,
            origin,
            env
          );
        }

        // ===== POST /__test__/webhook (TEST ONLY — bypasses signature verification) =====
        // Enabled only when ENVIRONMENT !== 'production'. Lets us verify KV persistence
        // without needing real PayPal-signed webhooks (which require a user to
        // complete the approve flow in a browser).
        if (url.pathname === "/__test__/webhook" && request.method === "POST" && env.ENVIRONMENT !== "production") {
          try {
            const event = (await request.json()) as {
              event_type: string;
              resource: { id: string; plan_id?: string; status?: string; subscriber?: { email_address?: string } };
            };
            if (!event.event_type || !event.resource?.id) {
              return jsonResponse({ error: "Invalid payload" }, 400, origin, env);
            }

            const subId = event.resource.id;
            const existing = await getSubscription(env, subId);
            const planId = event.resource.plan_id || existing?.plan || "unknown";
            const newStatus = event.resource.status || "unknown";
            const email = event.resource.subscriber?.email_address || existing?.email;

            const record: SubscriptionRecord = {
              subscriptionId: subId,
              plan: planId,
              status: newStatus,
              email,
              createdAt: existing?.createdAt || Date.now(),
              updatedAt: Date.now(),
              lastEventType: event.event_type,
            };
            await saveSubscription(env, record);

            console.log(`[Test Webhook] ${event.event_type} → ${subId} (${newStatus}) — saved to KV`);
            return jsonResponse({ received: true, subscriptionId: subId, status: newStatus, testMode: true }, 200, origin, env);
          } catch (error) {
            return jsonResponse({ error: error instanceof Error ? error.message : "Internal error" }, 500, origin, env);
          }
        }

    const allowedOrigins = [
      env.ALLOWED_ORIGIN,
      "http://localhost:3000",
      "http://127.0.0.1:3000",
      ...(env.EXTRA_ALLOWED_ORIGINS ? env.EXTRA_ALLOWED_ORIGINS.split(",").map((o) => o.trim()).filter(Boolean) : []),
    ];
    if (origin && !allowedOrigins.includes(origin)) {
      return jsonResponse({ error: "Forbidden origin" }, 403, origin, env);
    }

    // ===== POST /humanize =====
    if (url.pathname === "/humanize" && request.method === "POST") {
      const ip = request.headers.get("CF-Connecting-IP") || "unknown";
      const rl = checkRateLimit(ip);
      if (!rl.allowed) {
        return jsonResponse(
          { error: "Daily free limit reached. Upgrade to Pro for unlimited rewrites.", limit: FREE_DAILY_LIMIT, resetAt: new Date(rl.resetAt).toISOString() },
          429,
          origin,
          env
        );
      }
      try {
        const body = (await request.json()) as { text?: string; mode?: string };
        const text = body.text?.trim();
        const mode = (body.mode || "standard") as "standard" | "academic" | "creative";
        if (!text) return jsonResponse({ error: "Text is required" }, 400, origin, env);
        const wordCount = text.split(/\s+/).length;
        if (wordCount > 500) return jsonResponse({ error: "Free tier supports up to 500 words. Upgrade to Pro." }, 400, origin, env);
        if (!["standard", "academic", "creative"].includes(mode)) return jsonResponse({ error: `Invalid mode: ${mode}` }, 400, origin, env);
        if (!env.DEEPSEEK_API_KEY) {
          return jsonResponse({ error: "Service temporarily unavailable: DeepSeek API key not configured.", hint: "Set DEEPSEEK_API_KEY via `wrangler secret put DEEPSEEK_API_KEY`" }, 503, origin, env);
        }
        const humanized = await humanizePipeline(text, mode, env);
        const score = env.HUGGINGFACE_API_KEY ? await getAIScore(humanized, env.HUGGINGFACE_API_KEY) : null;
        return jsonResponse({ result: humanized, aiScore: score !== null ? `${(score * 100).toFixed(1)}%` : "N/A", originalWordCount: wordCount, remaining: rl.remaining }, 200, origin, env);
      } catch (error) {
        return jsonResponse({ error: error instanceof Error ? error.message : "Internal error" }, 500, origin, env);
      }
    }

    // ===== POST /score =====
    if (url.pathname === "/score" && request.method === "POST") {
      try {
        const body = (await request.json()) as { text?: string };
        const text = body.text?.trim();
        if (!text) return jsonResponse({ error: "Text is required" }, 400, origin, env);
        if (!env.HUGGINGFACE_API_KEY) return jsonResponse({ score: null, note: "HUGGINGFACE_API_KEY not set" }, 200, origin, env);
        const score = await getAIScore(text, env.HUGGINGFACE_API_KEY);
        return jsonResponse({ score: score !== null ? Math.round(score * 100) : null }, 200, origin, env);
      } catch (error) {
        return jsonResponse({ error: error instanceof Error ? error.message : "Internal error" }, 500, origin, env);
      }
    }

    // ===== POST /subscribe =====
    if (url.pathname === "/subscribe" && request.method === "POST") {
      try {
        if (!env.PAYPAL_CLIENT_ID || !env.PAYPAL_CLIENT_SECRET) {
          return jsonResponse({ error: "PayPal not configured" }, 503, origin, env);
        }
        const body = (await request.json()) as { plan?: string };
        const planKey = body.plan;
        const planId = planKey === "academic" ? env.PAYPAL_PLAN_ACADEMIC : env.PAYPAL_PLAN_PRO;
        if (!planId) return jsonResponse({ error: "Invalid plan. Use 'pro' or 'academic'." }, 400, origin, env);

        const token = await getPayPalToken(env);
        const subRes = await fetch(`${PAYPAL_API(env)}/v1/billing/subscriptions`, {
          method: "POST",
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
            Prefer: "return=representation",
          },
          body: JSON.stringify({
            plan_id: planId,
            application_context: {
              brand_name: "BypassAI.online",
              shipping_preference: "NO_SHIPPING",
              user_action: "SUBSCRIBE_NOW",
              payment_method: { payer_selected: "PAYPAL", payee_preferred: "IMMEDIATE_PAYMENT_REQUIRED" },
              return_url: env.PAYPAL_RETURN_URL || `${env.ALLOWED_ORIGIN}/billing/success`,
              cancel_url: env.PAYPAL_CANCEL_URL || `${env.ALLOWED_ORIGIN}/billing/cancel`,
            },
          }),
        });
        if (!subRes.ok) {
          const errBody = await subRes.text().catch(() => "");
          throw new Error(`PayPal subscribe failed: ${subRes.status} ${errBody.slice(0, 300)}`);
        }
        const subscription = (await subRes.json()) as { id: string; status: string; links: Array<{ href: string; rel: string }> };
        const approvalUrl = subscription.links.find((l) => l.rel === "approve")?.href;
        if (!approvalUrl) throw new Error("No approval URL returned");
        return jsonResponse({ subscriptionId: subscription.id, status: subscription.status, approvalUrl }, 200, origin, env);
      } catch (error) {
        return jsonResponse({ error: error instanceof Error ? error.message : "Internal error" }, 500, origin, env);
      }
    }

    // ===== GET /subscription/store/:id (debug — KV state) =====
    if (url.pathname.startsWith("/subscription/store/") && request.method === "GET") {
      const subId = url.pathname.split("/")[3];
      const stored = await getSubscription(env, subId);
      return jsonResponse(
        stored || { subscriptionId: subId, status: "not_found" },
        200,
        origin,
        env
      );
    }

    // ===== GET /subscription/:id (PayPal lookup) =====
    if (url.pathname.startsWith("/subscription/") && request.method === "GET") {
      try {
        if (!env.PAYPAL_CLIENT_ID) return jsonResponse({ error: "PayPal not configured" }, 503, origin, env);
        const subId = url.pathname.split("/")[2];
        const token = await getPayPalToken(env);
        const res = await fetch(`${PAYPAL_API(env)}/v1/billing/subscriptions/${subId}`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (!res.ok) return jsonResponse({ error: `PayPal ${res.status}` }, res.status as 400, origin, env);
        const data = await res.json();
        return jsonResponse(data, 200, origin, env);
      } catch (error) {
        return jsonResponse({ error: error instanceof Error ? error.message : "Internal error" }, 500, origin, env);
      }
    }

    // ===== POST /webhooks/paypal (verified, persisted) =====
    if (url.pathname === "/webhooks/paypal" && request.method === "POST") {
      // 1. Read raw body (needed for signature verification)
      const rawBody = await request.text();

      // 2. Extract + verify signature
      const sigHeaders = extractWebhookHeaders(request);
      if (!sigHeaders) {
        console.warn("[Webhook] Missing required PayPal signature headers");
        return jsonResponse({ error: "Missing signature headers" }, 400, origin, env);
      }

      const isValid = await verifyWebhookSignature(sigHeaders, rawBody, env);
      if (!isValid) {
        console.warn(`[Webhook] SIGNATURE VERIFICATION FAILED (transmission: ${sigHeaders.transmissionId})`);
        return jsonResponse({ error: "Invalid signature" }, 401, origin, env);
      }
      console.log(`[Webhook] Signature verified (${sigHeaders.transmissionId})`);

      // 3. Parse + process event
      let event: {
        id?: string;
        event_type: string;
        resource: {
          id: string;
          plan_id?: string;
          status?: string;
          subscriber?: { email_address?: string };
        };
      };
      try {
        event = JSON.parse(rawBody);
      } catch {
        return jsonResponse({ error: "Invalid JSON" }, 400, origin, env);
      }

      if (!event.event_type || !event.resource?.id) {
        return jsonResponse({ error: "Invalid event payload" }, 400, origin, env);
      }

      try {
        const subId = event.resource.id;
        const existing = await getSubscription(env, subId);

        // Idempotency: if we've already processed this exact event, skip
        if (event.id) {
          const alreadyProcessed = await env.SUBSCRIPTIONS.get(KV_KEYS.eventLog(event.id));
          if (alreadyProcessed) {
            console.log(`[Webhook] Duplicate event ${event.id} skipped`);
            return jsonResponse({ received: true, duplicate: true }, 200, origin, env);
          }
        }

        const planId = event.resource.plan_id || existing?.plan || "unknown";
        const newStatus = event.resource.status || "unknown";
        const email = event.resource.subscriber?.email_address || existing?.email;

        const record: SubscriptionRecord = {
          subscriptionId: subId,
          plan: planId,
          status: newStatus,
          email,
          createdAt: existing?.createdAt || Date.now(),
          updatedAt: Date.now(),
          lastEventType: event.event_type,
        };

        await saveSubscription(env, record);

        // Log this event ID for idempotency (TTL 7 days is enough for PayPal retry window)
        if (event.id) {
          await env.SUBSCRIPTIONS.put(KV_KEYS.eventLog(event.id), "1", {
            expirationTtl: 7 * 24 * 60 * 60,
          });
        }

        console.log(`[Webhook] ${event.event_type} → ${subId} (${newStatus})`);

        // Future: dispatch to email service / user notification queue here

        return jsonResponse({ received: true, subscriptionId: subId, status: newStatus }, 200, origin, env);
      } catch (error) {
        // Return 500 so PayPal retries the webhook
        console.error("[Webhook] Processing error:", error);
        return jsonResponse({ error: error instanceof Error ? error.message : "Processing failed" }, 500, origin, env);
      }
    }

    return jsonResponse(
      {
        service: "bypass-ai-api",
        routes: [
          "POST /humanize",
          "POST /score",
          "POST /subscribe",
          "GET /subscription/:id",
          "GET /subscription/store/:id",
          "POST /webhooks/paypal",
          "GET /health",
        ],
      },
      200,
      origin,
      env
    );
  },
};