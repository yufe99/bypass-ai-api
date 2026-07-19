# BypassAI API — Cloudflare Workers

> Guardrail-protected multi-language rewriting pipeline. Companion to [`yufe99/bypass-ai-frontend`](https://github.com/yufe99/bypass-ai-frontend).

## Routes

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/humanize` | Full Guardrail + multi-language rewrite (Standard / Academic / Creative) |
| `POST` | `/score` | Lightweight AI probability score (HuggingFace detector) |
| `GET` | `/health` | Liveness check |
| `OPTIONS` | `*` | CORS preflight |

## Pipeline

```
Input text
  │
  ▼
┌─────────────────────────────────────────┐
│ Layer 1: Guardrail (Term Protection)    │ ← citations & tech terms replaced with [[REF_n]] / [[TERM_n]]
└─────────────────────────────────────────┘
  │
  ▼
┌─────────────────────────────────────────┐
│ Layer 2 + 3: Multi-language Rewrite     │
│   • Standard: EN → CN → EN              │
│   • Creative: EN → FI → EN              │
│   • Academic: EN → CN → JP → FI → EN    │ (4 hops, 5-10s)
└─────────────────────────────────────────┘
  │
  ▼
┌─────────────────────────────────────────┐
│ Layer 4: Term Restoration               │ ← protected terms restored verbatim
└─────────────────────────────────────────┘
  │
  ▼
AI Score (HuggingFace followsci/bert-ai-text-detector)
```

## Security

- **CORS**: locked to `ALLOWED_ORIGIN` env var (no wildcard). Production should be `https://bypass-ai.pages.dev`.
- **Rate limit**: 3 free rewrites/day per IP (in-memory; replace with CF D1 / KV for production scale).
- **Word limit**: 500 words per rewrite on free tier.
- **Secret rotation**: API keys via `wrangler secret put`, never in repo.

## Setup

```bash
npm install
cp .dev.vars.example .dev.vars       # fill in real values for local
npx wrangler dev                     # localhost:8787
```

## Secrets (set via `wrangler secret put`)

| Secret | Required? | Source |
|--------|-----------|--------|
| `DEEPSEEK_API_KEY` | ✅ Yes | https://platform.deepseek.com/api-docs |
| `HUGGINGFACE_API_KEY` | Optional | https://huggingface.co/settings (free tier works) |
| `GOOGLE_TRANSLATE_KEY` | Optional (fallback only) | Google Cloud Console |

## Deploy

```bash
npx wrangler deploy
```

The default `wrangler.toml` deploys to a free `*.workers.dev` subdomain. To use a custom domain, configure routes in the CF Dashboard.

## License

© BypassAI.online. All rights reserved.