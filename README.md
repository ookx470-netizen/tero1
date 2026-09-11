<div align="center">
<img width="1200" height="475" alt="GHBanner" src="https://ai.google.dev/static/site-assets/images/share-ais-513315318.png" />
</div>

# TERO Network

> ⚠️ **Read `SECURITY.md` before deploying.** This backend previously shipped
> with hardcoded admin credentials, unauthenticated admin routes, forgeable
> login tokens, a wide-open Firestore database, and a leaked Telegram bot
> token. Those were fixed in this pass — but the fixes only take effect if
> you set the environment variables described below and in `.env.example`.

## Run locally

1. `npm install`
2. Copy `.env.example` to `.env.local` and fill in real values —
   `SESSION_SECRET` and `ADMIN_PASSWORD` at minimum. Nothing here has a
   safe default anymore; the app will generate a temporary random admin
   password and print it to the console if you skip this, purely so it's
   still runnable in local dev.
3. `npm run dev`

## What changed

See `SECURITY.md` for the full list of vulnerabilities and logic bugs
found and fixed, and what still needs your input (Firebase service
account, Telegram bot token rotation, RPC endpoint for on-chain deposit
verification).

## Note on the frontend

Only the built frontend (`assets/index-*.js`, already compiled/minified)
was included in this project — not its source. Backend fixes here don't
touch it. To make UI or business-logic changes on the frontend, you'll
need the original React/Vite source from the AI Studio project this was
exported from.

