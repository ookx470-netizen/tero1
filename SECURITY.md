# TERO — Security & Bug Fix Log

This documents what was found and fixed in `server.ts` / `firestore.rules` /
`package.json`. It does **not** cover the frontend (`assets/index-*.js`) —
only a production build was included in the upload, not its source, so it
could not be edited here.

## Critical (fixed)

1. **Every `/api/admin/*` route was unauthenticated.** Anyone who found the
   URL could list/edit users, approve withdrawals, change treasury
   addresses, etc. → Added a signed-token auth middleware in front of all
   admin routes.
2. **Admin credentials were hardcoded in source**
   (`admin`/`admin123`, `admin@tero.network`/`123ASDasd`, ...). → Replaced
   with `ADMIN_USERNAME` / `ADMIN_PASSWORD` env vars, hashed with scrypt at
   boot, changeable via `/api/admin/auth/change-password`.
3. **All auth tokens were `base64(username)` — unsigned and trivially
   forgeable**, for both admin and regular users. Anyone could impersonate
   any account without a password. → Replaced with HMAC-signed, expiring
   tokens (`signToken` / `verifyToken`, keyed by `SESSION_SECRET`).
4. **User login/register never checked a password.** Logging in as
   `username=admin` (or anyone) logged you into that account with no
   password check. → Registration now requires and hashes a password;
   login verifies it.
5. **Firestore rules allowed anyone on the internet to read/write the
   whole database directly** (`allow read, write: if true`), bypassing
   the API entirely. → Server migrated from the client Firestore SDK to
   `firebase-admin` (a trusted service account, unaffected by rules);
   `firestore.rules` now denies all direct client access. The frontend
   bundle was checked and never called Firestore directly, so this is
   safe.
6. **A live Telegram bot token was hardcoded in source**
   (`TELEGRAM_BOT_TOKEN`). Treat it as compromised — rotate it via
   @BotFather. → Now required from the environment; the bot integration
   is simply disabled without it.
7. **The daily task access code had hardcoded bypasses**
   (`"TERO1234"` / `"TERO2026"` always worked regardless of the
   configured code) and no expiry check. → Fixed to only accept codes
   currently in `taskAccessCodes`, respecting `validHours`.

## Correctness bugs (fixed)

8. Several "current user" endpoints (`/api/wallet/balance`,
   `/api/wallet/withdraw`, `/api/user/profile`, telegram status/link...)
   ignored the caller entirely and always returned/operated on
   `db.users[0]` — every visitor saw and could act on the same account.
   → All now resolve the real caller from their token and return 401 if
   unauthenticated.
9. `POST/PUT /api/admin/users/:id` silently fell back to editing
   `db.users[0]` if the `:id` didn't match anyone, risking editing the
   wrong user's balance. → Now returns 404 instead.
10. `/api/admin/users/:id/deposits` and `/withdrawals` always included a
    hardcoded `"asse_24"` user's transactions on every lookup. → Filters
    strictly by the requested user id now.
11. Telegram account-linking (`/api/user/telegram/verify-link` and the bot
    handler) fell back to linking a random first user when the link
    token didn't match anyone. → Now just fails with no match instead of
    guessing.
12. `POST /api/wallet/deposit` — the endpoint that actually records a
    user's deposit submission — **did not exist**. The UI had a deposit
    flow with nothing on the backend to receive it. → Added, with
    optional on-chain verification (see below).

## New: optional on-chain deposit verification

If `POLYGON_RPC_URL` is set, new deposits are checked against Polygon via
JSON-RPC: the transaction must have succeeded and contain a real USDT
`Transfer` event to the configured treasury address for at least the
claimed amount. Without it, deposits are recorded as `pending` for manual
admin review, same as before this fix.

This does **not** implement outbound withdrawal payouts (sending crypto
out) — that still requires an admin to mark a withdrawal completed after
sending funds manually, which is the safer default without a proper
custody/signing setup (hot wallet private key, multisig, etc.).

## This session's additional fixes (admin settings page / deposit address / task codes)

13. **`GET /api/admin/site-settings` and `POST /api/admin/site-settings` were
    leaking `adminAuth` (admin username + password hash) into their JSON
    response**, because both endpoints spread the entire `siteSettings`
    object straight into the response. This is a very plausible cause of
    the "white screen when opening panel settings" — if the settings page
    tries to render every key it receives and hits a nested object
    (`adminAuth: {username, passwordHash}`) where it expects a plain
    string, React throws ("Objects are not valid as a React child") and
    the whole page goes blank with no error boundary to catch it.
    → Both endpoints now strip `adminAuth` before responding.
14. **`POST /api/admin/site-settings` merged the entire request body
    into `siteSettings` with no restrictions** — a stray `{adminAuth:
    {...}}` in the payload (buggy client, or a malicious request) could
    silently overwrite the admin password hash. → `adminAuth` is now
    blocked from both the bulk `POST` and the per-key `PUT
    /api/admin/site-settings/:key` endpoints; it can only change via
    `/api/admin/auth/change-password`.
15. **Treasury (deposit) address updates had no format validation** — a
    typo would silently break deposits for every user until someone
    noticed. → `PUT`/`POST /api/admin/treasury-settings` now reject
    anything that isn't a valid `0x` + 40 hex-char address.
16. **Task access codes never actually replaced each other** — every code
    ever created stayed valid indefinitely (as long as it was still
    within its own `validHours`), so multiple old codes worked
    simultaneously. → Creating a new code now marks all previously
    "running" codes as "replaced".
17. Added `PUT /api/admin/task-access-codes/:id` to edit an existing
    code's value/validHours/status directly, instead of only being able
    to create a new one and delete the old one. Manual creation already
    existed (`POST /api/admin/task-access-codes` and
    `POST /api/admin/task-code-gen/manual`) — both still work and now
    also retire old codes correctly.

### About the white screen specifically

I can't fully guarantee this is fixed, because **only the compiled
frontend bundle was included** (`assets/index-*.js`), not its source —
I can't set a breakpoint or read its render logic, only grep the
minified output. What I could confirm and fix on the backend:

- The `adminAuth` leak above is a concrete, real bug that could crash a
  settings page trying to render it.
- Previously *every* admin endpoint had no auth check — after last
  session's fix, they now require a valid signed token. **Any admin
  token saved in the browser from before that fix is no longer valid.**
  If the settings page doesn't handle a `401` response gracefully, that
  alone could produce a blank page. **Log out and log back in (or clear
  `adminToken` from localStorage) after deploying this update.**

If a white screen still happens after redeploying + a fresh login, the
fastest way to actually fix it is to open the browser console on that
page and share the error message — or share the frontend source so it
can be patched directly instead of guessed at from a minified bundle.

- Set `SESSION_SECRET`, `ADMIN_USERNAME`, `ADMIN_PASSWORD` before deploying.
- Generate a Firebase service account key and set
  `FIREBASE_SERVICE_ACCOUNT_JSON` (or `GOOGLE_APPLICATION_CREDENTIALS`).
- Rotate the Telegram bot token via @BotFather and set `TELEGRAM_BOT_TOKEN`.
- Decide on a `POLYGON_RPC_URL` if you want automatic deposit verification.
- Existing users in `data.json` have no password — they can't log in
  under the new system until an admin resets one for them (there's no
  "set password" admin endpoint yet — worth adding next).
- The frontend is a compiled build only; if you want UI/business-logic
  changes (VIP economics, task flow, admin dashboard), you'll need the
  original React/Vite source from your AI Studio project.
