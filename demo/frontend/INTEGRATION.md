# WO-10 frontend — integration notes

Replaces `demo/frontend/` on `feat/wo10-terra-demo` (`c39ca94`). Pair it with
`0001-wo10-access-pack-audit.patch`, which adds the two API changes below.

## API contract (relative to c39ca94)

| Call | Change |
|---|---|
| `POST /demo/register` | Body adds `invite_code` (Tempris-issued). 403 without a valid invite or when `DEMO_INVITE_SECRET` is unset; 409 if the username exists. |
| `POST /demo/export` | New. Body `{ "kind": "report.pdf · <pack> v<version>" }`. Writes `demo.export` to the audit log. |
| Everything else | Unchanged: login, logout, bootstrap, pack, reset, journey-event. |

Any 401 or 403 during a session clears the token and returns to
sign-in with the server's reason.

## Behaviour

- Watermark: permanent on every screen (including sign-in) and on printed exports. No setting hides it (WO-10 10d, acceptance e).
- TES renders on the 0–10 scale the pack now carries.
- Finding status: the pack holds final status; screens show "open" until the journey reaches the decision or remediation that changed it.
- Explore mode navigation is sent as journey events with journey `EXPLORE`.
- Production build loads nothing external (fonts fall back to system mono); preview build adds Google Fonts and a mock API.

## Builds

- `npm run build` — production. Pack data arrives only from `GET /demo/pack` after sign-in.
- `npx vite build --config vite.preview.config.ts --mode preview` — single-file preview with a mock API over a copy of the pack (`src/preview/pack.json`) and pack review notes (`src/preview/review.ts`). Neither ships in production.

## Files

`src/App.tsx`, `src/api.ts`, `src/model.ts`, `src/context.tsx`, `src/ui.tsx`,
`src/screens/{estate,records,coverage,graph,report}.tsx`, `src/styles.css`,
`src/review.ts` (production stub), `src/preview/*`, `index.html`, `tsconfig.json`
(`resolveJsonModule`), `vite.preview.config.ts`, `.env.preview`, `package.json`
(adds dev dependency `vite-plugin-singlefile@2.1.0`). Delete `src/screens.tsx`.
