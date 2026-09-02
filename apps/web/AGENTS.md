# Customer web agent instructions

These instructions apply under `apps/web/` in addition to the repository-level
instructions.

## Boundaries

This is the operational customer UI. It must consume the server's authorization and
data model; it must not invent a second authorization model in the browser.

- Obtain subject, organization, roles, and capabilities from
  `GET /api/v1/auth/me`.
- Keep OIDC access tokens in memory. Only the short-lived PKCE transaction state may
  use session storage.
- Never authorize from an unsigned decoded JWT payload.
- Never put secrets in `VITE_*` variables. Vite values are public build-time data.
- Keep the API path same-origin unless an explicit, reviewed deployment change says
  otherwise.
- Preserve security headers and the restrictive CSP in the runtime Nginx image.

## Generated contracts

`openapi.json` and `src/generated/traceless-api/` are generated from the API.
Do not hand-edit generated files.

After an API schema change, run from the repository root:

```bash
make generate-contract
make check-contract
```

Use the generated types at the API boundary. Convert to UI-specific view models only
when that makes state or presentation clearer.

## React and TypeScript

- Follow the existing React 19, TypeScript, Vite, and Vitest patterns.
- Keep TypeScript strict; do not use `any`, non-null assertions, or broad casts to hide
  contract errors.
- Treat loading, empty, denied, stale, partial, cancelled, and failed states as
  deliberate UI states.
- Do not present an inferred risk, attack chain, or AI classification as a verified
  fact.
- Preserve unsaved-change protection and optimistic-concurrency handling on editable
  resources.
- Keep interfaces keyboard-usable and provide accessible labels for interactive
  controls.
- Do not add synthetic or hard-coded operational data outside clearly isolated test
  fixtures.

## Verification

```bash
npm run test
npm run build
```

Run focused Vitest files while iterating, then the complete commands above before
delivery. A changed API boundary also requires the repository contract checks.
