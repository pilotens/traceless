# Publisher web agent instructions

These instructions apply under `apps/publisher-web/` in addition to the
repository-level instructions.

The publisher UI is an administrative surface for the independent central
intelligence publisher. Do not merge it with the customer application or reuse
customer-runtime credentials to simplify deployment.

- Preserve separation between admin, ingest, review, and feed capabilities.
- Use only server-verified identity and authorization results.
- Keep OIDC access tokens in memory and never place secrets in `VITE_*` values.
- Distinguish staged, reviewed, published, rejected, revoked, and withdrawn content.
- Preserve source revisions, signatures, key identifiers, feed epochs, and audit
  attribution in the UI semantics.
- Never add automatic publication as a UI convenience unless the backend policy,
  approval model, tests, and task explicitly require it.
- Avoid displaying private key material, complete credentials, or sensitive raw
  ingestion payloads.

Verification:

```bash
npm run test
npm run build
```
