## Summary

<!-- What changed? Keep this concrete and observable. -->

## Why

<!-- Which issue, defect, risk, or user outcome does this address? -->

## Scope

<!-- List the main components changed and any explicit non-goals. -->

## Security and tenant impact

- [ ] No tenant-owned query or write was added without organization/resource scope.
- [ ] Authentication and authorization remain server-enforced.
- [ ] API/worker database roles remain least-privilege and `NOBYPASSRLS`.
- [ ] Scanner, connector, parser, job, and report bounds remain intact.
- [ ] No secret, production data, customer data, private key, or credential was added.
- [ ] Source evidence, AI/inference, and analyst decisions remain distinguishable.
- [ ] Not applicable; explanation:

## Database and API contracts

- Customer database migration:
- Publisher database migration:
- Backward/forward compatibility:
- Rollback or expand-and-contract plan:
- OpenAPI/generated TypeScript contracts:

## Configuration and deployment impact

- New or changed environment variables:
- Infrastructure or network changes:
- Health/readiness impact:
- Staging verification:
- Production rollout and rollback:

## Verification

<!-- Replace or add commands. Do not check a command that did not run. -->

- [ ] `cd apps/api && .venv/bin/ruff check .`
- [ ] Relevant API tests
- [ ] Time-sensitive fixtures remain stable as the calendar advances.
- [ ] Full API test suite
- [ ] `cd apps/web && npm run test`
- [ ] `cd apps/web && npm run build`
- [ ] `cd apps/publisher-web && npm run test`
- [ ] `cd apps/publisher-web && npm run build`
- [ ] `make check-contract`
- [ ] `make audit`
- [ ] `make compose-config`
- [ ] Production-shaped Compose smoke test
- [ ] Full GitHub Actions CI

Commands and results:

```text
<command> -> <result>
```

## Evidence

<!-- Screenshots, logs, generated artifacts, migration evidence, or API examples. -->

## Remaining risks and follow-up

<!-- State what was not verified or remains intentionally out of scope. -->
