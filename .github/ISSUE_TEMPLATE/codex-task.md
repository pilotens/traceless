---
name: Codex task
about: A bounded implementation task for Codex Cloud
title: "[Codex] "
labels: []
assignees: []
---

## Objective

<!-- One coherent, observable outcome. -->

## Current behavior or evidence

<!-- Link to relevant code, test, log, screenshot, or decision. -->

## In scope

- 

## Out of scope

- 

## Acceptance criteria

1. 
2. 
3. 

## Security and architecture constraints

<!-- Keep the applicable items and add task-specific constraints. -->

- Preserve tenant and project/system authorization.
- Preserve forced PostgreSQL RLS and least-privilege runtime roles.
- Keep scanning disabled by default and within the authorized fixed-profile contract.
- Keep external HTTP integrations HTTPS-only, allowlisted, tenant-bound, and bounded.
- Keep source evidence, AI analysis, inference, and analyst decisions separate.
- Do not use production credentials or production data.
- Do not deploy from the task branch.

## Database, API, and configuration impact

- Migration expected:
- OpenAPI/generated contracts expected:
- New configuration expected:
- Backward compatibility requirement:

## Verification required

- Targeted tests:
- Full service checks:
- PostgreSQL/Docker checks:
- Manual or staging evidence:

## Delivery

Read all applicable `AGENTS.md` files before editing. Open a focused pull request
against `main`. The PR must list commands run, anything not verified, security/tenant
impact, migration/configuration impact, deployment impact, rollback notes, and
remaining risks.
