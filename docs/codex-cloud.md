# Codex Cloud setup for Traceless

This repository is prepared for cloud-based Codex tasks. The remaining connection
steps are account-level actions in Codex and GitHub and therefore cannot be stored in
the repository.

## One-time Codex environment

Open a supported Codex client—Codex web when it is exposed for the account, or the
ChatGPT desktop app—and connect GitHub. During GitHub authorization, grant the Codex
GitHub app access to **only** `pilotens/traceless` unless another repository is
deliberately added later.

Create an environment with these values:

| Setting | Value |
|---|---|
| Environment name | `Traceless` |
| Repository | `pilotens/traceless` |
| Default branch | `main` |
| Base image | Universal |
| Python | `3.12` |
| Node.js | `22` |
| Setup script | `bash .codex/setup.sh` |
| Maintenance script | `bash .codex/maintenance.sh` |
| Agent internet access | Off |
| Environment variables | `CI=true`, `UV_LINK_MODE=copy` |
| Secrets | None |

The setup script installs `uv==0.11.28` and all three locked workspaces:

- `apps/api`
- `apps/web`
- `apps/publisher-web`

Do not add production database URLs, OIDC secrets, service API keys, feed
credentials, signing keys, customer data, or deployment tokens to the Codex
environment. Codex does not need them to implement and test ordinary changes.

Agent internet access should remain off by default. For a task that genuinely needs
current external documentation, use a narrowly reviewed domain allowlist rather than
unrestricted access. Restore the default after the task.

## First verification task

Run this as the first cloud task:

```text
Read every applicable AGENTS.md file. Make no code changes.

Verify that the environment is using Python 3.12, Node.js 22 and uv 0.11.28. Then run
the API linter, one representative API unit test, the customer-web tests and build,
and the publisher-web tests and build. Report every command and result. Do not claim
Docker or PostgreSQL checks ran unless they actually ran.
```

A no-change verification task does not need a pull request. If setup fails, fix the
checked-in `.codex/setup.sh` in a small PR rather than adding ad-hoc environment
commands that are invisible to the repository.

## Normal implementation task

Use a prompt with a concrete objective, boundaries, and acceptance criteria:

```text
In pilotens/traceless, implement <objective>.

Before editing, read AGENTS.md and the relevant architecture, security, contract and
test files. Preserve tenant isolation, runtime database roles and all scanner and
connector safety boundaries.

Acceptance criteria:
1. <observable behavior>
2. <failure or authorization behavior>
3. <migration or contract behavior, when applicable>
4. Regression tests cover the change.

Run targeted checks and all applicable service checks. Update generated API contracts
when the schema changes. Open a pull request against main. In the PR, list commands
run, security/tenant impact, migration and configuration impact, deployment impact,
rollback notes, and anything not verified.
```

Avoid prompts such as “improve everything”, “make it production-ready”, or “get it to
10/10”. They produce oversized, weakly reviewable changes. Create one issue or task
per coherent objective.

## Cloud and mobile handoff

1. Start a new cloud task in Codex web when it is available for the account; otherwise
   start it in Codex from the ChatGPT desktop app.
2. Select the `Traceless` environment and `main` as the base.
3. Once delegated to Codex Cloud, the task runs in the managed cloud environment and
   the local computer does not need to remain online.
4. Use the ChatGPT mobile app's **Remote** surface for supported Codex chats to inspect
   progress, answer questions, and steer the task. Availability can depend on the
   account, client, and rollout.
5. Ask Codex to open a pull request.
6. Review the PR summary, changed files, checks, and any migration or configuration
   changes from GitHub mobile.
7. Merge only after all required CI checks pass.
8. Deployment must be triggered by the protected `main` branch, never directly by a
   Codex branch.

The repository includes a **Codex task** issue template. Use it when a task benefits
from acceptance criteria, risk boundaries, and a permanent decision record.

## GitHub code review

After the Codex environment is connected, Codex code review can optionally be enabled
for this repository. Repository-specific review rules are defined in the
`## Code Review Rules` section of the nearest `AGENTS.md`.

For a solo-maintained repository, a practical ruleset is:

- require a pull request before changes reach `main`;
- require the `api`, `web`, `publisher-web`, `compose`, and `codex-environment` jobs;
- require branches to be current before merge;
- block force pushes and branch deletion;
- allow no bypass for automation;
- do not require a second human approval unless another reviewer is available.

This repository currently has no repository ruleset committed through GitHub's
settings. Configure it in GitHub after the first PR confirms the exact check names.

## Deployment status

Codex Cloud and automated deployment are separate controls.

The current repository has strong CI and production-shaped containers, but its
Compose file and PostgreSQL role provisioning are intentionally development/reference
configuration. They use local service discovery and trust-authenticated bootstrap
assumptions. They must not be presented as a production deployment manifest.

Before automatic production deployment is enabled, implement and validate:

1. a managed PostgreSQL design with separate migration owner, API role, worker role,
   and non-login dispatch owner;
2. secret-generated role passwords and rotation;
3. a pre-deploy migration and grants job;
4. public web ingress with a private API and private workers;
5. restrictive egress, TLS, OIDC, hosts, CORS, rate limiting, and secret management;
6. centralized redacted logs, metrics, alerts, backup/PITR, and a restore drill;
7. staging health/smoke checks and an automatic rollback decision;
8. a protected production environment requiring approval;
9. independent security testing before untrusted exposure.

The initial deployment scope should exclude the scanner worker and the central
publisher. Add those only as separately reviewed trust zones.

A deployment-readiness issue is created with these acceptance criteria so Codex can
prepare the infrastructure in a later, bounded task without receiving production
credentials.
