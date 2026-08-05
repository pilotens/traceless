# Reachable attack chains

Traceless implements the state-transition representation described by Hou et al.,
*An Automated Framework for Extracting Reachable Attack Chains from Cyber Threat
Intelligence Reports* (arXiv:2607.19742):

```text
preconditions -> attack behavior -> postconditions
```

Each ground postcondition becomes the head of one Datalog-style rule whose body is
the unit's complete precondition set. Forward chaining answers whether a requested
security state is reachable. Backward proof reconstruction returns all bounded,
branch-consistent paths supporting that state.

## Pipeline

1. Extract an ordered behavior skeleton using one of 16 stable behavior classes.
2. Extract local conditions from the step and its immediate context.
3. Extract global conditions from the whole report.
4. Fuse and normalize conditions into the closed, versioned predicate vocabulary.
5. Diagnose unsupported dependencies, future dependencies, invalid predicates,
   non-progressing steps and incorrectly merged alternative branches.
6. Apply at most two issue-directed repair rounds. A repair may promote an
   environmental condition to an initial fact only when the source explicitly
   supports it and the predicate is marked initial-fact eligible.
7. Compile attack units into ground rules, run forward chaining and reconstruct
   branch-consistent proofs backwards from the goal.

The extraction backend is an interface. The committed deterministic backend is a
conservative fallback and a test oracle. A separately operated LLM service can
implement the same staged interface without changing persistence or reasoning.

## API preview

The tenant-scoped preview endpoints are deliberately excluded from the generated
public OpenAPI contract until the schema stabilizes:

```text
POST /api/v1/operational/intelligence/attack-chains/analyze
GET  /api/v1/operational/intelligence/attack-chains
GET  /api/v1/operational/intelligence/attack-chains/{analysis_id}
POST /api/v1/operational/intelligence/attack-chains/{analysis_id}/reason
```

Analysis requires unrestricted organization-wide analyst access. A request must use
exactly one direct text source or one approved, active intelligence record. Stored rows
are protected by forced PostgreSQL RLS and a source-record tenant-match trigger.
TLP:RED source records are rejected. Raw report
text is hash-only by default and is retained only when the caller explicitly sets
`retain_source_text=true`.

## Deliberate boundaries

- The reasoner operates on ground predicates, not variables or negation.
- The deterministic extractor is not presented as an LLM replacement.
- No predicate outside the versioned vocabulary may enter reasoning.
- Diagnosis never silently invents an intermediate state.
- Reachability is evidence-dependent and is not proof that an intrusion occurred.

## Curated extraction quality gate

The deterministic preview extractor is evaluated against a versioned bilingual fixture in
`apps/api/evaluation/attack_chains.json`. The gate measures behavior and ATT&CK extraction,
evidence coverage, reachability decisions and confidence calibration. It includes English,
Swedish and negated examples and runs in CI through `scripts/evaluate_attack_chains.py`.

This is an internal regression dataset, not independent validation. Production promotion still
requires a larger externally annotated corpus, reviewer agreement measurements and validation
against the configured model backend.
