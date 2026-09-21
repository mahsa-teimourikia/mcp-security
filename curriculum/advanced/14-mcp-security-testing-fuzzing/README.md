# MCP Security Testing and Fuzzing

## Learning objectives

Turn MCP security invariants into deterministic tests; build negative contract,
parser, schema, resource, and capability cases; use bounded fuzzing/mutation to
find unexpected accepts; and preserve failures as regression fixtures.

## Evaluation loop

```text
invariant → fixtures/mutations → run system → capture decision/trace → inspect failure → fix → regression gate
```

Happy-path tests prove only intended behavior. Security tests deliberately vary
tool names, extra properties, types, sizes, tenant IDs, URI encoding, redirects,
prompt/tool output, capability changes, token claims, and delegation depth. A
test oracle must be explicit: allow, deny, review, or error-without-side-effect.

## Lab

Run `python3 lab.py`. It reuses the repository adversarial fixture set and
applies mutations for cross-tenant access, cloud metadata SSRF, and unapproved
side effects. The simple gate is a teaching oracle, not a full MCP parser or
fuzzer. Production tests should execute the real SDK server, property-test its
schemas, fuzz bounded parsers, isolate test targets, cap resources, preserve
seeds, and never direct fuzz traffic at unapproved production systems.

## Production and exercises

Measure invariant coverage, unique crash/accept count, attack success rate,
false denial, time-to-triage, and regression escape. Capture digest, version,
seed, case ID, decision, trace ID, and sanitized input class. Add differential
tests between host and server gates, malformed JSON-RPC cases, capability-cache
drift, and time-bound fuzz budgets.

## References

- [MCP specification](https://modelcontextprotocol.io/specification/latest)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
