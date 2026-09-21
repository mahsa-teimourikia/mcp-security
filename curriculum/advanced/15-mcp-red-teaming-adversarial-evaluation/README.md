# MCP Red Teaming and Adversarial Evaluation

## Learning objectives

Plan authorized red-team campaigns against MCP host, client, server, tool,
resource, prompt, identity, registry, and supply-chain boundaries; measure
attack success, detection, containment, and safe completion; and convert each
finding into a reproducible regression test and owned remediation.

## Campaign design

Use written scope, owners, target environment, safety limits, stop conditions,
test data, time window, and escalation route before testing. Campaigns cover
prompt/tool poisoning, broad schema discovery, SSRF, traversal, tenant escape,
token audience/scope errors, confused deputy, artifact substitution, capability
drift, and response/rollback failure. Never test external systems or production
accounts without explicit authorization and containment arrangements.

## Lab and metrics

Run `python3 lab.py`. The offline campaign scores attacks expected to deny and
reports block, detection, and containment rates. A high block rate alone is not
enough: a control may deny but omit evidence, or detect without being able to
contain an active compromised server. Track safe task completion too, so an
over-broad block policy is visible.

## Evaluation and production upgrade

For each trial retain scenario, artifact digest, policy/config version, seed,
target boundary, expected/observed decision, trace, detection, containment,
impact, owner, and fix. Re-run after changes. Use deterministic fixtures for
CI and separately governed human red-team exercises for novel chains. Do not
score model hidden reasoning; score observable requests, tool calls, results,
and controls.

## Exercises

1. Add safe-completion and false-positive metrics.
2. Design stop conditions for a cross-server exfiltration simulation.
3. Convert an accepted malicious tool schema into a regression case.

## References

- [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)
- [OWASP Agentic Security Initiative](https://genai.owasp.org/initiatives/agentic-security-initiative/)
