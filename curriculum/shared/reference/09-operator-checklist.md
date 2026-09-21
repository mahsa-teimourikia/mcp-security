# Production operator checklist

## Before launch

- [ ] Server, tools, data classes, owners, and destinations are inventoried.
- [ ] Workload identity, audience-bound tokens, rotation, and revocation are tested.
- [ ] Tool schemas and semantic tenant/path/amount checks are enforced in code.
- [ ] SBOM, vulnerability scan, signed artifact, immutable digest, and rollback digest are retained.
- [ ] Runtime has least filesystem, process, network, CPU, memory, and time privileges.
- [ ] Audit traces connect user → host → client → server → tool → resource.
- [ ] Prompt-injection, SSRF, traversal, replay, confused-deputy, and cross-tenant tests pass.

## During operation

- [ ] Alert on new tools, destinations, schema drift, failed signatures, and unusual volume.
- [ ] Review grants and dependencies on a defined cadence.
- [ ] Keep an emergency contact and kill-switch owner available.

## Incident

Disable server → revoke credentials → preserve logs/manifests/SBOMs → identify affected calls → rotate secrets → rebuild from known-good digest → canary → restore gradually → publish a post-incident review.
