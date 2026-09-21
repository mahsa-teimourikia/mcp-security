# MCP Supply-Chain Risk Management

## Learning objectives

Manage server, SDK, connector, model, package, registry, build, and vendor risk
as a portfolio; tier suppliers by impact; require provenance/SBOM/vulnerability
evidence and accountable ownership; and define onboarding, monitoring,
exception, revocation, and offboarding decisions.

## Enterprise risk lifecycle

Inventory every component that can influence MCP behavior: local executable,
remote server, package, transitive dependency, base image, SDK, connector,
registry, build runner, signer, and vendor-managed endpoint. Classify criticality
by tenant/data/side-effect reachability. Require immutable artifact references,
provenance, SBOM, vulnerability response SLA, owner, contractual/operational
assurance, and an exit/revocation plan. Repeat review after material change.

## Lab and evaluation

Run `python3 lab.py`. Missing supplier evidence blocks intake; a critical but
well-evidenced component receives elevated review rather than automatic approval.
Production scoring should be transparent and risk-based, not a false numerical
guarantee. Test compromised signer, dependency advisory, vendor outage, registry
takeover, stale SBOM, missed vulnerability SLA, ownership change, and emergency
offboarding. Track inventory completeness, critical evidence coverage, time to
identify affected artifacts, and revocation/rollback time.

## References

- [NIST SP 800-161r1](https://csrc.nist.gov/pubs/sp/800/161/r1/final)
- [SLSA](https://slsa.dev/)
