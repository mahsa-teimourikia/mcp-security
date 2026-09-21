# Multi-Agent and Cross-Server Attack Paths

## Learning objectives

Model lateral movement across hosts, agents, MCP servers, registries, gateways,
and downstream APIs; identify transitive authority; calculate bounded
reachability; and place controls that reduce blast radius and support
containment.

## Scenario and lab

An integration can be safe alone but unsafe in a graph: an agent passes context,
a gateway routes to several servers, and a server accesses an API. Run
`python3 lab.py` to traverse a small graph and see how a containment block
changes reachable assets. Build real graphs from registry ownership, artifact
identity, identity delegation, network policy, tool/resource edges, and traces.
Mark credentials, approvals, classifications, and kill switches.

## Controls and evaluation

Use least privilege, narrow interfaces, tenant/audience policy, isolation,
default-deny egress, verified registry onboarding, bounded delegation, and
traceable revocation. Test compromised server, malicious update, cross-agent
poisoning, shared credential, gateway bypass, and containment failure. Measure
maximum sensitive reachability, time-to-discover, time-to-cut, and residual
paths after revocation.

## References

- [MITRE ATT&CK](https://attack.mitre.org/)
- [MCP security best practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices)
