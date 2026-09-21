# Filesystem, Network, SSRF, and Egress Security

## Learning objectives

Constrain file access and outbound network calls; recognize SSRF through cloud
metadata, private ranges, redirects, DNS rebinding, and URL parsing confusion;
and verify egress at the network boundary rather than trusting a model-selected
URL or an application allow-list alone.

## Scenario and threat model

The support server may contact the ticket API and read a published workspace
file. An unsafe `fetch_url(url)` or `read_file(path)` turns content into
authority: injected text can target metadata services, internal admin endpoints,
redirect chains, traversal paths, or secrets. Course 03 narrows the interface;
this course enforces the underlying reachability boundary.

## Normal → attack → defense → retest

Run `python3 lab.py`. The fixture allows HTTPS to one logical destination, then
blocks the metadata IP, an unapproved host, and a traversal path. It is not a
network proxy: production must re-check each redirect and post-DNS resolved IP,
deny private/link-local/loopback ranges, use network default deny, and prevent
proxy bypass. Validate canonical paths after symlink resolution within the
sandbox; never use string prefix checks as the final filesystem control.

## Production controls

Use dedicated egress proxy/firewall policy, DNS controls, connect-time IP
validation, redirect limits, short timeouts, request/response size caps, method
and port allow-lists, and authenticated service-to-service identity. Mount only
needed files read-only; use a bounded scratch directory; prohibit host mounts
and ambient secrets; run non-root; and log destination class and policy decision
without sensitive query strings. Combine these controls with Course 09 runtime
isolation and Course 11 untrusted-content handling.

## Evaluation

Test URL encoding, alternate IP notation, redirect-to-private, DNS rebinding,
IPv6, loopback, proxy environment injection, file traversal, symlink escape,
oversized response, timeout, and repeated denials. Measure block coverage and
time-to-contain anomalous egress.

## References

- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [MCP security best practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices)
