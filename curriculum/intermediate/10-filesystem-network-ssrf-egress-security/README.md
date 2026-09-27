# Filesystem, Network, SSRF, and Egress Security

An MCP tool is not safe merely because its description says “read a file” or
“look up a ticket.” If a caller can choose a path, URL, host, header, or redirect
target, untrusted content can steer the server into authority the user never
intended to grant.

This course builds two narrow capabilities for a fictional multi-tenant support
service:

- `workspace.read(file_id)` reads one catalogued, tenant-owned file beneath an
  approved directory without following symlinks.
- `ticket.lookup(ticket_id)` constructs a server-owned request, validates every
  destination, connects to a vetted address, rechecks redirects, bounds the
  response, and binds the result to the request.

The testable security claim is:

> Untrusted input selects an opaque resource, never ambient filesystem or
> network authority; trusted code maps that resource to a least-authority
> operation and independently constrains every effect.

## Learning objectives

By the end of the course, you should be able to:

1. explain SSRF as confused use of a server's identity and reachability;
2. replace arbitrary-path and arbitrary-URL tools with opaque identifiers;
3. distinguish URL parsing from URL validation;
4. validate every A and AAAA answer and pin the approved connect address;
5. re-run complete policy at every redirect hop;
6. enforce file containment during open, not only during a prior string check;
7. bind credentials, methods, paths, responses, and limits to a destination;
8. combine application controls with network default deny, workload isolation,
   and cloud metadata hardening;
9. produce redacted evidence that proves a control ran without recording secrets;
10. test traversal, symlink escape, metadata access, rebinding, redirect pivots,
    timeouts, and oversized responses.

## Prerequisites and learner path

Complete Courses 03, 06, 07, and 09 first. They cover narrow interfaces,
audience-bound credentials, authorization, and workload isolation.

1. Read this chapter.
2. Run `python3 lab.py` in this directory.
3. Work through `filesystem-network-ssrf-egress-security.ipynb`.
4. Inspect `tests/test_course_10_filesystem_network.py`.
5. Complete the design and adversarial exercises below.

From the repository root:

```bash
uv sync --extra contributor
uv run python curriculum/intermediate/10-filesystem-network-ssrf-egress-security/lab.py
uv run pytest -q tests/test_course_10_filesystem_network.py
```

No cloud account, credential, or live endpoint is required. The network and DNS
layers are deterministic test doubles; file reads use real OS file descriptors
inside a temporary directory.

## Scenario: Northstar support assistant

Northstar's support assistant serves multiple tenants. An analyst may read an
approved policy document and look up a ticket owned by their current tenant. The
host supplies authenticated identity. The model supplies only `file_id` or
`ticket_id`.

```text
untrusted prompt/model arguments
        |
        v
strict MCP schema: opaque identifiers only
        |
        v
trusted session identity + resource catalog + destination policy
        |                                  |
        v                                  v
descriptor-relative file open       URL/DNS/redirect gate
        |                                  |
        v                                  v
bounded regular-file read            pinned transport + bounded response
        |                                  |
        +---------------+------------------+
                        v
               redacted decision evidence
```

User content, model arguments, DNS answers, redirects, upstream bytes, and names
inside a writable directory are untrusted. Session identity, reviewed catalogs,
destination policy, credential broker, and enforcement code are trusted inputs.
The OS, network dataplane, DNS infrastructure, TLS stack, and cloud configuration
are dependencies whose behavior needs independent evidence.

## Threat model and invariants

Protected assets include tenant documents, ticket data, metadata credentials,
internal services, destination-specific tokens, network topology, service
availability, and trustworthy audit evidence.

| Boundary | Invariant | Lab evidence |
|---|---|---|
| MCP | No caller-selected path, URL, host, headers, or tenant | Tool schema test |
| Identity | Tenant comes from trusted session context | Cross-tenant tests |
| File selection | Only a reviewed record may be opened | Registry denial event |
| Containment | Every component opens beneath a root descriptor without links | Symlink tests |
| File integrity | Opened bytes match catalog digest and size cap | Digest/size tests |
| URL | Exact HTTPS scheme, ASCII host, port, and path family | Parser matrix |
| DNS | Every A/AAAA answer is valid and globally routable | Address matrix |
| Connection | Transport uses a vetted IP and original TLS name | Call evidence |
| Redirect | Every hop repeats URL and DNS policy | Rebinding tests |
| Credential | Token is destination-bound and never logged raw | Fingerprint evidence |
| Response | Status, type, size, JSON, tenant, and resource are checked | Fault matrix |
| Audit | Decisions are correlated and redacted | Serialization tests |

## Why arbitrary paths and URLs are dangerous

`read_file(path)` delegates namespace interpretation to untrusted input.
Traversal, absolute paths, alternate separators, symlinks, mount points, and
time-of-check/time-of-use races can turn a narrow read into host access.

`fetch_url(url)` delegates network authority. A server may reach loopback,
private networks, cloud metadata, control planes, socket bridges, or
authenticated internal applications the caller cannot reach directly. If the
server attaches credentials, SSRF can become credential theft or an
authenticated cross-service action.

OWASP's primary architectural advice applies: when possible, do not accept a
complete user URL. Accept a business identifier or validated component and
construct the destination in trusted code.

## Filesystem containment

### Why string checks fail

This is unsafe:

```python
if str(candidate).startswith(str(root)):
    return candidate.read_text()
```

`/srv/data-evil` starts with `/srv/data`; normalization can change meaning; and a
symlink can point outside the root. Even `resolve()` followed later by `open()`
can race. Python's `os.access` documentation states the general rule: checking
before opening creates a security hole because the filesystem can change between
the two operations.

### The lab's descriptor-relative design

`DescriptorFileStore` receives a trusted record: opaque ID, tenant, root ID,
relative path, expected SHA-256, and maximum bytes. It rejects absolute paths,
`.`/`..`, backslashes, and NUL bytes. It opens the root directory, then each child
relative to the already-open directory descriptor with `O_NOFOLLOW`. The final
descriptor must be a regular file. The reader enforces size while reading and
verifies the digest of the bytes actually opened.

The policy and use are coupled to descriptors; the code does not validate one
pathname and later open a separately resolved pathname.

### Production strengthening

On Linux, prefer `openat2(2)` where available. `RESOLVE_BENEATH`,
`RESOLVE_NO_SYMLINKS`, `RESOLVE_NO_MAGICLINKS`, and optionally
`RESOLVE_NO_XDEV` express containment in the kernel. Use a vetted binding or
small native broker rather than recreating the syscall contract casually.

This remains defense in depth. Mount only approved input read-only, keep host
files and service-account material outside the runtime, run without privilege,
and use a bounded scratch directory as taught in Course 09.

## SSRF is a chain, not a string check

```text
business ID -> constructed URL -> parsed authority -> DNS answers
            -> connect IP -> TLS identity -> redirect target
            -> response headers -> streamed body -> domain object
```

Every arrow is a validation boundary. A hostname allowlist does not prove where
the socket connects. An IP check before automatic redirect following does not
constrain the next hop. A safe status does not make an unbounded body safe. Valid
JSON does not prove the returned object belongs to the requested tenant.

## URL grammar and canonical policy

Python's `urllib.parse` documentation explicitly says its parsing functions do
not perform validation. RFC 3986 also permits user information before a host,
making strings such as `trusted.example@evil.example` visually misleading.

The lab requires:

- a bounded URL with no control characters, whitespace, or backslashes;
- exact `https` scheme;
- no userinfo, fragment, or percent-encoded authority;
- one exact lowercase ASCII hostname without a trailing dot;
- port 443 only;
- a reviewed path prefix and valid percent encoding; and
- no encoded or repeatedly encoded dot-segment traversal.

Do not copy one grammar blindly into every stack. Define a canonical form, test
it against the exact client and proxy you deploy, and reject inputs interpreted
differently by adjacent layers.

## DNS and connect-time pinning

The gate evaluates every A and AAAA answer. One loopback, link-local, private,
multicast, unspecified, reserved, or otherwise non-global answer rejects the
whole set. IPv4-mapped IPv6 is normalized so `::ffff:169.254.169.254` cannot
bypass IPv4 rules.

Validation is insufficient if the HTTP library resolves again. Attacker DNS can
return a public IP during checking and a private IP during connection. The
`ApprovedTarget` therefore passes a vetted `connect_ip` to the transport while
retaining the hostname for TLS server-name verification and HTTP authority.

A production adapter must prove that it:

1. connects to an address from the approved set;
2. does not perform a hidden second lookup or retry;
3. verifies the certificate for the logical hostname;
4. exposes redirects to policy; and
5. cannot use environment proxy settings as an unreviewed route.

The scripted transport demonstrates the interface and evidence, not production
TLS, proxy, or firewall enforcement.

## Redirects are new requests

Treat every `Location` as a new, attacker-influenced request:

- disable automatic following;
- cap hops and detect cycles;
- parse, resolve, and authorize every hop;
- never forward credentials to a different authority;
- preserve only policy-approved methods; and
- apply response limits to the final response.

The lab permits redirects only inside the exact host and path family. A redirect
to `http://169.254.169.254/...` fails the scheme check. A DNS answer that changes
to metadata on the next hop fails before a second transport call.

## Cloud metadata

AWS, Google Cloud, and Azure expose instance metadata through link-local
endpoints. AWS documents IMDSv2 session tokens and an option to require IMDSv2.
Google documents `Metadata-Flavor: Google`; Azure documents `Metadata: true`.
These mechanisms reduce some risks but do not authorize application access.

Application code should deny metadata destinations. Also require the strongest
provider mode, minimize workload identity privileges, block metadata at the
workload or host boundary where supported, and alert on unexpected access.
Cover IPv4, IPv6, mapped forms, loopback, link-local, multicast, unspecified,
reserved, and provider-specific service endpoints—not only four private IPv4
ranges.

## Credentials and request construction

The caller cannot provide headers. `CredentialBroker` retrieves a token for a
reviewed audience only after target approval. The transport records header names
and a one-way fingerprint, never the token.

In production:

- use distinct, short-lived credentials for each downstream audience;
- never pass the MCP resource token to another API;
- avoid secrets in query strings;
- strip authorization and cookies before an authority change; and
- redact logs, traces, exceptions, and captures.

Methods and paths are also authority. A GET-only lookup should not become an
arbitrary POST, and a ticket prefix should not imply access to `/admin`.

## Bounded response handling

Outbound policy is incomplete until the response is constrained. The lab checks:

1. accepted status;
2. normalized media type;
3. valid `Content-Length` when present;
4. declared size before reading;
5. actual streamed bytes without trusting `Content-Length`;
6. JSON decoding and top-level shape; and
7. ticket and tenant binding before release.

Timeout and connection failures become stable reason codes. Production should
separately bound connection, TLS, first-byte, idle-read, and total deadlines and
limit decompressed bytes rather than trusting compressed size.

## Network-layer enforcement

Application checks understand resources, redirects, credentials, and response
schemas. Independent network controls contain a bug or compromised process.

Use default-deny workload egress, an explicit egress proxy or gateway, firewall
policy, controlled DNS, service identity, and network separation for control
planes. Kubernetes `NetworkPolicy` works only when the installed network plugin
enforces it; test the dataplane. DNS-name policy behavior is implementation
specific and needs explicit rules for TTLs, rotation, mixed answers, and IPv6.

Common choices include cloud firewalls, Kubernetes-aware CNI policy engines,
Envoy egress gateways, service meshes, and managed secure web proxies. The
product is secondary to the invariant: independently enforced, observable,
least reachability with a known bypass story.

## Lab architecture

| Component | Responsibility |
|---|---|
| `DescriptorFileStore` | catalog/tenant checks, descriptor traversal, type/size/digest limits |
| `ScriptedResolver` | deterministic answer sequences and rebinding |
| `URLGate` | strict URL grammar, exact destination, all-answer IP policy |
| `CredentialBroker` | destination-bound headers |
| `ScriptedTransport` | approved-IP connection and preserved TLS name, offline |
| `EgressClient` | redirects, timeouts, response bounds, JSON shape |
| `SecureSupportService` | ID grammar, tenant and output binding |
| `MCPServer` | narrow `workspace.read` and `ticket.lookup` tools |

The fixture creates a real temporary tree, valid and other-tenant documents, a
symlink to an outside secret, scripted DNS, and a fake ticket API. It uses no
ambient credential or live network.

Expected scenario evidence:

- valid file and ticket calls succeed;
- symlink and cross-tenant attempts fail;
- metadata DNS and redirect attempts fail;
- transport uses the vetted IP and logical TLS name;
- raw tokens and query values are absent from events; and
- zero forbidden effects complete.

## Testing and metrics

```bash
uv run pytest -q tests/test_course_10_filesystem_network.py
```

The suite covers unknown/cross-tenant IDs, traversal and symlinks, size/digest
faults, URL ambiguity, IPv4/IPv6 address classes, mixed DNS answers, rebinding,
redirects, timeouts, response limits, output binding, schema authority, and
error redaction.

Keep attempts and outcomes distinct:

```text
block coverage = malicious attempts denied / labelled malicious attempts
forbidden-effect rate = completed forbidden effects / labelled malicious attempts
false-denial rate = legitimate requests denied / labelled legitimate requests
```

Report the corpus, environment, enforcement point, and denominator. Do not turn
a finite offline suite into a claim of complete security.

## Operations and incident response

Useful redacted fields include request ID, logical destination/root, tenant where
permitted, redirect hop, decision/reason, scheme/host/port, address class,
path/content fingerprint, status, type, byte count, and policy/artifact version.

Alert on repeated non-global address denials, strange redirect chains, unknown
file IDs, cross-tenant attempts, response-limit failures, and abrupt DNS changes.
Containment should be rehearsed: disable the tool or destination, revoke its
credential, isolate the workload, preserve evidence, and roll back to a
known-good policy and artifact. Re-enable only after adversarial replay.

## Common mistakes

- Treating `urlsplit` as validation.
- Checking a hostname, then allowing the client to resolve again.
- Accepting one public DNS answer while another is private.
- Forgetting IPv6 and mapped IPv6.
- Following redirects automatically or forwarding credentials.
- Trusting `Content-Length` or forgetting decompression limits.
- Parsing JSON without binding the returned tenant/resource.
- Using `startswith` for path containment.
- Resolving a path and opening it later.
- Mounting the whole workspace or home directory.
- Assuming NetworkPolicy is active without checking the CNI.
- Logging URLs, query strings, bodies, or tokens.
- Calling an offline transport proof of production enforcement.

## Exercises

### Beginner — explain authority

For each MCP input, identify who controls it, what authority it could select, and
which trusted mapping contains it. Explain why `ticket_id` is safer than `url`
but still needs tenant authorization.

### Intermediate — second destination

Add a read-only customer-directory destination with its own hostname, path,
credential audience, response cap, and output schema. Do not add a generic fetch
tool. Prove credentials never cross between destinations.

### Intermediate — real adapter

Build an HTTP adapter behind the scripted interface. Disable ambient proxies and
automatic redirects, connect to a vetted IP, preserve TLS hostname validation,
surface redirects, and cap compressed and decompressed bytes. Keep offline tests.

### Advanced — kernel-enforced open

Implement a Linux file broker using `openat2` with `RESOLVE_BENEATH`,
`RESOLVE_NO_SYMLINKS`, and `RESOLVE_NO_MAGICLINKS`. Document unsupported-platform
behavior and add adversarial rename and mount tests.

### Enterprise — deployed evidence

Correlate application, DNS, proxy/gateway, flow, workload-identity, and policy
evidence. State what each proves and cannot prove. Add a rollback and credential
revocation drill with measurable recovery targets.

## Reflection

1. Which authority remains when a caller supplies only `ticket_id`?
2. Why must every DNS answer pass?
3. How does a validated hostname differ from a pinned connection?
4. Which redirect fields require fresh authorization?
5. Why is a post-open digest useful but not sufficient containment?
6. What evidence proves production traffic cannot bypass the egress gateway?
7. Which lab components are simulations rather than deployment proof?

## Authoritative references

- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [Python URL parsing security](https://docs.python.org/3.12/library/urllib.parse.html#url-parsing-security)
- [Python filesystem APIs](https://docs.python.org/3/library/os.html#files-and-directories)
- [Linux `openat2(2)`](https://man7.org/linux/man-pages/man2/openat2.2.html)
- [RFC 3986: URI Generic Syntax](https://www.rfc-editor.org/rfc/rfc3986)
- [RFC 9110: HTTP Semantics](https://www.rfc-editor.org/rfc/rfc9110.html)
- [IANA IPv4 registry](https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml) and [IPv6 registry](https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml)
- [AWS instance metadata options](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)
- [Google Compute Engine metadata overview](https://cloud.google.com/compute/docs/metadata/overview) and [query guidance](https://cloud.google.com/compute/docs/metadata/querying-metadata)
- [Azure Instance Metadata Service](https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service)
- [Kubernetes Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [MCP security best practices](https://modelcontextprotocol.io/specification/latest/basic/security_best_practices)

## Completion checklist

- [ ] Tools expose opaque identifiers only; identity comes from session context.
- [ ] File records are tenant-, size-, and digest-bound.
- [ ] File opens are descriptor-relative and do not follow links.
- [ ] URL grammar is canonical and tested.
- [ ] Every A/AAAA answer is classified; connection uses a vetted address.
- [ ] TLS verifies the logical host; redirects repeat full policy.
- [ ] Ambient proxies and automatic redirects cannot bypass review.
- [ ] Credentials are destination-specific and redacted.
- [ ] Method, path, status, media type, time, and bytes are bounded.
- [ ] Output is bound to requested resource and tenant.
- [ ] Independently enforced default-deny egress backs application policy.
- [ ] Metadata and workload identity follow provider guidance.
- [ ] Positive, negative, boundary, and adversarial tests pass.
- [ ] Evidence is redacted, correlated, and versioned.
- [ ] Revocation, containment, rollback, and re-enable are exercised.
