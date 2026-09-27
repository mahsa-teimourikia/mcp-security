# Runtime Isolation and Sandboxing for MCP Servers

> **Course 09 · Intermediate · 90–120 minutes**
>
> Admit a pinned least-privilege workload, execute it inside an observable bounded
> process, attack the boundary, and map the same invariants to containers,
> sandboxed runtimes, microVMs, or WebAssembly without overstating the evidence.

## Learning objectives

After this course, you should be able to:

1. explain why MCP authorization, consent, and runtime isolation solve different
   problems;
2. threat-model a local stdio or remote MCP server as potentially compromised
   code;
3. separate artifact admission, application capability policy, runtime
   enforcement, and post-execution verification;
4. choose an isolation tier according to code trust, tenant boundaries, host
   sensitivity, kernel-sharing risk, compatibility, and operational cost;
5. build and test a bounded subprocess with exact arguments, a minimal
   environment, dedicated workspace, resource limits, output limits, timeout,
   termination, and redacted evidence;
6. prevent model-controlled commands, paths, environment variables, identity,
   destinations, and runtime profiles;
7. translate the invariant set into a Kubernetes Restricted-style workload plus
   a sandbox RuntimeClass and default-deny network policy;
8. test traversal, symlink escape, cross-tenant access, artifact drift, secret
   inheritance, hangs, output exhaustion, malformed output, and non-zero exit;
9. distinguish a blocked attempt from an actual sandbox escape or forbidden
   effect; and
10. identify what must still be enforced by namespaces, cgroups, seccomp, an
    LSM, a userspace kernel, a hypervisor, or a capability runtime.

## Prerequisites and course boundary

Complete Courses 01–08 first. Those courses establish the protocol boundary,
server identity, capability review, authentication, application authorization,
and delegation. This course assumes a call is already authenticated and
authorized, then asks what happens if the invoked server or dependency is buggy
or hostile.

Course 10 goes deeper on filesystem traversal, SSRF, redirects, DNS changes,
metadata endpoints, and egress proxies. Course 12 covers artifact provenance,
signatures, SBOMs, and dependency admission. Course 13 applies these controls to
release gates.

The default lab is credential-free and portable across the repository's macOS
and Linux environments. It launches a real child process but does not pretend
that Python resource limits are a container or microVM.

## Course thesis

> A model may request a narrow operation. Trusted application code resolves the
> workload and data from reviewed registries, verifies a pinned policy and
> artifact, launches the smallest compatible isolation boundary, terminates it
> on limit violations, verifies its result, and records exactly which controls
> were enforced. The workload never chooses its own authority or sandbox.

## Why isolation is independent of authorization

Authorization decides whether an intended action may occur. Isolation limits
what the process can reach when implementation logic, a dependency, the model's
request, or the server itself is malicious.

| Control | Question | Example |
|---|---|---|
| Consent | Did the user knowingly approve launching this server or action? | show the complete local install command |
| Artifact admission | Is this the reviewed code and configuration? | verify an immutable digest and signature |
| Authorization | May this caller use this operation on this resource now? | analyst may inspect `file-support-policy` |
| Isolation | What can compromised code reach at runtime? | no ambient secrets, host paths, network, or unbounded resources |
| Verification | Did the bounded execution produce a valid result? | parse schema, check exit state, correlate evidence |

A successful policy decision does not make code safe. A strong sandbox does not
grant permission. Both are required for high-impact agent and MCP workloads.

## MCP's local-server trust boundary

The MCP project documents that a stdio client launches the server as a local
subprocess and that both peers have the privileges of their execution
environment. The stdio transport is not a sandbox. If the host launches an
untrusted server with the user's files, environment, network, and process
privileges, the server already has those capabilities before any tool call.

Final SEP-1024 requires clients with one-click local-server installation to show
the exact command and arguments and obtain explicit user consent. That reduces
silent installation risk; it does not confine a command after approval. Consent
must therefore precede launch, while isolation must surround every execution.

## Threat model

Treat the sandboxed workload as hostile after start. It may try to:

- read host credentials, browser profiles, SSH keys, cloud configuration, or
  unrelated tenant data;
- traverse paths or follow symlinks outside an allowed input tree;
- write startup files, replace binaries, modify source, or persist after the
  request;
- inherit access tokens or secret values from the parent environment;
- invoke a shell, package manager, debugger, compiler, or arbitrary child
  process;
- connect to cloud metadata, localhost services, control planes, databases, or
  an attacker endpoint;
- exhaust CPU, memory, processes, file descriptors, storage, network bandwidth,
  or log capacity;
- exploit the shared host kernel, sandbox runtime, hypervisor, device model, or
  host integration;
- return malformed, oversized, deceptive, or injected output; or
- hide a failed or killed process behind a fabricated success message.

Also threat-model the control plane. A user allowed to change RuntimeClass,
security context, mounts, image, NetworkPolicy, or admission exemptions may be
able to remove the sandbox without exploiting it.

## Four layers of a defensible execution path

```text
model/tool input
    |
    v
trusted request mapper      opaque file ID -> authorized tenant record
    |
    v
admission policy            artifact + operation + data + limits + runtime class
    |
    v
runtime boundary            process/container/userspace kernel/microVM/Wasm
    |
    v
result verifier             exit state + output bounds + schema + evidence
```

### 1. Trusted request mapping

The Course 09 tool accepts only `file_id`. The model cannot provide a host path,
command, argument vector, tenant, environment variable, network destination,
image, runtime class, seccomp profile, or limit.

The application maps the opaque ID to a trusted record and derives tenant from
authenticated state. Schema validation proves only that the ID is a string; the
registry and authorization decision establish whether it names an allowed
record.

### 2. Admission

Admission verifies the complete execution contract before a process starts:

- reviewed worker artifact digest;
- exact operation from a closed set;
- tenant and record binding;
- traversal-safe relative input name;
- input size;
- allowed environment-key set;
- no network destination in a networkless profile; and
- bounded runtime policy.

Unknown or unavailable policy state denies launch. An admission label is not
runtime evidence: after deployment, verify which runtime and controls the node
actually applied.

### 3. Runtime enforcement

The portable lab actually applies:

- a pinned worker source digest;
- an exact argument vector with `shell=False`;
- Python isolated mode (`-I`);
- a fresh dedicated working directory;
- a copied input marked mode `0400` as hygiene, not a filesystem boundary;
- an explicit minimal child environment;
- POSIX CPU, file-size, process-count, and file-descriptor limits;
- an address-space limit on supported Linux hosts;
- a wall-clock timeout followed by process-group termination; and
- file-backed bounded stdout.

The same-UID child could change that mode bit, which is why the production
profile requires a read-only mount. The pinned wrapper applies resource limits
before workload logic without using Python's thread-unsafe `preexec_fn` path.

macOS injects `__CF_USER_TEXT_ENCODING` into child processes even when the
parent supplies a minimal environment, and rejects the address-space rlimit in
this launch path. The tests permit only that documented platform key and report
whether the address-space limit was applied. Honest evidence is stronger than a
portable-looking claim that is false on one host.

`RLIMIT_NPROC` is scoped to the real user rather than one sandbox and may not
constrain privileged users. The wrapper applies it as local defense in depth;
production process isolation should use a cgroup PID controller or the
platform's equivalent and verify the observed limit.

### 4. Result verification and evidence

Success requires a zero exit status, completion before the deadline, output
below the cap, valid JSON, and the expected result shape. A timeout, signal,
non-zero exit, or malformed response is a failed execution—not a successful
tool call with an error-shaped payload.

Events contain request and evidence IDs, policy ID, artifact fingerprint,
tenant, opaque file ID, operation, decision, reason, duration, exit state,
timeout, output bytes, and applied-control names. They omit document content,
environment values, worker source, and raw secrets.

## What the local harness does not enforce

The subprocess lab does **not** provide:

- a filesystem namespace or genuinely read-only root filesystem;
- a network namespace or packet-level egress filter;
- non-root UID remapping;
- `no_new_privileges`, Linux capability removal, seccomp, AppArmor, SELinux, or
  Landlock confinement;
- cgroup-level accounting and eviction;
- independent-kernel or hardware-virtualization isolation; or
- multi-tenant host hardening.

Its path and destination checks are application admission controls. Compromised
arbitrary native code could bypass them unless an OS or VM boundary independently
enforces the same policy. The lab returns the list of controls it applied and the
production controls it refuses to claim.

## Isolation tiers and trade-offs

Choose the lowest-complexity tier that meets the threat model, but do not treat
all “sandboxes” as equivalent.

| Tier | Main boundary | Compatibility | Typical use | Important residual risk |
|---|---|---:|---|---|
| In-process API | language/application checks | highest | reviewed deterministic library | no containment from native process compromise |
| Restricted subprocess | OS user + rlimits + app policy | high | trusted local helper | shares user, host filesystem, network, and kernel unless separately constrained |
| Standard container | namespaces, cgroups, seccomp/LSM | high | reviewed single-tenant service | shares host kernel; unsafe privilege/mount settings can collapse isolation |
| Sandboxed container | userspace kernel or lightweight VM runtime | medium-high | untrusted plugins or stronger tenant separation | runtime integration, compatibility, and resource overhead |
| WebAssembly/WASI | capability-oriented runtime | workload-dependent | portable narrow functions | host imports and resource limits define real authority; runtime bugs remain |
| MicroVM | guest kernel + hardware virtualization | medium | hostile code or tenant boundary | host/hypervisor/device configuration, side channels, boot and memory overhead |
| Dedicated VM/host | larger hardware/OS boundary | broad | highest blast-radius or regulatory needs | cost, density, lifecycle, and control-plane risk |

Risk-tier examples:

- A reviewed internal parser with no secrets may use a bounded process or
  container.
- A third-party local MCP server that processes private repositories deserves a
  stronger sandbox and no ambient host access.
- Arbitrary multi-tenant code execution generally requires a userspace-kernel or
  hardware-virtualized boundary plus host hardening.
- A workload needing host Docker socket, privileged mode, host PID namespace,
  or broad writable mounts is effectively asking to weaken or cross the
  container boundary. Redesign or isolate it on a dedicated worker.

## Containers: common controls and failure modes

Linux containers commonly combine namespaces, cgroups, capabilities, seccomp,
and an LSM such as AppArmor or SELinux. Configure all relevant dimensions:

### Identity and privilege

- run as an explicit non-root UID/GID;
- use rootless containers or user namespaces where compatible;
- set `allowPrivilegeEscalation=false` / `no-new-privileges`;
- drop all Linux capabilities and add back none unless measured need exists;
- never use privileged mode for an untrusted MCP server; and
- do not mount container-runtime sockets or sensitive host device nodes.

Docker's rootless mode runs both the daemon and containers inside a user
namespace, reducing exposure to daemon/runtime vulnerabilities. It is one layer,
not proof that mounts, network, secrets, or resource limits are safe.

### Filesystem

- use an immutable digest-pinned image;
- make the root filesystem read-only;
- mount only reviewed inputs, read-only where possible;
- provide a small, lifecycle-bound scratch volume;
- reject hostPath and broad home-directory mounts;
- prevent path traversal and symlink escape before mount construction; and
- remove scratch and outputs after verified collection.

Read-only root does not make every mount read-only and does not erase data from
memory or scratch. Inventory the complete mount table.

### Syscalls and mandatory access control

Use the runtime-default seccomp profile at minimum and keep AppArmor/SELinux
enforcement enabled. Docker describes its default seccomp profile as a
moderately protective allowlist designed for compatibility; it is not a proof
against every kernel exploit. Kubernetes notes that privileged containers
override or bypass important seccomp, AppArmor, SELinux, and capability
restrictions.

Landlock is a Linux security module that lets even unprivileged processes add
filesystem and, in newer ABIs, selected network restrictions to themselves and
their descendants. Detect the available ABI and enforce only claims the running
kernel supports; never silently claim unavailable Landlock controls.

### Resources and lifecycle

Set memory, CPU, PID, file descriptor, storage, log, network, request, and wall
time limits. Docker documents that containers have no resource constraints by
default. A container is not a resource sandbox until limits are configured and
observed.

On timeout or cancellation:

1. stop accepting new work;
2. terminate the complete process tree or workload;
3. wait for a bounded grace period;
4. force kill if necessary;
5. collect bounded evidence;
6. remove scratch, secrets, network identity, and workload; and
7. report a terminal state owned by the application.

## Kubernetes production mapping

`restricted_kubernetes_bundle()` generates a reference Pod and default-deny
NetworkPolicy with:

- digest-pinned image;
- `runtimeClassName: gvisor` as an example sandboxed runtime selection;
- no service-account token automount;
- no host network, PID, or IPC namespaces;
- non-root identity;
- RuntimeDefault seccomp and AppArmor requests;
- no privilege escalation or privileged mode;
- all capabilities dropped;
- read-only root filesystem;
- explicit CPU, memory, and ephemeral-storage limits;
- read-only input plus size-bounded scratch; and
- default-deny ingress and egress.

This is a reference mapping, not deployment proof. Verify that:

- Pod Security Admission enforces the Restricted standard at a pinned version;
- the RuntimeClass really selects the expected runtime on every eligible node;
- AppArmor/seccomp are enabled and applied on the node;
- the CNI plugin enforces NetworkPolicy;
- DNS and approved API egress are added without creating metadata, localhost,
  redirect, or DNS-rebinding paths;
- PID limits are enforced outside core Pod resource fields;
- admission exemptions cannot bypass the policy; and
- runtime, kernel, image, and node versions remain patched.

Kubernetes explicitly states there is no standard API definition of a
“sandboxed Pod,” and it does not prescribe one universal security profile for
every sandbox runtime. A RuntimeClass name is configuration, not evidence of
the actual isolation boundary.

## Sandboxed containers and microVMs

### gVisor

gVisor provides an OCI runtime (`runsc`) with an application kernel that handles
most workload system calls instead of passing them directly to the host Linux
kernel. Its security model still relies on cgroups for resource exhaustion and
on container-level network policy. Compatibility and performance should be
tested against the actual server workload.

### Kata Containers

Kata integrates with container tooling while placing workloads in lightweight
virtual machines with a guest kernel. It supports several hypervisors, including
QEMU, Cloud Hypervisor, and Firecracker. The stronger boundary does not remove
the need for image admission, minimal mounts, guest policy, network policy,
resource quotas, or patched hosts.

### Firecracker

Firecracker provides lightweight KVM microVMs with a reduced device model. Its
documentation recommends production use through the jailer, default seccomp,
cgroups, namespaces, and host hardening. Firecracker does not filter guest
network traffic; operators must enforce egress at the host layer. Hardware,
microcode, hypervisor, host kernel, side-channel, and tenant-placement decisions
remain part of the security model.

## WebAssembly and WASI

Wasmtime/WASI can expose only preopened directories and selected host imports,
making a capability-oriented boundary attractive for narrow portable workloads.
No preopened directory means no ambient filesystem capability through WASI.

Do not assume WebAssembly automatically solves resource exhaustion or unsafe
host integration. A 2026 Wasmtime advisory addressed guest-controlled host
resource exhaustion and added limits for resources and host-call copying. Pin a
patched runtime, bound fuel/epoch/time/memory/resources, minimize host functions,
and test the exact embedding. The host imports define real authority.

## Secrets and environment handling

Do not pass the parent's complete environment to a local server. Build a new
environment from an allowlist and prefer short-lived brokered credentials over
ambient tokens. Bind any secret to workload identity, audience, tenant, purpose,
and lifetime. Revoke it when the sandbox terminates.

Redact values in:

- process listings and command arguments;
- environment dumps and crash reports;
- stdout/stderr and MCP errors;
- traces, metrics labels, and audit events;
- snapshots, core dumps, swap, and scratch; and
- notebook outputs.

The lab injects a fake parent secret and proves that the worker sees only the
explicit safe keys plus a documented platform-injected key on macOS.

## Lab walkthrough

### 1. Run the executable scenario

From the repository root:

```bash
python curriculum/intermediate/09-runtime-isolation-sandboxing/lab.py
```

Expected result:

```text
PASS: bounded subprocess and admission controls block the tested escape paths
```

The scenario uses the official MCP Python SDK to call `document.inspect`, then
tests an unknown file, secret environment request, network request, cross-tenant
record, hung worker, and oversized output. Its evidence reports:

- valid MCP call success;
- blocked attempts and reason codes;
- forbidden effects observed in this fixture;
- parent-secret absence;
- raw-document absence from events;
- controls actually applied locally;
- address-space-limit availability; and
- production controls the lab refuses to claim.

An expected domain denial may log `document is unavailable`.

### 2. Run the notebook

Open `runtime_isolation.ipynb` and run all cells. You will:

1. inspect the MCP schema;
2. compare local and production boundaries;
3. execute a real child process;
4. verify environment minimization;
5. run an admission attack matrix;
6. kill a hung process and cap oversized output;
7. inspect the Kubernetes reference bundle;
8. calculate security metrics with correct denominators; and
9. run the end-to-end MCP scenario.

### 3. Run focused tests

```bash
python -m pytest -q tests/test_course_09_runtime_isolation.py
```

The focused suite covers positive, negative, boundary, and dependency-failure
cases, including path traversal, symlink escape, tenant mismatch, artifact
drift, unapproved environment keys, network denial, input size, arbitrary
operation rejection, timeout, output exhaustion, malformed output, non-zero
exit, event redaction, generic MCP denial, hardened-profile weakening, and
Kubernetes mapping.

## Evaluation

Label the expected outcome before executing a test. Report at least:

```text
blocked-attempt rate = expected-deny cases correctly denied / expected-deny cases
forbidden-effect rate = forbidden effects completed / adversarial attempts
false-deny rate = expected-allow cases denied / expected-allow cases
limit-enforcement rate = triggered limits reaching the expected terminal state / triggered limits
```

All denominators must be non-zero and reported. Slice results by runtime tier,
host OS/kernel, policy version, artifact digest, attack class, and tenant-risk
class where relevant.

Keep these categories separate:

- **attempt:** untrusted input requested a forbidden capability;
- **blocked attempt:** admission or runtime prevented it;
- **policy bypass:** forbidden work started because policy was not applied;
- **sandbox escape:** workload crossed an intended enforced boundary; and
- **forbidden effect:** unauthorized disclosure, mutation, egress, persistence,
  or resource impact actually occurred.

The lab's `fixture_forbidden_effects=0` applies only to its labelled cases. It is
not an empirical escape-rate claim for Python, containers, gVisor, Kubernetes,
or Firecracker.

## Operational evidence and response

Collect observable facts, not hidden model reasoning:

- request, trace, sandbox, tenant, workload, and evidence IDs;
- artifact digest and policy/profile versions;
- selected runtime class and node identity;
- validated operation and input digest, not sensitive content;
- admission decision and structured reason;
- start/end time, duration, exit code/signal, and terminal state;
- CPU, memory, PID, file-descriptor, storage, network, and output use;
- seccomp/LSM/network denials and runtime alerts;
- kill, quarantine, revoke, cleanup, and evidence-preservation actions; and
- verifier result and released-output digest.

Repeated egress denials, unexpected child processes, profile changes, runtime
alerts, or limit bursts should create a risk signal. High-confidence containment
may quarantine the workload, revoke credentials, and preserve evidence. A model
recommendation alone must not terminate production workloads or close an
incident.

## Production checklist

- [ ] Classify code trust, tenant boundary, data sensitivity, and host exposure.
- [ ] Require explicit installation/launch consent for local MCP servers.
- [ ] Verify immutable artifact provenance before runtime admission.
- [ ] Map opaque IDs to authorized records in trusted code.
- [ ] Keep commands, paths, identity, limits, and runtime profile out of tool input.
- [ ] Run non-root/rootless or with user namespaces where supported.
- [ ] Drop all capabilities and disallow privilege escalation and privileged mode.
- [ ] Use read-only root, minimal read-only mounts, and bounded disposable scratch.
- [ ] Apply seccomp and an LSM; verify they are enabled on the actual node.
- [ ] Set CPU, memory, PID, FD, storage, output, network, and wall-time limits.
- [ ] Default-deny network and independently test the enforcement path.
- [ ] Avoid ambient secrets; broker narrow, short-lived workload credentials.
- [ ] Kill the complete process tree and clean up on timeout/cancellation.
- [ ] Validate exit state and bounded typed output before release.
- [ ] Emit redacted policy and runtime evidence with stable correlation IDs.
- [ ] Patch runtimes, kernels, hypervisors, guest kernels, and microcode.
- [ ] Test escape, exhaustion, cleanup, failover, and outage behavior.
- [ ] Reassess isolation when the workload, host, dependency, or tenancy changes.

## Common mistakes

1. **Calling stdio a sandbox.** It is a transport to a spawned process; the
   launch environment defines privilege.
2. **Using approval as containment.** A user can approve malicious code, and
   reviewed code can later be compromised.
3. **Passing arbitrary commands through a typed tool.** A string schema does not
   make command execution safe.
4. **Inheriting the parent environment.** This leaks ambient secrets and config.
5. **Checking path prefixes as strings.** Traversal and symlinks require
   canonical, beneath-root resolution plus OS-level confinement.
6. **Assuming a container has limits.** Common runtimes require explicit resource
   configuration.
7. **Using privileged mode to fix compatibility.** It can nullify other
   isolation controls.
8. **Treating RuntimeClass as proof.** Verify actual scheduling and runtime
   evidence.
9. **Allowing network, then filtering only URLs in application code.** Compromised
   code can open sockets directly; enforce egress independently.
10. **Reporting a killed worker as success.** Terminal state and result validity
    belong to trusted application code.
11. **Logging the evidence payload.** Record digests and reason codes, not secrets
    or private documents.
12. **Calling blocked probes incidents or escapes.** Use precise denominators and
    outcome categories.

## Exercises

### Exercise 1: capability delta review

Add a second operation that writes a derived report. Define the exact additional
filesystem, resource, and egress capabilities it needs. Require a review when
the capability delta is non-empty and add tests showing the original operation
did not gain those capabilities.

### Exercise 2: optional Docker adapter

Implement an optional adapter using a digest-pinned image, non-root user,
read-only root, dropped capabilities, no-new-privileges, default seccomp,
memory/CPU/PID/output limits, network none, read-only input, and bounded tmpfs.
Keep the portable lab as the default and return actual `docker inspect` evidence.

### Exercise 3: runtime comparison

Run one reviewed fixture on a standard container and gVisor or Kata. Measure
startup latency, task latency, memory, compatibility failures, and privileged
surface. Do not claim stronger security from latency results; compare boundary
architecture and applied controls separately.

### Exercise 4: cancellation and cleanup

Add trusted cancellation while a worker is running. Prove the process tree
stops, scratch is removed, credentials are revoked, evidence is durable, and a
late child result cannot overwrite the cancelled terminal state.

## Knowledge check

1. Why does a successful Course 07 authorization decision not remove the need
   for Course 09 isolation?
2. What privilege does an unsandboxed stdio MCP server normally have?
3. Which controls in the lab are actually enforced, and which are admission
   requirements for a production platform?
4. Why are a read-only root filesystem and a default-deny NetworkPolicy separate
   controls?
5. What does `runtimeClassName: gvisor` prove by itself?
6. Why is `jti`, a request ID, or an audit record not evidence that a process was
   confined?
7. When should a microVM be preferred over a standard container?
8. How do blocked-attempt rate and forbidden-effect rate differ?

## Assessment rubric

| Criterion | Meets expectations |
|---|---|
| Trust boundary | Treats workload and model input as untrusted without granting authority |
| Admission | Binds reviewed artifact, operation, tenant data, environment, network, and limits |
| Real execution | Launches a bounded child without shell interpolation and verifies terminal state |
| Negative evidence | Covers escape inputs, resource exhaustion, dependency failures, and cleanup |
| Honest guarantees | Separates local subprocess controls from kernel, container, and VM claims |
| Production mapping | Uses hardened identity, filesystem, syscall, resource, network, and runtime settings |
| Evaluation | Uses labelled populations and distinguishes attempts, blocks, escapes, and effects |
| Observability | Emits correlated redacted evidence without document or secret contents |

## References

### MCP

- [MCP security policy and stdio trust model](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/SECURITY.md)
- [SEP-1024: client security requirements for local server installation](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/seps/1024-mcp-client-security-requirements-for-local-server-.md)
- [MCP 2026-07-28 security and trust guidance](https://modelcontextprotocol.io/specification/2026-07-28)
- [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk)

### Containers and Kubernetes

- [NIST SP 800-190: Application Container Security Guide](https://csrc.nist.gov/pubs/sp/800/190/final)
- [Docker seccomp security profiles](https://docs.docker.com/engine/security/seccomp/)
- [Docker rootless mode](https://docs.docker.com/engine/security/rootless/)
- [Docker resource constraints](https://docs.docker.com/engine/containers/resource_constraints/)
- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Kubernetes Linux kernel security constraints](https://kubernetes.io/docs/concepts/security/linux-kernel-security-constraints/)
- [Kubernetes security contexts](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Linux Landlock userspace API](https://www.kernel.org/doc/html/latest/userspace-api/landlock.html)

### Sandboxed runtimes and microVMs

- [gVisor security introduction](https://gvisor.dev/docs/architecture_guide/intro/)
- [gVisor security model](https://gvisor.dev/docs/architecture_guide/security/)
- [Kata Containers architecture](https://katacontainers.io/software/)
- [Firecracker design and sandboxing](https://github.com/firecracker-microvm/firecracker/blob/main/docs/design.md)
- [Firecracker production host setup](https://github.com/firecracker-microvm/firecracker/blob/main/docs/prod-host-setup.md)

### WebAssembly

- [Wasmtime WASI capability tutorial](https://github.com/bytecodealliance/wasmtime/blob/main/docs/WASI-tutorial.md)
- [Wasmtime resource-exhaustion advisory GHSA-852m-cvvp-9p4w](https://github.com/bytecodealliance/wasmtime/security/advisories/GHSA-852m-cvvp-9p4w)
