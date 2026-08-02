# 4. Runtime isolation and tool safety

Run local MCP servers with a dedicated identity, read-only mounts, a temporary workspace, CPU/memory/time limits, and an explicit network egress policy. Containers are a packaging boundary, not automatically a security boundary; consider gVisor, a separate VM, or a platform sandbox for hostile code.

## Tool safety checklist

- Allow-list tool names and versions; reject unknown capabilities.
- Validate JSON Schema, then apply semantic rules (tenant, path, amount, destination).
- Resolve paths and prevent traversal, symlink escapes, and hidden mounts.
- Permit only approved HTTPS destinations; block localhost, link-local, metadata, and private ranges unless explicitly required.
- Redact secrets from tool arguments and outputs; cap payload size and retries.
- Require approval before side effects and make operations idempotent where possible.
- Treat resources and tool results as untrusted content; delimit them from instructions.

The [OWASP AI Agent Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html) and [MCP security guidance](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices) provide practical control checklists.
