# Threat-model worksheet

Copy this table for each MCP server and commit the completed version with the release evidence.

| Asset / data | Principal | Trust boundary | Threat | Control | Test | Residual risk / owner |
| --- | --- | --- | --- | --- | --- | --- |
| Ticket text | Support agent | Client → server | Prompt injection | Delimit output; re-authorize tools | Malicious fixture |  |
| Tenant tickets | Workload identity | Server → API | Cross-tenant read | Tenant policy | Negative test |  |
| API credential | Server runtime | Process → network | Token theft | Short-lived audience token | Replay test |  |
| Package / image | CI → registry | Build → deploy | Dependency compromise | SBOM, signature, digest | Verify gate |  |

Use STRIDE or an attack tree. For every threat, name an owner, a deterministic test, an alert, and a recovery action. Do not mark “the model will avoid it” as a control.
