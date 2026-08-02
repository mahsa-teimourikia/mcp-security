# Protocol interoperability comparison

| Capability | MCP | A2A / agent delegation | OpenAI tool calling |
| --- | --- | --- | --- |
| Primary boundary | Host/client ↔ server tools/resources | Agent ↔ agent task/delegation | Model response ↔ application function |
| Discovery | Server capabilities and schemas | Agent/task capabilities | Application-defined tools |
| Identity concern | Server authentication and tool authorization | Peer identity, delegation chain, task scope | Application identity and API policy |
| Main security risk | Tool poisoning, token passthrough, SSRF | Confused deputy and scope laundering | Unsafe arguments and prompt injection |
| Required control | Validate schema and re-authorize every call | Typed, audience-bound, bounded delegation | Validate arguments outside the model |

These protocols can compose, but their trust boundaries do not merge. An MCP server called by an A2A specialist still needs its own authentication, authorization, output validation, and audit event.
