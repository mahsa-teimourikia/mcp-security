# 5. Incident response and operations

## Detect and contain

Alert on unexpected tools, new destinations, privilege changes, unusual volume, schema drift, failed signature checks, and prompt-injection indicators. A kill switch should disable a server, revoke its tokens, and block its network identity in seconds.

1. Declare an incident and assign an owner.
2. Disable the MCP server and revoke credentials; do not destroy evidence.
3. Identify affected sessions, users, resources, tool calls, and package digests.
4. Preserve audit logs, manifests, images, SBOMs, and relevant model/tool output.
5. Rotate exposed secrets and notify data owners.
6. Rebuild from a reviewed commit, verify provenance, and deploy a canary.
7. Restore gradually, monitor, and publish a post-incident review with control changes.

Trace `user → host → client → server → tool → resource` with OpenTelemetry. Record correlation ID, principal, audience, policy version, decision, artifact digest, and outcome; never record raw access tokens or unnecessary personal data. Test the runbook quarterly with a simulated malicious server.
