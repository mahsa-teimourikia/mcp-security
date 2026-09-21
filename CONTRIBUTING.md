# Contributing

Thank you for improving MCP Security Engineering.

## Add or revise a lesson

Keep every published topic vertically complete:

1. Update its `README.md` with motivation, mental model, mechanics, a worked
   scenario, failure modes, evaluation, production concerns, exercises, and
   authoritative references.
2. Put reusable, typed, credential-free behavior in `lab.py`.
3. Keep exactly one canonical notebook beside the lab. It should import the
   same implementation, inject a failure, interpret results, and end with
   production upgrades and exercises.
4. Add focused tests for both allowed and denied behavior.
5. Update the course map, Learning Hub, and quiz/checkpoint as needed.

Do not present a placeholder or planned topic as published. Model output,
retrieved content, peer messages, and tool metadata remain untrusted; trusted
application code owns validation, authorization, execution, verification, and
audit evidence.

## Pull requests

Keep changes focused and explain validation performed. Prefer protocol
specifications, standards, official documentation, and primary research.
Never commit credentials, raw access tokens, customer data, notebook caches,
or generated dependency folders.
