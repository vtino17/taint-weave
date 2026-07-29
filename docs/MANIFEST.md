# Session manifest reference

A session manifest describes the tools that will coexist in one agent context.

```json
{
  "schemaVersion": "1.0",
  "sessionId": "research-session",
  "summary": "Search, sanitize, and publish public research.",
  "servers": [
    {
      "id": "web",
      "trustZone": "partner",
      "tools": [
        {
          "name": "search",
          "description": "Read public web content.",
          "consumes": ["public"],
          "produces": ["untrusted"],
          "sanitizes": [],
          "capabilities": ["untrusted-read", "external-read"],
          "requiresHumanApproval": false
        }
      ]
    }
  ]
}
```

## Trust zones

- `trusted`: controlled and reviewed by the session owner.
- `partner`: operated by an identified third party with limited trust.
- `untrusted`: unknown, community-provided, or intentionally adversarial.

Cross-zone status is derived from the server owning each tool.

## Data classes

- `public`: safe for unrestricted disclosure.
- `internal`: non-public operational information.
- `personal`: personally identifying or user-specific data.
- `confidential`: sensitive organizational content.
- `credential`: tokens, passwords, keys, and authentication material.
- `untrusted`: content that may contain attacker-controlled instructions.
- `any`: wildcard accepted or produced class.

`any` should be used sparingly. A consumer accepting `any` can receive every
active taint.

## Capabilities

Supported capabilities are `private-read`, `untrusted-read`, `external-send`,
`external-read`, `write`, `destructive`, `execute-code`, and `transform`.

Capabilities describe roles used by policy rules. They do not prove runtime
behavior.

## Sanitizers

A sanitizer removes named incoming taints before propagation continues. The
tool may also originate new output classes through `produces`.

Only declare sanitization when a deterministic control makes the output inert.
Prompt instructions such as “ignore malicious text” are not reliable
sanitizers.
