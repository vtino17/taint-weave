# Integration guide

## Pre-session gate

Build a manifest for the exact MCP servers and tools enabled in the target
agent profile:

```bash
taint-weave analyze session.json --policy flow-policy.json
```

Use the exit code as the provisioning gate:

- `0`: safe and complete.
- `2`: high-risk route is unapproved.
- `3`: lower-risk route requires review.
- `5`: malformed input.

## Review

Inspect one finding and suggested graph cuts:

```bash
taint-weave explain session.json \
  --policy flow-policy.json \
  --finding 0123456789abcdef

taint-weave cuts session.json --policy flow-policy.json
```

Prefer breaking the route by removing a tool, splitting the session, narrowing
accepted data, or adding a real sanitizer. Fingerprint approval should be the
exception.

## CI example

```yaml
name: MCP composition gate

on:
  pull_request:

jobs:
  information-flow:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v6
      - uses: pnpm/action-setup@v4
        with:
          version: 10.14.0
      - uses: actions/setup-node@v6
        with:
          node-version: 22
          cache: pnpm
      - run: pnpm install --frozen-lockfile
      - run: pnpm weave analyze session.json --policy flow-policy.json
```

## Receipt

Archive a receipt with the approved agent configuration. It binds the manifest,
policy, and analysis using SHA-256. The receipt is tamper-evident but not signed;
sign it externally when reviewer identity must be authenticated.
