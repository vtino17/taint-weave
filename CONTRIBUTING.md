# Contributing

Thank you for improving TaintWeave.

## Development

Requirements: Node.js 20+ and pnpm 10.14+.

```bash
pnpm install
pnpm check
pnpm dev
```

New rules should include a safe composition, an adversarial composition, a
stable code and severity, deterministic fingerprints, and documented false
positive and false negative boundaries.

Keep the core offline, model-free, and usable in Node.js and modern browsers.
Run `pnpm check` before opening a pull request.

Contributions are licensed under the MIT License.
