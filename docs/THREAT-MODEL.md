# Threat model

TaintWeave addresses dangerous information-flow paths that emerge when multiple
MCP servers and tools coexist in one agent session.

## Threats addressed

| Threat | Control |
| --- | --- |
| Private data can reach an external sender | Sensitive source-to-sink analysis |
| Untrusted content can influence shell or destructive tools | Untrusted-to-privileged paths |
| Individually benign tools form the lethal trifecta | Session composition rule |
| Sensitive data crosses server ownership | Trust-zone flow finding |
| Untrusted server offers a privileged action | Server-zone capability rule |
| Approval reused after the route changes | Finding fingerprint |
| Search budget hides routes | Truncation prevents certification |
| Receipt copied to another configuration | Manifest, policy, and analysis hashes |

## Trust assumptions

- The manifest represents every tool available to the agent.
- Tool data classes, capabilities, and sanitizers were independently reviewed.
- Policy and approvals are protected from the profile author.
- The execution environment and SHA-256 implementation are trusted.

## Out of scope

TaintWeave does not:

- inspect or execute MCP server code;
- infer profiles from natural-language descriptions;
- guarantee that a declared sanitizer is effective;
- model control flow inside an individual tool;
- predict which path an LLM will choose;
- enforce OAuth, network, filesystem, or process restrictions;
- provide a complete formal non-interference proof;
- authenticate reviewers or digitally sign receipts.

## Conservative propagation

Incoming taint persists through a tool unless the profile explicitly names that
class in `sanitizes`. This can produce false positives when an implementation
implicitly aggregates or discards data. Declare a sanitizer only when that
behavior is deterministic and reviewed.

Paths are simple and bounded. Very large graphs may be truncated; such results
cannot receive a receipt.

## Layered deployment

Use TaintWeave before provisioning a session. Combine it with least-privilege
tool selection, separate agent contexts, trusted profile generation, server
code review, runtime taint markers, sandboxing, network egress controls, and
human confirmation for privileged actions.
