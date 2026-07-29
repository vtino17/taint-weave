# Flow policy reference

```json
{
  "policyVersion": "1.0",
  "sessionId": "research-session",
  "maxPathLength": 4,
  "maxFindings": 100,
  "sensitiveClasses": ["personal", "confidential", "credential"],
  "untrustedClasses": ["untrusted"],
  "externalSinkCapabilities": ["external-send"],
  "privilegedCapabilities": ["execute-code", "destructive"],
  "requireApprovalAcrossZones": true,
  "blockUnapprovedHighRisk": true,
  "approvals": []
}
```

- `maxPathLength` limits the number of tools in one explored route.
- `maxFindings` bounds stored results and contributes to the exploration cap.
- `sensitiveClasses` defines data that must not reach external sinks.
- `untrustedClasses` defines attacker-influence taints.
- `externalSinkCapabilities` identifies exfiltration-capable destinations.
- `privilegedCapabilities` identifies sinks that untrusted content must not
  reach.
- `requireApprovalAcrossZones` flags sensitive trust-boundary crossings.
- `blockUnapprovedHighRisk` blocks unapproved high and critical findings.
- `approvals` contains accepted finding fingerprints.

If exploration or findings are truncated, the result cannot be certified even
when the visible findings are approved.

Approvals should be stored on a protected branch and issued by a reviewer who
can verify the manifest against actual server behavior.
