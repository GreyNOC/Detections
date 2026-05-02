# Contributing

Thanks for helping improve GreyNOC Detections.

## Submitting Rules

New rules should be generic, defensive, and public-safe.

1. Add or update JSON rule files under `rules/`.
2. Validate rules with `python -m greynoc_detections.validate rules`.
3. Add tests when changing validator or normalizer behavior.
4. Keep examples free of customer-specific IPs, hostnames, usernames, tokens, or secrets.

## Rule Requirements

Every rule needs:

- `id`
- `type`
- `title`
- `severity`
- `description`
- `recommended_action`
- `conditions`

Use generic documentation and public ATT&CK references when useful. Keep thresholds conservative and explain them in rule metadata.

## Public-Safety Boundaries

Do not add:

- Engine orchestration or evaluation loops.
- Alert scoring, entity-risk scoring, or case building.
- Advanced correlation graphs or attack-chain progression logic.
- Private AI/prompt-abuse token lists.
- Dedupe store integrations.
- Customer-specific telemetry or identifiers.

