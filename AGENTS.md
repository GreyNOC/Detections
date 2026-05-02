# Agent Instructions

This repository is public-safe by design. Future coding agents must keep it that way.

Allowed work:

- Rule schemas and docs.
- Generic example rules.
- Rule validation.
- Event normalization.
- Tests for public behavior.

Never add:

- `DetectionEngine`, `evaluate()`, or engine orchestration.
- Alert scoring, entity-risk scoring, or case-building logic.
- Coordinated attack correlation, graph correlation, or attack-chain progression internals.
- Internal dedupe store dependencies.
- Private AI/prompt-abuse fingerprints or proprietary crawler/token lists.
- Customer-specific thresholds, IPs, hostnames, usernames, secrets, or telemetry.

When in doubt, prefer a smaller public validation helper over executable detection logic.

