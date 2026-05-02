# GreyNOC Detections

Public-safe detection rule package for GreyNOC-compatible security events.

This repository contains rule examples, schemas, documentation, event normalization helpers, and a rule validator. It intentionally does not include the private GreyNOC detection engine, orchestration, alert scoring, entity-risk scoring, case building, dedupe stores, advanced correlation logic, or proprietary AI/prompt-abuse fingerprints.

## Quickstart

Install the package in editable mode:

```bash
python -m pip install -e .
```

Validate the bundled example rules:

```bash
python -m greynoc_detections.validate rules/examples
```

Normalize a sample event:

```python
import json
from pathlib import Path
from greynoc_detections import normalize_security_event

events = json.loads(Path("tests/sample_events.json").read_text())
print(normalize_security_event(events[0]))
```

Run tests:

```bash
python -m pytest
```

## What Is Public

- Rule format documentation.
- Generic example detection rules.
- JSON schema for rule shape.
- Lightweight event normalization.
- Safe rule validation, including simple ReDoS checks for regex patterns.
- CLI validation for rule JSON files.

## What Is Not Included

- Detection engine orchestration.
- `DetectionEngine` or `evaluate()` implementations.
- Alert scoring or entity risk scoring.
- Case building or dedupe storage.
- Coordinated attack, graph, or attack-chain correlation internals.
- Private AI/prompt-abuse fingerprint lists.
- Customer-specific thresholds, IPs, hostnames, users, or examples.

## Rule Compatibility

Rules are data only. They describe what a public detector may match, but do not ship private GreyNOC execution behavior. Private deployments can import and validate these rules before loading them into an internal engine.

