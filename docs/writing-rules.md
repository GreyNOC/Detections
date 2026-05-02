# Writing Rules

Good public rules are generic, defensive, and easy to validate.

Guidelines:

- Use generic examples and documentation.
- Keep conditions simple and understandable.
- Prefer anchored or bounded regex patterns.
- Avoid customer-specific thresholds, identifiers, or infrastructure names.
- Explain the defensive value in `description`.
- Provide a practical `recommended_action`.

Avoid:

- Proprietary correlation behavior.
- Offensive instructions.
- Private prompt-abuse or crawler fingerprint lists.
- Secrets, tokens, real customer logs, hostnames, usernames, or IPs.

Validate before submitting:

```bash
python -m greynoc_detections.validate rules
```

