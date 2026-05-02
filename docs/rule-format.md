# Rule Format

GreyNOC public rules are JSON objects. They are data definitions only and do not contain private engine execution logic.

Required fields:

- `id`: stable lowercase identifier.
- `type`: supported rule type.
- `title`: short analyst-facing title.
- `severity`: one of `info`, `low`, `medium`, `high`, or `critical`.
- `description`: public defensive context.
- `recommended_action`: next step for a defender.
- `conditions`: generic match hints for compatible engines.

Optional fields:

- `tags`: string labels.
- `references`: public URLs or identifiers.

Supported public rule types:

- `port_scan`
- `brute_force`
- `malware_beaconing`
- `suspicious_powershell`
- `scan_finding`
- `ai_user_agent_abuse`

The public package validates rule shape and obvious regex risk. It does not evaluate events or score alerts.

