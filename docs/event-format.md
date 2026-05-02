# Event Format

`normalize_security_event()` accepts a dictionary and returns a stable public event shape.

Normalized fields:

- `id`
- `timestamp`
- `source_ip`
- `destination_ip`
- `source_port`
- `destination_port`
- `protocol`
- `hostname`
- `username`
- `event_type`
- `severity`
- `message`
- `raw_event`

Timestamps are normalized to UTC ISO-8601. Missing timestamps are rejected unless `allow_now_timestamp=True` is passed.

This helper does not enrich entities, score users, build cases, or correlate events.

