# Alert Output

This public repository does not implement private GreyNOC alert output or scoring.

Compatible engines may transform a validated rule match into an alert using their own private logic. A safe public alert shape may include:

- `rule_id`
- `title`
- `severity`
- `event_ids`
- `summary`
- `recommended_action`
- `created_at`

Do not add internal scoring fields, dedupe keys, entity-risk data, case links, graph evidence, or customer-specific identifiers to public examples.

