# JSON Report Schema

When running `e8scan scan --format json`, the output follows this schema:

```json
{
  "schema_version": "1.0",
  "generated_at": "2024-01-01T00:00:00+00:00",
  "platform": {
    "system": "Linux",
    "version": "...",
    "python": "3.11.0"
  },
  "summary": {
    "total": 33,
    "pass": 10,
    "fail": 5,
    "error": 2,
    "skipped": 12,
    "manual": 4,
    "indicative_maturity_level": 0
  },
  "results": [
    {
      "id": "E8-OM-001",
      "title": "Office macros from the internet are blocked (Word)",
      "strategy": "configure_office_macros",
      "maturity_level": 1,
      "severity": "high",
      "ism_controls": ["ISM-1671", "ISM-1488"],
      "status": "PASS",
      "actual_value": "1",
      "message": "",
      "remediation": "...",
      "references": ["..."]
    }
  ]
}
```

## Status values

| Value | Meaning |
|---|---|
| `PASS` | Check passed |
| `FAIL` | Check failed — see `message` and `remediation` |
| `SKIPPED` | Check not applicable on this platform |
| `ERROR` | Check could not run (permission denied, tool missing, etc.) |
| `MANUAL` | Manual verification required — see `message` |
