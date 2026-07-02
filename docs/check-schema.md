# Check Schema Reference

Every check in `e8scan/checks/` is a YAML file with the following schema:

## Required fields

| Field | Type | Description |
|---|---|---|
| `id` | string | Unique check ID, e.g. `E8-OM-001` |
| `strategy` | string | One of the 8 strategy names (see below) |
| `title` | string | Short human-readable description |
| `ism_controls` | list[string] | ISM control IDs this check maps to |
| `maturity_level` | int | 1, 2, or 3 |
| `platforms` | list[string] | `windows`, `linux`, `macos`, or `all` |
| `severity` | string | `critical`, `high`, `medium`, `low`, or `info` |
| `check` | mapping | Check definition (see below) |
| `remediation` | string | How to fix a failure |

## Optional fields

| Field | Type | Description |
|---|---|---|
| `references` | list[string] | URLs to documentation |

## Valid strategies

- `configure_office_macros`
- `patch_operating_systems`
- `restrict_admin_privileges`
- `user_application_hardening`
- `multi_factor_authentication`
- `regular_backups`
- `application_control`
- `patch_applications`

## Check types

### `registry` (Windows only)

```yaml
check:
  type: registry
  hive: HKLM          # HKLM | HKCU | HKCR | HKU | HKCC
  path: 'SOFTWARE\Policies\Microsoft\...'
  key: keyname
  expected: 1
  operator: equals    # equals | not_equals | gte (optional, default: equals)
```

### `command`

```yaml
check:
  type: command
  cmd: "uname -r"           # string or platform dict
  # Platform dict:
  # cmd:
  #   windows: "..."
  #   linux: "..."
  #   macos: "..."
  shell: true
  operator: equals          # equals | not_equals | contains | not_contains | regex | jsonpath | version_gte | exit_code
  expected: "5.15"
  timeout: 30               # seconds
  # For jsonpath operator:
  jsonpath_field: "FieldName.SubField"
```

### `file`

```yaml
check:
  type: file
  path: /etc/apt/apt.conf.d/20auto-upgrades
  operator: exists          # exists | not_exists | contains | not_contains | regex | permissions
  expected: "some string"   # for contains/regex/permissions
```

### `service`

```yaml
check:
  type: service
  name: wuauserv
  expected_state: running   # running | stopped | enabled
```

### `manual`

```yaml
check:
  type: manual
  guidance: >
    Verify manually that ...
```

Manual checks always return status `MANUAL` and display the guidance text in reports.

## Example

```yaml
id: E8-OM-001
strategy: configure_office_macros
title: "Office macros from the internet are blocked (Word)"
ism_controls: ["ISM-1671", "ISM-1488"]
maturity_level: 1
platforms: [windows]
severity: high
check:
  type: registry
  hive: HKLM
  path: 'SOFTWARE\Policies\Microsoft\Office\16.0\Word\Security'
  key: blockcontentexecutionfrominternet
  expected: 1
remediation: >
  Enable "Block macros from running in Office files from the Internet"
  via Group Policy.
references:
  - https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight
```
