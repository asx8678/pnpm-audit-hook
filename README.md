# pnpm-audit-hook

`pnpm` hook-based package guard that can block or warn on denied dependencies during install.

## How It Works

- `.pnpmfile.cjs` loads `src/audit-hook.cjs`.
- The `readPackage` hook evaluates each package against policy rules.
- On a match, behavior is controlled by `onViolation`:
  - `fail` throws and stops the install.
  - `warn` logs and allows the install to continue.

## Policy File

Default path: `pnpm-audit-policy.json` (project root).  
Override path with `PNPM_AUDIT_POLICY_PATH`.

```json
{
  "onViolation": "fail",
  "onError": "fail",
  "rules": [
    {
      "name": "event-stream",
      "versions": ["3.3.6"],
      "reason": "Known compromised release"
    },
    {
      "name": "example-package",
      "versions": ["1.2.*"]
    }
  ]
}
```

## Rule Matching

- `name` must match package name exactly.
- `versions` is optional:
  - Omit it to match all versions of that package.
  - Use exact versions such as `"1.2.3"`.
  - Use wildcard suffix such as `"1.2.*"`.
  - Use `"*"` to match any version.

## Error Handling

- `onError: "fail"` blocks installs on policy parse/validation errors.
- `onError: "warn"` logs policy errors and falls back to an empty rule set.
- `PNPM_AUDIT_ON_ERROR` can override bootstrap behavior.
- `PNPM_AUDIT_ON_VIOLATION` can override violation behavior.

## Tests

Run:

```bash
npm test
```
