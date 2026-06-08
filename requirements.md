# API Scope Requirements

This tool is designed to work with the smallest practical set of Falcon API scopes.

## Required minimum

These scopes are needed for the current CLI flow:

- `alerts.read` - detection totals, category/severity breakdowns, NG-SIEM slices, and the OverWatch fallback path
- `cases.read` - cases totals and case severity breakdowns

## Optional scopes

These are only needed if you want the direct API-backed versions of certain sections instead of the built-in fallback behavior:

- `incidents.read` - direct CrowdScore / incidents-backed metrics
- `falcon_complete_dashboard` - primary OverWatch analyzed-events endpoint

## Notes

- If a required endpoint is unavailable, the script already falls back where possible.
- Keep scopes limited to the minimum above unless you specifically need the optional sections to use their primary endpoints.
