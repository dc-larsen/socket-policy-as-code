# socket-policy-as-code

Manage a [Socket.dev](https://socket.dev) org security policy from a git repo. The policy lives in `policy/security-policy.json`, changes ship through pull requests, and two GitHub Actions keep the repo and the Socket dashboard in sync in both directions:

- **Apply** (`.github/workflows/apply.yml`): when a change to the policy file lands on `main`, it is POSTed to the Socket API and read back to verify it took effect.
- **Drift** (`.github/workflows/drift.yml`): a scheduled job pulls the live policy and opens a PR if someone changed it in the dashboard. Merge the PR to accept the dashboard change, or close it and push the intended values so the apply workflow re-asserts them.

The result: every policy change is a reviewed commit, and out-of-band dashboard edits surface as PRs instead of silent divergence.

## Setup

1. Create a Socket API token (Dashboard, Settings, API Tokens) with the `security-policy:read` and `security-policy:update` scopes.
2. Add it as an Actions secret named `SOCKET_API_KEY`.
3. Add an Actions variable named `SOCKET_ORG_SLUG` with your org slug.
4. In Settings, Actions, General, enable "Allow GitHub Actions to create and approve pull requests" so the drift job can open PRs.
5. Seed the file from your current live policy:

   ```bash
   export SOCKET_API_KEY=... SOCKET_ORG_SLUG=your-org
   python3 scripts/socket_policy.py pull
   git add policy/security-policy.json && git commit -m "Seed policy from live org"
   ```

From then on, edit `policy/security-policy.json` in a PR. Rule names and actions match the dashboard's security policy page; each rule takes one of `defer`, `error`, `warn`, `monitor`, or `ignore`:

```json
{
  "policyDefault": "high",
  "policyRules": {
    "recentlyPublished": { "action": "error" },
    "telemetry": { "action": "warn" }
  }
}
```

## API notes (learned by testing)

- **Read and write shapes differ.** `GET /v0/orgs/{org}/settings/security-policy` returns `securityPolicyRules` / `securityPolicyDefault`; `POST` to the same path expects `policyRules` / `policyDefault`. The script normalizes reads into the write shape so the file round-trips.
- **POST merges.** Rules in the body are upserted; rules missing from the body are untouched. Removing a customization means setting the rule back to its intended action in the file (or `POST {"resetPolicyRules": true}` to wipe all customizations). The drift job is what makes merge semantics safe: dashboard-only rules show up in its PRs.
- **`custom_rules_only=true`** keeps the file down to intentional customizations instead of the full rule catalog.
- Auth is HTTP Basic with the token as username and an empty password: `curl -u "$SOCKET_API_KEY:" ...`

## Extending the pattern to allowlists

Alert triage rules (allowlist and blocklist entries) have the same API surface and the same pattern applies:

- `GET /v0/orgs/{org}/triage/alerts` lists entries.
- `POST /v0/orgs/{org}/triage/alerts` upserts a batch: `{"alertTriage": [{"packageType": "npm", "packageNamespace": null, "packageName": "left-pad", "packageVersion": null, "alertType": "recentlyPublished", "alertKey": null, "cveOrGhsaId": null, "cvssScoreCmp": null, "state": "ignore", "note": "why"}]}`. Filter fields must be present explicitly (`null` or `"*"` for wildcards), and entries without a specific `alertKey` need `?force=true`. Token scope: `triage:alerts-update`.
- `DELETE /v0/orgs/{org}/triage/alerts/{uuid}` removes an entry.

A `policy/triage-alerts.json` plus the same apply/drift pair gives you allowlists as code. Deletion works differently than for the security policy: triage entries are keyed by server-generated UUID, so a sync script diffs on the filter fields and issues DELETEs for entries that leave the file.
