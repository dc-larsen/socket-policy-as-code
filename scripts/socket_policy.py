#!/usr/bin/env python3
"""Sync a Socket.dev org security policy with a JSON file in this repo.

Two subcommands:

  apply   Read policy/security-policy.json and POST it to the Socket API,
          then read the policy back and verify every rule in the file is
          live. Exits non-zero if the API rejects the update or the
          verification read does not match.

  pull    Read the live policy from the Socket API, normalize it to the
          file format, and write policy/security-policy.json. Used by the
          drift workflow and for seeding the file initially.

The file uses the API's write shape:

  {
    "policyDefault": "high",
    "policyRules": {
      "telemetry": {"action": "warn"}
    }
  }

Note the read/write asymmetry in the API: GET returns securityPolicyRules
and securityPolicyDefault, while POST expects policyRules and policyDefault.
This script normalizes reads into the write shape so the file round-trips.

The POST endpoint merges: rules in the body are upserted and rules missing
from the body are left alone. Applying the file therefore never removes a
customization made in the dashboard. The drift workflow covers that
direction by pulling the live policy and opening a pull request when it
differs from the file.

Environment:
  SOCKET_API_KEY    API token with security-policy:read and
                    security-policy:update scopes.
  SOCKET_ORG_SLUG   Org slug, e.g. my-org.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

API_BASE = "https://api.socket.dev/v0"
POLICY_FILE = Path(__file__).resolve().parent.parent / "policy" / "security-policy.json"

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger("socket-policy")


def _env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        log.error("%s is not set", name)
        sys.exit(2)
    return value


def _request(method: str, url: str, token: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
    """Call the Socket API. Basic auth is base64('TOKEN:'), the trailing
    colon inside the encoded input (token as username, empty password)."""
    encoded = base64.b64encode(f"{token}:".encode()).decode("ascii")
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={
            "Authorization": f"Basic {encoded}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "socket-policy-as-code/1.0",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as err:
        detail = err.read().decode(errors="replace")
        log.error("%s %s returned HTTP %d: %s", method, url, err.code, detail)
        sys.exit(1)
    except urllib.error.URLError as err:
        log.error("%s %s failed: %s", method, url, err.reason)
        sys.exit(1)


def _policy_url(org_slug: str) -> str:
    return f"{API_BASE}/orgs/{org_slug}/settings/security-policy?custom_rules_only=true"


def normalize(api_response: dict[str, Any]) -> dict[str, Any]:
    """Convert the GET response shape into the POST/file shape, with rules
    sorted by name so diffs stay stable."""
    rules = api_response.get("securityPolicyRules") or {}
    return {
        "policyDefault": api_response.get("securityPolicyDefault", "default"),
        "policyRules": {name: rules[name] for name in sorted(rules)},
    }


def read_policy_file() -> dict[str, Any]:
    if not POLICY_FILE.exists():
        log.error("policy file not found: %s", POLICY_FILE)
        sys.exit(2)
    with POLICY_FILE.open() as fh:
        return json.load(fh)


def write_policy_file(policy: dict[str, Any]) -> None:
    POLICY_FILE.parent.mkdir(parents=True, exist_ok=True)
    with POLICY_FILE.open("w") as fh:
        json.dump(policy, fh, indent=2, sort_keys=False)
        fh.write("\n")


def cmd_apply(token: str, org_slug: str) -> int:
    desired = read_policy_file()
    log.info(
        "applying %d rule(s), policyDefault=%s, to org %s",
        len(desired.get("policyRules", {})),
        desired.get("policyDefault"),
        org_slug,
    )
    _request("POST", _policy_url(org_slug), token, desired)

    live = normalize(_request("GET", _policy_url(org_slug), token))

    failures = []
    if desired.get("policyDefault") and live["policyDefault"] != desired["policyDefault"]:
        failures.append(f"policyDefault: wanted {desired['policyDefault']}, live {live['policyDefault']}")
    for name, rule in desired.get("policyRules", {}).items():
        live_rule = live["policyRules"].get(name)
        if live_rule != rule:
            failures.append(f"{name}: wanted {rule}, live {live_rule}")

    if failures:
        for failure in failures:
            log.error("verify failed: %s", failure)
        return 1

    extras = sorted(set(live["policyRules"]) - set(desired.get("policyRules", {})))
    if extras:
        log.warning(
            "live policy has customized rules not in the file (POST merges and cannot remove them): %s",
            ", ".join(extras),
        )
        log.warning("run the drift workflow, or add them to the file, to reconcile")

    log.info("applied and verified %d rule(s)", len(desired.get("policyRules", {})))
    return 0


def cmd_pull(token: str, org_slug: str) -> int:
    live = normalize(_request("GET", _policy_url(org_slug), token))
    write_policy_file(live)
    log.info(
        "wrote %s (%d rule(s), policyDefault=%s)",
        POLICY_FILE,
        len(live["policyRules"]),
        live["policyDefault"],
    )
    return 0


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in {"apply", "pull"}:
        print(__doc__, file=sys.stderr)
        return 2
    token = _env("SOCKET_API_KEY")
    org_slug = _env("SOCKET_ORG_SLUG")
    if sys.argv[1] == "apply":
        return cmd_apply(token, org_slug)
    return cmd_pull(token, org_slug)


if __name__ == "__main__":
    sys.exit(main())
