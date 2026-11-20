"""
checks/drift.py
Custom Check: Configuration & Account Drift Detector.
Compares current MySQL accounts and security variables against a local baseline in ./output/baseline.json.
"""

import json
import os
from datetime import datetime, timezone

BASELINE_DIR = "output"
BASELINE_FILE = os.path.join(BASELINE_DIR, "baseline.json")

TRACKED_VARIABLES = (
    "local_infile",
    "secure_file_priv",
    "require_secure_transport",
    "tls_version",
    "sql_mode",
    "max_connections",
)


def _to_str(val):
    if isinstance(val, (bytes, bytearray)):
        return val.decode("utf-8", errors="replace")
    return "" if val is None else str(val)


def _run_query(connector, query):
    if hasattr(connector, "query"):
        return connector.query(query)
    if hasattr(connector, "execute"):
        return connector.execute(query)
    cursor = connector.cursor()
    cursor.execute(query)
    rows = cursor.fetchall()
    cursor.close()
    return rows


def _collect_snapshot(connector):
    user_rows = _run_query(
        connector,
        "SELECT user, host, account_locked, Super_priv, Grant_priv FROM mysql.user ORDER BY user, host;",
    )
    users = [
        {
            "account": f"'{_to_str(r[0])}'@'{_to_str(r[1])}'",
            "locked": _to_str(r[2]),
            "super": _to_str(r[3]),
            "grant": _to_str(r[4]),
        }
        for r in user_rows
    ]

    var_rows = _run_query(connector, "SHOW GLOBAL VARIABLES;")
    variables = {
        _to_str(r[0]): _to_str(r[1])
        for r in var_rows
        if _to_str(r[0]) in TRACKED_VARIABLES
    }

    return {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "users": users,
        "variables": variables,
    }


def check_configuration_drift(connector, baseline_path=BASELINE_FILE, reset_baseline=False):
    """Custom: Detects account or security configuration drift against saved baseline."""
    try:
        current = _collect_snapshot(connector)
        os.makedirs(os.path.dirname(baseline_path) or BASELINE_DIR, exist_ok=True)

        if reset_baseline or not os.path.exists(baseline_path):
            with open(baseline_path, "w", encoding="utf-8") as f:
                json.dump(current, f, indent=2)
            return {
                "cis_id": "Custom",
                "title": "Configuration and account drift check",
                "level": "Custom",
                "status": "PASS",
                "detail": f"Baseline snapshot saved to '{baseline_path}' ({len(current['users'])} accounts).",
                "remediation": "Re-run audit later to detect unauthorized changes against this baseline.",
            }

        with open(baseline_path, "r", encoding="utf-8") as f:
            baseline = json.load(f)

        diffs = []
        base_accounts = {u["account"]: u for u in baseline.get("users", [])}
        curr_accounts = {u["account"]: u for u in current.get("users", [])}

        for acc in sorted(set(curr_accounts) - set(base_accounts)):
            diffs.append(f"New account added: {acc}")
        for acc in sorted(set(base_accounts) - set(curr_accounts)):
            diffs.append(f"Account removed: {acc}")
        for acc in sorted(set(curr_accounts) & set(base_accounts)):
            if curr_accounts[acc] != base_accounts[acc]:
                diffs.append(f"Account privileges/lock changed: {acc}")

        base_vars = baseline.get("variables", {})
        curr_vars = current.get("variables", {})
        for var_name in TRACKED_VARIABLES:
            if base_vars.get(var_name) != curr_vars.get(var_name):
                diffs.append(
                    f"Variable '{var_name}' drifted: '{base_vars.get(var_name)}' -> '{curr_vars.get(var_name)}'"
                )

        if diffs:
            return {
                "cis_id": "Custom",
                "title": "Configuration and account drift check",
                "level": "Custom",
                "status": "FAIL",
                "detail": "Drift detected: " + "; ".join(diffs),
                "remediation": "Review changes and update baseline only if changes were authorized.",
            }

        return {
            "cis_id": "Custom",
            "title": "Configuration and account drift check",
            "level": "Custom",
            "status": "PASS",
            "detail": f"No drift detected since baseline ({baseline.get('captured_at')}).",
            "remediation": "None required.",
        }
    except Exception as exc:
        return {
            "cis_id": "Custom",
            "title": "Configuration and account drift check",
            "level": "Custom",
            "status": "ERROR",
            "detail": f"Drift check failed: {exc}",
            "remediation": "Verify ./output directory permissions and database connectivity.",
        }


def run_checks(connector):
    return [check_configuration_drift(connector)]