"""
checks/filesystem.py
Audits MySQL filesystem paths and permissions (CIS 3.1, 3.3).
Handles remote/Docker targets safely without crashing when host paths differ.
"""

import os
import stat


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


def _inspect_path_permissions(path, max_mode):
    """Checks POSIX permissions if the path is accessible on the local host."""
    if os.name == "nt":
        return "SKIPPED", f"Host is Windows; cannot verify POSIX permissions for '{path}'."
    try:
        st = os.stat(path)
        perms = stat.S_IMODE(st.st_mode)
        if perms & ~max_mode:
            return "FAIL", f"Path '{path}' has overly permissive mode {oct(perms)} (expected <= {oct(max_mode)})."
        return "PASS", f"Path '{path}' permissions {oct(perms)} meet CIS requirements."
    except FileNotFoundError:
        return "SKIPPED", f"Path '{path}' not found on local host (target is likely Docker/remote)."
    except PermissionError:
        return "ERROR", f"Permission denied inspecting '{path}' on local host."


def check_datadir_permissions(connector):
    """CIS 3.1: Ensure 'datadir' Has Appropriate Permissions."""
    try:
        rows = _run_query(connector, "SHOW VARIABLES LIKE 'datadir';")
        datadir = _to_str(rows[0][1]) if rows else ""
        if not datadir:
            return {
                "cis_id": "3.1",
                "title": "Ensure 'datadir' has appropriate permissions",
                "level": 1,
                "status": "ERROR",
                "detail": "Could not retrieve 'datadir' variable.",
                "remediation": "Verify MySQL server variables are readable.",
            }
        status, detail = _inspect_path_permissions(datadir, 0o750)
        return {
            "cis_id": "3.1",
            "title": "Ensure 'datadir' has appropriate permissions",
            "level": 1,
            "status": status,
            "detail": detail,
            "remediation": f"chmod 750 {datadir} && chown mysql:mysql {datadir}",
        }
    except Exception as exc:
        return {
            "cis_id": "3.1",
            "title": "Ensure 'datadir' has appropriate permissions",
            "level": 1,
            "status": "ERROR",
            "detail": f"Check failed: {exc}",
            "remediation": "Verify SHOW VARIABLES access.",
        }


def check_error_log_permissions(connector):
    """CIS 3.3: Ensure 'log_error' Has Appropriate Permissions."""
    try:
        rows = _run_query(connector, "SHOW VARIABLES LIKE 'log_error';")
        log_error = _to_str(rows[0][1]) if rows else ""
        if not log_error or log_error.lower() in ("stderr", "stdout"):
            return {
                "cis_id": "3.3",
                "title": "Ensure 'log_error' has appropriate permissions",
                "level": 1,
                "status": "PASS",
                "detail": f"Error logging directed to '{log_error or 'stderr'}' (no world-readable log file).",
                "remediation": "None required.",
            }
        status, detail = _inspect_path_permissions(log_error, 0o600)
        return {
            "cis_id": "3.3",
            "title": "Ensure 'log_error' has appropriate permissions",
            "level": 1,
            "status": status,
            "detail": detail,
            "remediation": f"chmod 600 {log_error} && chown mysql:mysql {log_error}",
        }
    except Exception as exc:
        return {
            "cis_id": "3.3",
            "title": "Ensure 'log_error' has appropriate permissions",
            "level": 1,
            "status": "ERROR",
            "detail": f"Check failed: {exc}",
            "remediation": "Verify SHOW VARIABLES access.",
        }


def run_checks(connector):
    return [
        check_datadir_permissions(connector),
        check_error_log_permissions(connector),
    ]