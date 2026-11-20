"""
checks/accounts.py
Audits MySQL user accounts and privileges against CIS MySQL 8.0 Benchmark v1.5.0.
Uses strictly read-only SELECT queries.
"""

SYSTEM_USERS = ("'mysql.sys'", "'mysql.session'", "'mysql.infoschema'")


def _to_str(val):
    if isinstance(val, (bytes, bytearray)):
        return val.decode("utf-8", errors="replace")
    return "" if val is None else str(val)


def _run_query(connector, query):
    """Supports either a custom connector wrapper or a standard DB-API connection."""
    if hasattr(connector, "query"):
        return connector.query(query)
    if hasattr(connector, "execute"):
        return connector.execute(query)
    cursor = connector.cursor()
    cursor.execute(query)
    rows = cursor.fetchall()
    cursor.close()
    return rows


def check_admin_privileges(connector):
    """CIS 5.1: Ensure Only Administrative Users Have Full Database Access."""
    query = (
        "SELECT user, host FROM mysql.user "
        "WHERE (Super_priv = 'Y' OR Grant_priv = 'Y') "
        f"AND user NOT IN ('root', {', '.join(SYSTEM_USERS)});"
    )
    try:
        rows = _run_query(connector, query)
        if rows:
            offenders = ", ".join(f"'{_to_str(r[0])}'@'{_to_str(r[1])}'" for r in rows)
            return {
                "cis_id": "5.1",
                "title": "Only administrative users have full database access",
                "level": 1,
                "status": "FAIL",
                "detail": f"Non-root users with SUPER/GRANT privileges: {offenders}",
                "remediation": "REVOKE ALL PRIVILEGES, GRANT OPTION FROM <user>@<host>;",
            }
        return {
            "cis_id": "5.1",
            "title": "Only administrative users have full database access",
            "level": 1,
            "status": "PASS",
            "detail": "Only root/system accounts hold SUPER or GRANT privileges.",
            "remediation": "None required.",
        }
    except Exception as exc:
        return {
            "cis_id": "5.1",
            "title": "Only administrative users have full database access",
            "level": 1,
            "status": "ERROR",
            "detail": f"Query failed: {exc}",
            "remediation": "Verify audit user has SELECT access to mysql.user.",
        }


def check_empty_passwords(connector):
    """CIS 7.3: Ensure Passwords Are Set for All MySQL Accounts."""
    query = (
        "SELECT user, host FROM mysql.user "
        "WHERE authentication_string = '' AND account_locked = 'N' "
        f"AND user NOT IN ({', '.join(SYSTEM_USERS)});"
    )
    try:
        rows = _run_query(connector, query)
        if rows:
            offenders = ", ".join(f"'{_to_str(r[0])}'@'{_to_str(r[1])}'" for r in rows)
            return {
                "cis_id": "7.3",
                "title": "Ensure passwords are set for all MySQL accounts",
                "level": 1,
                "status": "FAIL",
                "detail": f"Unlocked accounts without passwords: {offenders}",
                "remediation": "ALTER USER <user>@<host> IDENTIFIED BY '<strong_password>';",
            }
        return {
            "cis_id": "7.3",
            "title": "Ensure passwords are set for all MySQL accounts",
            "level": 1,
            "status": "PASS",
            "detail": "All unlocked user accounts have passwords configured.",
            "remediation": "None required.",
        }
    except Exception as exc:
        return {
            "cis_id": "7.3",
            "title": "Ensure passwords are set for all MySQL accounts",
            "level": 1,
            "status": "ERROR",
            "detail": f"Query failed: {exc}",
            "remediation": "Verify audit user has SELECT access to mysql.user.",
        }


def check_wildcard_hosts(connector):
    """CIS 7.6: Ensure No Users Have Wildcard Hostnames."""
    query = (
        "SELECT user, host FROM mysql.user "
        f"WHERE host = '%' AND user NOT IN ({', '.join(SYSTEM_USERS)});"
    )
    try:
        rows = _run_query(connector, query)
        if rows:
            offenders = ", ".join(f"'{_to_str(r[0])}'@'{_to_str(r[1])}'" for r in rows)
            return {
                "cis_id": "7.6",
                "title": "Ensure no users have wildcard hostnames",
                "level": 1,
                "status": "FAIL",
                "detail": f"Accounts allowing connections from any host ('%'): {offenders}",
                "remediation": "Restrict host to specific IPs or 'localhost' and DROP '%' accounts.",
            }
        return {
            "cis_id": "7.6",
            "title": "Ensure no users have wildcard hostnames",
            "level": 1,
            "status": "PASS",
            "detail": "No accounts use wildcard '%' host bindings.",
            "remediation": "None required.",
        }
    except Exception as exc:
        return {
            "cis_id": "7.6",
            "title": "Ensure no users have wildcard hostnames",
            "level": 1,
            "status": "ERROR",
            "detail": f"Query failed: {exc}",
            "remediation": "Verify audit user has SELECT access to mysql.user.",
        }


def check_anonymous_users(connector):
    """CIS 7.7: Ensure No Anonymous Accounts Exist."""
    query = "SELECT user, host FROM mysql.user WHERE user = '';"
    try:
        rows = _run_query(connector, query)
        if rows:
            offenders = ", ".join(f"''@'{_to_str(r[1])}'" for r in rows)
            return {
                "cis_id": "7.7",
                "title": "Ensure no anonymous accounts exist",
                "level": 1,
                "status": "FAIL",
                "detail": f"Anonymous user accounts detected: {offenders}",
                "remediation": "DROP USER ''@'localhost';",
            }
        return {
            "cis_id": "7.7",
            "title": "Ensure no anonymous accounts exist",
            "level": 1,
            "status": "PASS",
            "detail": "No anonymous user accounts exist.",
            "remediation": "None required.",
        }
    except Exception as exc:
        return {
            "cis_id": "7.7",
            "title": "Ensure no anonymous accounts exist",
            "level": 1,
            "status": "ERROR",
            "detail": f"Query failed: {exc}",
            "remediation": "Verify audit user has SELECT access to mysql.user.",
        }


def run_checks(connector):
    return [
        check_admin_privileges(connector),
        check_empty_passwords(connector),
        check_wildcard_hosts(connector),
        check_anonymous_users(connector),
    ]