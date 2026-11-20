from checks.base import BaseCheck

class ConfigAudit(BaseCheck):
    def run(self):
        results = []
        
        # 1. CIS Benchmark: Check secure_file_priv
        res_sfp = self.execute_query("SHOW GLOBAL VARIABLES LIKE 'secure_file_priv';")
        if isinstance(res_sfp, list) and res_sfp:
            val = res_sfp[0][1] if len(res_sfp[0]) > 1 else None
            # CIS 4.8: a folder path is good, NULL (import/export disabled) is best, empty is FAIL
            status = "FAIL" if val == "" else "PASS"
            results.append({
                "id": "CIS-4.8",
                "name": "Secure File Priv Check",
                "status": status,
                "details": f"secure_file_priv is set to: {'NULL (disabled)' if val is None else repr(val)}",
                "remediation": "Set secure_file_priv=/var/lib/mysql-files in my.cnf and restart MySQL."
            })

        # 2. CIS Benchmark: Check local_infile
        res_li = self.execute_query("SHOW GLOBAL VARIABLES LIKE 'local_infile';")
        if isinstance(res_li, list) and res_li:
            val = res_li[0][1].upper() if len(res_li[0]) > 1 else ""
            status = "PASS" if val == "OFF" else "FAIL"
            results.append({
                "id": "CIS-4.4",
                "name": "Local Infile Disabled Check",
                "status": status,
                "details": f"local_infile is currently: {val} (Recommended: OFF)",
                "remediation": "SET PERSIST local_infile = OFF;"
            })

        # 3. Custom Check: Strict SQL Mode Enforcement
        res_sql = self.execute_query("SHOW GLOBAL VARIABLES LIKE 'sql_mode';")
        if isinstance(res_sql, list) and res_sql:
            val = res_sql[0][1] if len(res_sql[0]) > 1 else ""
            is_strict = "STRICT_TRANS_TABLES" in val or "STRICT_ALL_TABLES" in val
            results.append({
                "id": "CUSTOM-01",
                "name": "Strict SQL Mode Enforcement",
                "status": "PASS" if is_strict else "FAIL",
                "details": f"sql_mode contains: {val}",
                "remediation": "SET PERSIST sql_mode = CONCAT(@@sql_mode, ',STRICT_ALL_TABLES');"
            })

        # 4. Custom Check: Max Connections Limit Check
        res_conn = self.execute_query("SHOW GLOBAL VARIABLES LIKE 'max_connections';")
        if isinstance(res_conn, list) and res_conn:
            val = int(res_conn[0][1]) if len(res_conn[0]) > 1 and res_conn[0][1].isdigit() else 151
            status = "PASS" if val <= 500 else "FAIL" 
            results.append({
                "id": "CUSTOM-03",
                "name": "Max Connections Threshold Check",
                "status": status,
                "details": f"max_connections is set to: {val}",
                "remediation": "SET PERSIST max_connections = 500;"
            })

        return results