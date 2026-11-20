from checks.base import BaseCheck

class NetworkAudit(BaseCheck):
    def run(self):
        results = []

        # 1. CIS Benchmark: Require Secure Transport (TLS)
        res_rst = self.execute_query("SHOW GLOBAL VARIABLES LIKE 'require_secure_transport';")
        if isinstance(res_rst, list) and res_rst:
            val = res_rst[0][1].upper() if len(res_rst[0]) > 1 else ""
            status = "PASS" if val == "ON" else "FAIL"
            results.append({
                "id": "CIS-8.1",
                "name": "Require Secure Transport Check",
                "status": status,
                "details": f"require_secure_transport is: {val}",
                "remediation": "SET PERSIST require_secure_transport = ON;"
            })

        # 2. Custom Check: Outdated TLS Protocols
        res_tls = self.execute_query("SHOW GLOBAL VARIABLES LIKE 'tls_version';")
        if isinstance(res_tls, list) and res_tls:
            val = res_tls[0][1] if len(res_tls[0]) > 1 else ""
            # compare each protocol exactly ("TLSv1" is a substring of "TLSv1.2")
            protocols = [p.strip() for p in val.split(",")]
            has_old_tls = "TLSv1" in protocols or "TLSv1.1" in protocols
            status = "FAIL" if has_old_tls else "PASS"
            results.append({
                "id": "CIS-2.15",
                "name": "Outdated TLS Protocols Check",
                "status": status,
                "details": f"Active TLS versions: {val}",
                "remediation": "SET PERSIST tls_version = 'TLSv1.2,TLSv1.3';"
            })

        return results