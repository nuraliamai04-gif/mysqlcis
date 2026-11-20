"""core/runner.py - runs every check module and writes a labelled LOCAL report.

Member 4 module. Combines: ConfigAudit + NetworkAudit (class based) and the
accounts / filesystem / drift modules (function based, expose run_checks()).
Nothing here talks to the network; results are written only to output_dir.
"""
import importlib
import json
import os
import re
from datetime import datetime

TOOL_VERSION = "1.0.0"
CLASS_CHECKS = [("checks.config", "ConfigAudit", "Config"),
                ("checks.network", "NetworkAudit", "Network")]
FUNCTION_CHECKS = [("checks.accounts", "Accounts"),
                   ("checks.filesystem", "File system"),
                   ("checks.drift", "Drift")]


class _QueryRecorder:
    """Wraps the connector so a query that fails is reported as ERROR
    instead of silently disappearing from the report."""

    def __init__(self, connector):
        self._connector = connector
        self.failures = []

    def query(self, sql, params=None):
        try:
            return self._connector.query(sql, params)
        except Exception as exc:  # Ctrl+C (KeyboardInterrupt) is NOT caught here
            self.failures.append((sql, str(exc)))
            raise

    def __getattr__(self, name):
        return getattr(self._connector, name)


def _result(rid, name, status, details, remediation="", level=""):
    return {"id": rid, "name": name, "status": status, "details": details,
            "remediation": remediation, "level": str(level)}


def _from_class_result(res):
    return _result(res.get("id", "?"), res.get("name", "?"), res.get("status", "ERROR"),
                   res.get("details", ""), res.get("remediation", ""), res.get("level", ""))


def _from_function_result(res):
    """Member 3 format: cis_id / title / detail  ->  common format."""
    cis_id = str(res.get("cis_id", "?"))
    rid = "CUSTOM-04" if cis_id.lower() == "custom" else f"CIS-{cis_id}"
    return _result(rid, res.get("title", "?"), res.get("status", "ERROR"),
                   res.get("detail", ""), res.get("remediation", ""), res.get("level", ""))


def _run_class_group(connector, module_name, class_name, label):
    recorder = _QueryRecorder(connector)
    try:
        module = importlib.import_module(module_name)
        found = getattr(module, class_name)(recorder).run()
    except Exception as exc:
        return [_result(f"{label.upper()}-ERR", f"{label} checks", "ERROR",
                        f"Module could not run: {type(exc).__name__}: {exc}")]
    results = [_from_class_result(r) for r in found]
    for sql, reason in recorder.failures:  # failed queries become visible ERRORs
        results.append(_result(f"{label.upper()}-ERR", f"{label} query failed", "ERROR",
                               f"{reason} | {sql.strip()[:70]}"))
    return results


def _run_function_group(connector, module_name, label):
    try:
        module = importlib.import_module(module_name)
        return [_from_function_result(r) for r in module.run_checks(connector)]
    except Exception as exc:
        return [_result(f"{label.upper()}-ERR", f"{label} checks", "ERROR",
                        f"Module could not run: {type(exc).__name__}: {exc}")]


def summarise(results):
    counts = {s: sum(r["status"] == s for r in results)
              for s in ("PASS", "FAIL", "ERROR", "SKIPPED")}
    graded = counts["PASS"] + counts["FAIL"]
    counts["compliance_pct"] = round(100 * counts["PASS"] / graded, 1) if graded else 0.0
    return counts


def _format_text(meta, results, summary):
    bar = "=" * 70
    lines = [bar, " MYSQL CIS BENCHMARK AUDIT REPORT  -  CONFIDENTIAL", bar,
             f" Target     : {meta['target']}", f" MySQL      : {meta['mysql_version']}",
             f" Scanned at : {meta['scanned_at']}",
             f" Tool       : mysqlcis v{TOOL_VERSION} (read-only, nothing was changed)",
             " Handling   : contains security findings - share only with the system owner", bar]
    for r in results:
        lines.append(f"[{r['status']:<7}] {r['id']:<10} {r['name']}")
        lines.append(f"            {r['details']}")
        if r["status"] == "FAIL" and r["remediation"]:
            lines.append(f"            Suggested fix (NOT executed): {r['remediation']}")
    lines += ["-" * 70,
              f"SUMMARY: PASS {summary['PASS']} | FAIL {summary['FAIL']} | "
              f"ERROR {summary['ERROR']} | SKIPPED {summary['SKIPPED']}",
              f"Compliance (PASS / (PASS+FAIL)): {summary['compliance_pct']}%", bar]
    return "\n".join(lines) + "\n"


def run(connector, output_dir):
    print("[+] Running MySQL CIS Benchmark audits (Config, Network, Accounts, File system, Drift)...")
    try:
        version = str(connector.query("SELECT VERSION()")[0][0])
    except Exception:
        version = "unknown"

    results = []
    for module_name, class_name, label in CLASS_CHECKS:
        results += _run_class_group(connector, module_name, class_name, label)
    for module_name, label in FUNCTION_CHECKS:
        results += _run_function_group(connector, module_name, label)

    summary = summarise(results)
    meta = {"target": f"{getattr(connector, 'host', '?')}:{getattr(connector, 'port', '?')}",
            "mysql_version": version,
            "scanned_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

    os.makedirs(output_dir, exist_ok=True)
    safe_host = re.sub(r"[^A-Za-z0-9_.-]", "_", str(getattr(connector, "host", "host")))
    stem = os.path.join(output_dir, f"mysqlcis_{safe_host}_{datetime.now():%Y%m%d_%H%M%S}")
    text = _format_text(meta, results, summary)
    with open(stem + ".txt", "w", encoding="utf-8") as fh:
        fh.write(text)
    with open(stem + ".json", "w", encoding="utf-8") as fh:
        json.dump({"meta": meta, "summary": summary, "results": results}, fh, indent=2)

    print()
    print(text)
    print(f"[+] Audit finished. Reports saved locally:\n    {stem}.txt\n    {stem}.json")
    print("[i] Suggested fixes are only suggestions - this tool never changes the server.")
    return 0
