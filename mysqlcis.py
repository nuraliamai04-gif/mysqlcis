#!/usr/bin/env python3
"""mysqlcis - CIS Benchmark Checker for MySQL (read-only auditing tool).

Entry point. Order of operations (this order is the safety design):
  1. parse arguments
  2. show legal banner + require explicit confirmation
  3. enforce scope  (BEFORE any network connection)
  4. dry-run? -> print the plan and stop
  5. connect (read-only) and run the audit
  6. Ctrl+C at any time -> clean abort (kill switch)
"""
import argparse
import getpass
import os
import sys

from core.connector import ConnectionFailed, MySQLConnector
from core.scope import ScopeError, enforce_scope

VERSION = "1.0.0"

BANNER = r"""
==============================================================================
  mysqlcis v{ver} - CIS Benchmark Checker for MySQL
==============================================================================
  LEGAL DISCLAIMER
  Unauthorised access to computer systems is a criminal offence under the
  Computer Crimes Act 1997 (Malaysia). Use this tool ONLY on systems you own
  or have EXPLICIT WRITTEN permission to audit.

  - Auditing only: the tool runs read-only queries and changes nothing.
  - Results are saved locally in the output directory. Nothing is uploaded.
  - Press Ctrl+C at any time to abort immediately (kill switch).
  The authors accept no liability for misuse.
==============================================================================
""".format(ver=VERSION)

EPILOG = """examples:
  %(prog)s --dry-run                       show what would happen, no connection
  %(prog)s                                 audit localhost (127.0.0.1:3306) as root
  %(prog)s --user auditor --port 3307      audit local MySQL on another port
  %(prog)s --host 192.168.56.10 --scope 192.168.56.0/24
                                           audit a lab host (written authorisation required)

scope rules:
  Default targets: localhost, 127.0.0.1, example.com and test ranges.
  Anything else is refused unless you list it with --scope (IP, CIDR or hostname).

password:
  You will be prompted (hidden). Or set the MYSQLCIS_PASSWORD environment variable.
  There is deliberately no --password flag: it would leak into shell history.
"""


def build_parser():
    p = argparse.ArgumentParser(
        prog="mysqlcis.py",
        description="Audit a MySQL server against CIS Benchmark controls (read-only).",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--host", default="127.0.0.1", help="target host (default: 127.0.0.1)")
    p.add_argument("--port", type=int, default=3306, help="MySQL port (default: 3306)")
    p.add_argument("--user", default="root", help="MySQL user (default: root)")
    p.add_argument("--scope", action="append", metavar="TARGET",
                   help="authorised target: IP, CIDR or hostname. Repeatable. "
                        "Needed for any non-default host.")
    p.add_argument("--output", default="output",
                   help="local directory for results (default: ./output)")
    p.add_argument("--dry-run", action="store_true",
                   help="show the plan and exit WITHOUT connecting to anything")
    p.add_argument("--version", action="version", version="mysqlcis " + VERSION)
    return p


def confirm_authorisation():
    """Make the user type an explicit confirmation. Anything else aborts."""
    print(BANNER)
    answer = input("Do you have authorisation to audit this target? Type 'yes' to continue: ")
    return answer.strip().lower() == "yes"


def print_plan(args):
    print("\n[DRY RUN] No connection will be made. Plan:")
    print("  target      : %s:%s" % (args.host, args.port))
    print("  user        : %s" % args.user)
    print("  extra scope : %s" % (", ".join(args.scope) if args.scope else "none (defaults only)"))
    print("  output dir  : %s" % args.output)
    print("  actions     : connect (read-only) -> run CIS checks -> write report locally")


def run_audit(connector, output_dir):
    """Hand over to the team's runner. Falls back to a simple connection test
    so the CLI still works while the other modules are being finished."""
    try:
        from core.runner import run  # Member 4's module
    except ImportError:
        version = connector.query("SELECT VERSION()")[0][0]
        print("[+] Connected. MySQL version: %s" % version)
        print("[!] core/runner.py not found yet - no CIS checks were run.")
        return 0
    return run(connector, output_dir)


def main(argv=None):
    args = build_parser().parse_args(argv)
    connector = MySQLConnector(args.host, args.port, args.user)
    try:
        # 1. Legal confirmation first
        if not confirm_authorisation():
            print("\n[-] Authorisation not confirmed. Exiting. Nothing was scanned.")
            return 1

        # 2. Scope check BEFORE any network activity
        try:
            enforce_scope(args.host, args.scope)
        except ScopeError as exc:
            print("\n[-] REFUSED: %s" % exc)
            return 2
        print("\n[+] Target %s is in scope." % args.host)

        # 3. Dry run stops here
        if args.dry_run:
            print_plan(args)
            return 0

        # 4. Password: env var or hidden prompt (never a CLI flag)
        password = os.environ.get("MYSQLCIS_PASSWORD")
        if password is None:
            password = getpass.getpass("MySQL password for %s@%s: " % (args.user, args.host))

        connector.connect(password)
        del password
        return run_audit(connector, args.output)

    except ConnectionFailed as exc:
        print("\n[-] %s" % exc)
        return 3
    except KeyboardInterrupt:  # kill switch
        print("\n[!] Scan aborted by user (Ctrl+C). Closing connection...")
        return 130
    finally:
        connector.close()  # always runs: clean shutdown on success, error or abort


if __name__ == "__main__":
    sys.exit(main())
