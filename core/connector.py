"""Safe MySQL connector.

Safety goals:
  * connection timeout so the tool never hangs
  * friendly errors instead of raw tracebacks
  * READ-ONLY: only SELECT / SHOW queries are allowed
  * the password is never stored in an attribute, logged or printed
"""
import re

import pymysql

CONNECT_TIMEOUT = 5  # seconds

# Only queries that start with one of these words may run (audit = look, never change).
_READ_ONLY = re.compile(r"^\s*(select|show|describe|desc)\b", re.IGNORECASE)


class ConnectionFailed(Exception):
    """Friendly, user-facing connection error."""


class ReadOnlyViolation(Exception):
    """Raised if something tries to run a non-read query."""


class MySQLConnector:
    def __init__(self, host="127.0.0.1", port=3306, user="root"):
        self.host, self.port, self.user = host, port, user
        self._conn = None

    def connect(self, password):
        """Open the connection. Password is passed in, used once, not kept."""
        try:
            self._conn = pymysql.connect(
                host=self.host,
                port=self.port,
                user=self.user,
                password=password,
                connect_timeout=CONNECT_TIMEOUT,
                read_timeout=CONNECT_TIMEOUT * 2,
                autocommit=True,
            )
        except pymysql.err.OperationalError as exc:
            code = exc.args[0] if exc.args else 0
            if code == 1045:
                msg = "Access denied: wrong username or password."
            elif code in (2003, 2002, 2005):
                msg = ("Cannot reach MySQL at %s:%s. Is the server running and the "
                       "port correct?" % (self.host, self.port))
            else:
                msg = "MySQL connection error (code %s)." % code
            raise ConnectionFailed(msg) from None
        except Exception:
            raise ConnectionFailed("Unexpected error while connecting to MySQL.") from None

    def query(self, sql, params=None):
        """Run a read-only query and return a list of rows (tuples)."""
        if not _READ_ONLY.match(sql):
            raise ReadOnlyViolation("Blocked non-read-only query: %s" % sql.split()[0])
        if self._conn is None:
            raise ConnectionFailed("Not connected.")
        try:
            with self._conn.cursor() as cur:
                cur.execute(sql, params)
                return list(cur.fetchall())
        except pymysql.err.MySQLError as exc:
            raise ConnectionFailed("Query failed (code %s)." % (exc.args[0] if exc.args else "?")) from None

    def close(self):
        """Close cleanly. Safe to call more than once (used by the kill switch)."""
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None
