"""Demo-only Qosmos gateway. Put the loopback listener behind HTTPS for remote access."""

import argparse
import getpass
import hashlib
import json
import os
import re
import secrets
import sqlite3
import sys
import uuid
from contextlib import closing
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Lock
from time import monotonic
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import HTTPRedirectHandler, Request, build_opener

VOX_API = "https://api.vox-vpn.com/partner/v1"
MAX_RESPONSE = 1_048_576
DEMO_DEVICE_LIMIT = 2
PROTOCOLS = ("vless", "wireguard", "amneziawg")
CATALOG_TTL = 45


class GatewayError(Exception):
    def __init__(self, status, code):
        super().__init__(code)
        self.status = status
        self.code = code


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Vox:
    def __init__(self, key, timeout=10):
        self.key = key
        self.timeout = timeout
        self.client = build_opener(NoRedirect())

    def request(self, path, payload=None):
        headers = {"Authorization": f"Bearer {self.key}", "Accept": "application/json"}
        if payload is not None:
            headers["Content-Type"] = "application/json"
        data = json.dumps(payload).encode() if payload is not None else None
        try:
            with self.client.open(Request(VOX_API + path, data, headers), timeout=self.timeout) as response:
                body = response.read(MAX_RESPONSE + 1)
                if len(body) > MAX_RESPONSE:
                    raise GatewayError(502, "vox_unavailable")
                return json.loads(body)
        except HTTPError as error:
            if error.code == 403:
                try:
                    detail = json.loads(error.read(4096)).get("detail")
                except (OSError, ValueError, AttributeError):
                    detail = None
                if detail == "account_suspended":
                    raise GatewayError(403, "account_inactive") from error
                if detail == "trial_device_limit":
                    raise GatewayError(403, "device_limit") from error
            if error.code in (404, 429, 503):
                raise GatewayError(503, "vox_unavailable") from error
            raise GatewayError(502, "vox_unavailable") from error
        except (OSError, URLError, ValueError) as error:
            raise GatewayError(502, "vox_unavailable") from error

    def require_demo(self):
        if self.request("/billing").get("demo") is not True:
            raise GatewayError(503, "demo_required")


class Gateway:
    def __init__(self, database, vox=None):
        self.database = database
        self.vox = vox
        self._catalog_lock = Lock()
        self._catalog = (float('-inf'), [])
        with closing(self.open_database()) as db, db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS accounts (
                    external_id TEXT PRIMARY KEY,
                    token_hash TEXT NOT NULL UNIQUE,
                    provisioned INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS account_profiles (
                    external_id TEXT PRIMARY KEY REFERENCES accounts(external_id),
                    email TEXT,
                    expires_at TEXT
                );
                CREATE TABLE IF NOT EXISTS devices (
                    external_id TEXT NOT NULL REFERENCES accounts(external_id),
                    device_id TEXT NOT NULL,
                    slot INTEGER NOT NULL CHECK (slot BETWEEN 1 AND 2),
                    PRIMARY KEY (external_id, device_id),
                    UNIQUE (external_id, slot)
                );
            """)

    def open_database(self):
        db = sqlite3.connect(self.database, timeout=5)
        db.execute("PRAGMA foreign_keys = ON")
        return db

    @staticmethod
    def digest(token):
        return hashlib.sha256(token.encode("ascii")).hexdigest()

    def issue(self, external_id):
        token = "qv_" + secrets.token_urlsafe(32)
        with closing(self.open_database()) as db, db:
            db.execute("INSERT INTO accounts (external_id, token_hash) VALUES (?, ?)",
                       (external_id, self.digest(token)))
        return token

    def update_profile(self, external_id, email, expires_at):
        with closing(self.open_database()) as db, db:
            if db.execute("SELECT 1 FROM accounts WHERE external_id = ?", (external_id,)).fetchone() is None:
                raise GatewayError(404, "account_not_found")
            db.execute("""
                INSERT INTO account_profiles (external_id, email, expires_at) VALUES (?, ?, ?)
                ON CONFLICT(external_id) DO UPDATE SET
                    email = COALESCE(excluded.email, account_profiles.email),
                    expires_at = COALESCE(excluded.expires_at, account_profiles.expires_at)
            """, (external_id, email, expires_at))

    def account(self, authorization):
        if not re.fullmatch(r"Bearer qv_[A-Za-z0-9_-]{43}", authorization):
            raise GatewayError(401, "invalid_activation")
        digest = self.digest(authorization.removeprefix("Bearer "))
        with closing(self.open_database()) as db:
            account = db.execute(
                "SELECT external_id, provisioned FROM accounts WHERE token_hash = ?", (digest,),
            ).fetchone()
        if account is None:
            raise GatewayError(401, "invalid_activation")
        return account

    def locations(self, country=None, protocol="vless"):
        filters = {}
        if protocol:
            filters["protocol"] = protocol
        if country:
            filters["country"] = country
        query = "?" + urlencode(filters) if filters else ""
        locations = self.vox.request("/locations" + query)["locations"]
        return [
            location for location in locations
            if (protocol is None or protocol in location["protocols"])
            and re.fullmatch(r"[A-Z]{2}", location["country"])
            and re.fullmatch(r"[a-z0-9-]{1,80}", location["id"])
            and (country is None or country == location["country"])
        ]

    def catalog(self):
        with self._catalog_lock:
            timestamp, locations = self._catalog
            if monotonic() - timestamp >= CATALOG_TTL:
                locations = self.locations(protocol=None)
                self._catalog = (monotonic(), locations)
            return locations

    def countries(self):
        self.vox.require_demo()
        catalog = {}
        for location in self.catalog():
            code = location["country"]
            name, protocols = catalog.setdefault(code, (location["country_name"], set()))
            protocols.update(protocol for protocol in PROTOCOLS if protocol in location["protocols"])
        countries = [
            {"code": code, "name": name, "protocols": [p for p in PROTOCOLS if p in protocols]}
            for code, (name, protocols) in sorted(catalog.items()) if protocols
        ]
        return {
            "countries": [country for country in countries if "vless" in country["protocols"]],
            "protocol_countries": countries,
        }

    def subscription(self, account):
        self.vox.require_demo()
        external_id, provisioned = account
        user = self.vox.request(f"/users/{quote(external_id, safe='')}")["user"] if provisioned else {}
        with closing(self.open_database()) as db:
            assigned, = db.execute(
                "SELECT COUNT(*) FROM devices WHERE external_id = ?", (external_id,),
            ).fetchone()
            profile = db.execute(
                "SELECT email, expires_at FROM account_profiles WHERE external_id = ?", (external_id,),
            ).fetchone()
        email, expires_at = profile or (None, None)
        registered = user.get("devices_used", 0)
        month_bytes = user.get("traffic_month", {}).get("total_bytes", 0)
        if type(registered) is not int or registered < 0 or type(month_bytes) is not int or month_bytes < 0:
            raise GatewayError(502, "vox_unavailable")
        return {
            "devices_used": max(registered, assigned),
            "device_limit": DEMO_DEVICE_LIMIT,
            "monthly_bytes": month_bytes,
            "email": email,
            "expires_at": expires_at,
            "subscription_status": user.get("status") if provisioned else "pending",
        }

    def slot(self, external_id, device_id):
        with closing(self.open_database()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            devices = dict(db.execute("SELECT device_id, slot FROM devices WHERE external_id = ?", (external_id,)))
            if device_id in devices:
                return devices[device_id]
            slot = next((n for n in range(1, DEMO_DEVICE_LIMIT + 1) if n not in devices.values()), None)
            if slot is None:
                raise GatewayError(403, "device_limit")
            db.execute("INSERT INTO devices VALUES (?, ?, ?)", (external_id, device_id, slot))
            return slot

    def config(self, account, data):
        try:
            country = data["country"]
            device_id = str(uuid.UUID(data["device_id"]))
            protocol = data.get("protocol", "vless")
            if protocol not in PROTOCOLS or not re.fullmatch(r"[A-Z]{2}", country):
                raise ValueError
        except (AttributeError, KeyError, TypeError, ValueError) as error:
            raise GatewayError(400, "invalid_request") from error

        self.vox.require_demo()
        locations = sorted(
            (loc for loc in self.catalog() if loc["country"] == country and protocol in loc["protocols"]),
            key=lambda loc: loc["id"],
        )
        if not locations:
            raise GatewayError(404, "country_unavailable")
        external_id, provisioned = account
        if not provisioned:
            result = self.vox.request("/users", {"external_id": external_id, "label": "Qosmos demo"})
            if result["user"]["status"] != "active":
                raise GatewayError(403, "account_inactive")
            with closing(self.open_database()) as db, db:
                db.execute("UPDATE accounts SET provisioned = 1 WHERE external_id = ?", (external_id,))

        slot = self.slot(external_id, device_id)
        path = f"/users/{quote(external_id, safe='')}/config?"
        candidates = locations[:2]
        for index, location in enumerate(candidates):
            query = urlencode({"protocol": protocol, "location": location["id"], "device": slot})
            try:
                result = self.vox.request(path + query)
            except GatewayError as error:
                if index + 1 == len(candidates) or error.status not in (502, 503):
                    raise
                continue
            config = result.get("config")
            if result.get("protocol") == protocol and isinstance(config, str) and len(config) <= 16384:
                if protocol == "vless" and config.startswith("vless://"):
                    return {"protocol": protocol, "link": config}
                if protocol != "vless" and config.lstrip().startswith("[Interface]"):
                    return {"protocol": protocol, "config": config}
        raise GatewayError(502, "invalid_profile")


class Handler(BaseHTTPRequestHandler):
    def send(self, status, value):
        body = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def dispatch(self):
        try:
            account = self.server.gateway.account(self.headers.get("Authorization", ""))
            if self.command == "GET" and self.path == "/v1/locations":
                result = self.server.gateway.countries()
            elif self.command == "GET" and self.path == "/v1/subscription":
                result = self.server.gateway.subscription(account)
            elif self.command == "POST" and self.path == "/v1/config":
                try:
                    size = int(self.headers.get("Content-Length", "0"))
                    if not 0 < size <= 4096:
                        raise ValueError
                    result_data = json.loads(self.rfile.read(size))
                except ValueError as error:
                    raise GatewayError(400, "invalid_request") from error
                result = self.server.gateway.config(account, result_data)
            else:
                raise GatewayError(404, "not_found")
        except GatewayError as error:
            self.send(error.status, {"error": error.code})
        except (KeyError, AttributeError, TypeError, sqlite3.Error):
            self.send(502, {"error": "vox_unavailable"})
        else:
            self.send(200, result)

    do_GET = dispatch
    do_POST = dispatch

    def setup(self):
        self.request.settimeout(15)
        super().setup()

    def log_message(self, *_):
        pass


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", required=True, help="Local SQLite path outside the repository")
    commands = parser.add_subparsers(dest="command", required=True)
    issue = commands.add_parser("issue")
    issue.add_argument("external_id", help="A test user ID starting with qosmos-demo-")
    profile = commands.add_parser("profile", help="Update subscriber details without changing the activation code")
    profile.add_argument("external_id")
    profile.add_argument("--email")
    profile.add_argument("--expires-at", help="ISO 8601 timestamp with a time zone")
    serve = commands.add_parser("serve")
    serve.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()

    if args.command == "issue":
        if not re.fullmatch(r"qosmos-demo-[A-Za-z0-9_.:@+-]{1,68}", args.external_id):
            parser.error("Use an external ID starting with qosmos-demo-.")
        try:
            print(Gateway(args.database).issue(args.external_id))
        except sqlite3.IntegrityError:
            sys.exit("This demo user already has an activation code.")
        return

    if args.command == "profile":
        if args.email is None and args.expires_at is None:
            parser.error("Specify --email or --expires-at.")
        if args.email is not None and (len(args.email) > 254 or not re.fullmatch(r"[^@\s]+@[^@\s]+", args.email)):
            parser.error("Use a valid email address.")
        expires = None
        if args.expires_at is not None:
            try:
                instant = datetime.fromisoformat(args.expires_at.removesuffix("Z") + (
                    "+00:00" if args.expires_at.endswith("Z") else ""
                ))
                if instant.utcoffset() is None:
                    raise ValueError
                expires = instant.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
            except ValueError:
                parser.error("Use an ISO 8601 expiration timestamp with a time zone.")
        try:
            Gateway(args.database).update_profile(args.external_id, args.email, expires)
        except GatewayError:
            sys.exit("Demo subscriber not found.")
        return

    key = os.environ.get("QOSMOS_VOX_DEMO_KEY") or getpass.getpass("Vox demo key: ")
    key = key.strip()
    if not key.startswith("vxk_"):
        sys.exit("A Vox demo key beginning with vxk_ is required.")
    vox = Vox(key)
    try:
        vox.require_demo()
    except GatewayError as error:
        sys.exit(f"Demo gateway could not start: {error.code}")

    with ThreadingHTTPServer(("127.0.0.1", args.port), Handler) as server:
        server.gateway = Gateway(args.database, vox)
        print(f"Qosmos demo gateway listening on 127.0.0.1:{server.server_port}", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
