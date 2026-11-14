"""Internal API of the lab. Standard library only.

It does no TLS itself. It trusts two headers that nginx sets after checking the client certificate:
  X-Client-Verify  SUCCESS when nginx verified the certificate
  X-Client-DN      the certificate's subject, for example CN=alice,O=EPITA Lab
The CN is the user name. Whoever can reach this port directly can send these headers too.

Every request is logged: who called (address), the two headers, the user and role read from them,
and the answer. Watch it with:  docker compose logs -f api
"""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROLES = {"alice": "admin", "bob": "user", "billing": "service"}
ALLOWED = {
    "/whoami": {"admin", "user", "service"},
    "/admin": {"admin"},
    "/invoices": {"service"},
}


def caller(headers):
    """The CN of the verified client certificate, or None."""
    if headers.get("X-Client-Verify") != "SUCCESS":
        return None
    for part in headers.get("X-Client-DN", "").split(","):
        key, _, value = part.strip().partition("=")
        if key == "CN":
            return value
    return None


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # replaced by the one line per request written in do_GET

    def reply(self, status, body):
        data = (json.dumps(body) + "\n").encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = self.path.split("?")[0]
        verify = self.headers.get("X-Client-Verify")
        dn = self.headers.get("X-Client-DN")
        user = caller(self.headers)
        role = ROLES.get(user)

        if path not in ALLOWED:
            status, body = 404, {"error": "unknown path"}
        elif user is None:
            status, body = 401, {"error": "no verified client certificate"}
        elif role not in ALLOWED[path]:
            status, body = 403, {"error": "forbidden", "user": user, "role": role}
        else:
            status, body = 200, {"user": user, "role": role, "path": path}

        print(f"from={self.client_address[0]} GET {path} "
              f"X-Client-Verify={verify!r} X-Client-DN={dn!r} -> user={user} role={role} -> {status}")
        self.reply(status, body)


if __name__ == "__main__":
    print("api listening on :8080")
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
