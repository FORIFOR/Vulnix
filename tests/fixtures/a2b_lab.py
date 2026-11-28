"""A2B (app-to-backend) lab API on loopback: two organizations, three users, one admin.

Tokens (synthetic): tok-a = user A (org-a, member), tok-b = user B (org-a, admin),
tok-c = user C (org-b, member). Routes:
  GET /api/orgs/<org>/notes/<id>   a note (owner and org are fixed per note)
  GET /api/orgs/<org>/admin/export  organization export (admins of that org only)
mode "vulnerable": the backend checks only that the token is valid.
mode "patched":    it also checks the note's owner, the caller's organization and the role.
"""
import http.server
import json
import re

USERS = {"tok-a": ("user-a", "org-a", "member"), "tok-b": ("user-b", "org-a", "admin"),
         "tok-c": ("user-c", "org-b", "member")}
NOTES = {"note-a1": ("user-a", "org-a", "VULNIX_A2B_OWNER_A_DATA"),
         "note-b1": ("user-b", "org-a", "VULNIX_A2B_OWNER_B_DATA"),
         "note-c1": ("user-c", "org-b", "VULNIX_A2B_ORG_B_DATA")}


class A2BLab(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, mode: str):
        super().__init__(("127.0.0.1", 0), _Handler)
        self.mode = mode


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, status, obj):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        token = (self.headers.get("Authorization") or "").removeprefix("Bearer ").strip()
        user = USERS.get(token)
        if user is None:
            return self._send(401, {"error": "unauthenticated"})
        uid, org, role = user
        strict = self.server.mode == "patched"
        if m := re.fullmatch(r"/api/orgs/([a-z0-9-]+)/notes/([a-z0-9-]+)", self.path):
            path_org, nid = m.groups()
            note = NOTES.get(nid)
            if note is None or note[1] != path_org:
                return self._send(404, {"error": "not found"})
            if strict and (path_org != org or note[0] != uid):
                return self._send(403, {"error": "forbidden"})
            return self._send(200, {"id": nid, "body": note[2]})
        if m := re.fullmatch(r"/api/orgs/([a-z0-9-]+)/admin/export", self.path):
            if strict and (m.group(1) != org or role != "admin"):
                return self._send(403, {"error": "forbidden"})
            return self._send(200, {"export": f"VULNIX_A2B_EXPORT_{m.group(1)}"})
        return self._send(404, {"error": "not found"})
