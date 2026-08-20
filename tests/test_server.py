import io
import json
import tempfile
import unittest
from pathlib import Path

import server


class ServerRelayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        server.DB_PATH = root / "mytail.db"
        server.RELAY_AUTHORIZED_KEYS = str(root / "relay" / "authorized_keys")
        server.OPERATOR_KNOWN_HOSTS = str(root / "operator" / "known_hosts")
        server.RELAY_KNOWN_HOSTS = "[relay.example]:22 ssh-ed25519 " + "A" * 68
        server.RELAY_HOST = "relay.example"
        server.OPERATOR_SSH_PUBLIC_KEY = "ssh-ed25519 " + "B" * 68 + " operator"
        server.init_db()
        conn = server.db()
        conn.execute(
            """insert into machines
               (customer_name,machine_name,machine_token,consent_code,notes,created_at,relay_port)
               values (?,?,?,?,?,?,?)""",
            ("Customer", "Device", "machine-token-1234567890", "ABC123", "", server.now_ts(), 22001),
        )
        conn.commit()
        conn.close()

    def tearDown(self):
        self.temp.cleanup()

    def call(self, path, payload):
        body = json.dumps(payload).encode()
        captured = {}
        environ = {
            "PATH_INFO": path,
            "REQUEST_METHOD": "POST",
            "CONTENT_LENGTH": str(len(body)),
            "wsgi.input": io.BytesIO(body),
            "REMOTE_ADDR": "127.0.0.1",
        }

        def start(status, headers):
            captured["status"] = status
            captured["headers"] = headers

        response = b"".join(server.application(environ, start))
        return captured["status"], json.loads(response)

    def test_device_key_registration_and_connectivity_contract(self):
        key = "ssh-ed25519 " + "C" * 68 + " device"
        status, payload = self.call(
            "/api/agent/checkin",
            {
                "machine_token": "machine-token-1234567890",
                "hostname": "device-1",
                "ssh_public_key": key,
                "local_ssh_host_key": "ssh-ed25519 " + "E" * 68 + " local-host",
                "remote_user": "admin",
                "platform": "linux/amd64",
            },
        )
        self.assertEqual(status, "200 OK")
        self.assertIsNone(payload["active_request"])
        authorized = Path(server.RELAY_AUTHORIZED_KEYS).read_text()
        self.assertIn('permitlisten="127.0.0.1:22001"', authorized)
        self.assertIn("mytail-machine-1", authorized)
        known_hosts = Path(server.OPERATOR_KNOWN_HOSTS).read_text()
        self.assertIn("mytail-machine-1 ssh-ed25519", known_hosts)

        status, payload = self.call(
            "/api/agent/connectivity", {"machine_token": "machine-token-1234567890"}
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(payload["control_plane"], "ok")
        self.assertEqual(payload["relay"]["remote_port"], 22001)

    def test_active_request_exposes_operator_key_only_when_approved(self):
        conn = server.db()
        machine_id = conn.execute("select id from machines").fetchone()[0]
        conn.execute(
            """insert into access_requests
               (machine_id,operator_email,reason,requested_minutes,status,consent_token,
                created_at,responded_at,approved_minutes,expires_at,requested_by_ip)
               values (?,?,?,?,?,?,?,?,?,?,?)""",
            (machine_id, "operator@example.com", "Diagnostics", 15, "approved", "consent", server.now_ts(), server.now_ts(), 15, server.now_ts()+900, "127.0.0.1"),
        )
        conn.commit()
        conn.close()
        status, payload = self.call(
            "/api/agent/checkin",
            {
                "machine_token": "machine-token-1234567890",
                "hostname": "device-1",
                "ssh_public_key": "ssh-ed25519 " + "D" * 68,
                "local_ssh_host_key": "ssh-ed25519 " + "E" * 68,
                "remote_user": "admin",
                "platform": "linux/amd64",
            },
        )
        self.assertEqual(status, "200 OK")
        active = payload["active_request"]
        self.assertEqual(active["operator_ssh_public_key"], server.OPERATOR_SSH_PUBLIC_KEY)
        self.assertEqual(active["relay"]["remote_port"], 22001)


if __name__ == "__main__":
    unittest.main()
