"""Loopback production listener admission and recovery."""
import http.client
import threading
import unittest
from http.server import BaseHTTPRequestHandler

from aegis.server import ControlPlaneHTTPServer, SSE_PLATFORM


class TestControlPlaneCapacity(unittest.TestCase):
    def test_production_backlog_and_slots_are_bounded(self):
        self.assertGreaterEqual(ControlPlaneHTTPServer.request_queue_size, 32)
        self.assertGreater(ControlPlaneHTTPServer.connection_limit, SSE_PLATFORM)
        self.assertLessEqual(ControlPlaneHTTPServer.connection_limit, 512)
        self.assertGreater(ControlPlaneHTTPServer.timeout_per_connection, 0)

    def test_overload_returns_retry_and_recovers_after_connection_closes(self):
        entered = threading.Event()
        released = threading.Event()
        finished = threading.Event()

        class OneSlot(ControlPlaneHTTPServer):
            connection_limit = 1

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                entered.set()
                released.wait(3)
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *_args):
                pass

        class Observed(OneSlot):
            def process_request_thread(self, request, address):
                try:
                    super().process_request_thread(request, address)
                finally:
                    finished.set()

        with Observed(("127.0.0.1", 0), Handler) as server:
            runner = threading.Thread(target=server.serve_forever, daemon=True)
            runner.start()
            first = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=4)
            next_request = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=4)
            try:
                first.request("GET", "/")
                self.assertTrue(entered.wait(2))
                next_request.request("GET", "/")
                result = next_request.getresponse()
                self.assertEqual(result.status, 503)
                self.assertEqual(result.getheader("Retry-After"), "2")
                result.read()
                released.set()
                self.assertEqual(first.getresponse().status, 200)
                first.close()
                self.assertTrue(finished.wait(2))
                next_request.request("GET", "/")
                self.assertEqual(next_request.getresponse().status, 200)
            finally:
                released.set()
                first.close()
                next_request.close()
                server.shutdown()
                runner.join()
