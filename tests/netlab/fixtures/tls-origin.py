#!/usr/bin/env python3
import http.server
import ssl
import sys
import threading


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = f"shakerproxy-netlab-origin:{self.server.server_port}\n".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        return


def serve(port, certificate, key):
    server = http.server.ThreadingHTTPServer(("10.61.0.2", port), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if len(sys.argv) != 5:
    raise SystemExit("usage: tls-origin.py trusted-cert trusted-key untrusted-cert untrusted-key")

threads = [
    threading.Thread(target=serve, args=(443, sys.argv[1], sys.argv[2]), daemon=True),
    threading.Thread(target=serve, args=(8443, sys.argv[1], sys.argv[2]), daemon=True),
    threading.Thread(target=serve, args=(9443, sys.argv[3], sys.argv[4]), daemon=True),
]
for thread in threads:
    thread.start()
threads[0].join()
