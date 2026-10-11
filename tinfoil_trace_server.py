#!/usr/bin/env python3

import os
import re
import sys
import json
import time
import threading
from urllib.parse import quote, unquote, urlparse
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

FILE = os.path.abspath(sys.argv[1])
NAME = os.path.basename(FILE)
PORT = 8090
HOST_IP = "192.168.10.146"
SIZE = os.path.getsize(FILE)

lock = threading.Lock()
active = 0
request_id = 0

def log(s):
    print(s, flush=True)

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def do_HEAD(self):
        self.handle_request(False)

    def do_GET(self):
        self.handle_request(True)

    def handle_request(self, body):
        path = unquote(urlparse(self.path).path)

        log(
            f"[REQ] {self.command} {self.path} "
            f"Range={self.headers.get('Range')!r} "
            f"UA={self.headers.get('User-Agent')!r}"
        )

        # Tinfoil custom index
        if path in ("/", "/index.tfl"):
            file_url = (
                f"http://{HOST_IP}:{PORT}/"
                + quote(NAME)
            )

            data = json.dumps({
                "files": [
                    {
                        "url": file_url,
                        "size": SIZE
                    }
                ],
                "directories": []
            }).encode()

            self.send_response(200)
            self.send_header(
                "Content-Type",
                "application/json"
            )
            self.send_header(
                "Content-Length",
                str(len(data))
            )
            self.end_headers()

            if body:
                self.wfile.write(data)
            return

        if path != "/" + NAME:
            self.send_error(404)
            return

        self.serve_file(body)

    def serve_file(self, body):
        global active, request_id

        with lock:
            request_id += 1
            rid = request_id
            active += 1
            now_active = active

        started = time.monotonic()
        range_header = self.headers.get("Range")

        start = 0
        end = SIZE - 1
        status = 200

        if range_header:
            m = re.match(
                r"bytes=(\d*)-(\d*)",
                range_header
            )

            if not m:
                self.send_error(416)
                return

            a, b = m.groups()

            if a:
                start = int(a)
                if b:
                    end = min(int(b), SIZE - 1)
            elif b:
                count = int(b)
                start = max(0, SIZE - count)

            status = 206

        length = end - start + 1

        log(
            f"[START #{rid}] "
            f"active={now_active} "
            f"range={range_header!r} "
            f"start={start} end={end} "
            f"length={length}"
        )

        self.send_response(status)
        self.send_header(
            "Content-Type",
            "application/octet-stream"
        )
        self.send_header(
            "Accept-Ranges",
            "bytes"
        )
        self.send_header(
            "Content-Length",
            str(length)
        )

        if status == 206:
            self.send_header(
                "Content-Range",
                f"bytes {start}-{end}/{SIZE}"
            )

        self.end_headers()

        sent = 0

        try:
            if body:
                with open(FILE, "rb") as f:
                    f.seek(start)
                    remain = length

                    while remain > 0:
                        data = f.read(
                            min(1024 * 1024, remain)
                        )

                        if not data:
                            break

                        self.wfile.write(data)
                        sent += len(data)
                        remain -= len(data)

        except (
            BrokenPipeError,
            ConnectionResetError
        ):
            pass

        elapsed = max(
            time.monotonic() - started,
            0.000001
        )

        with lock:
            active -= 1
            now_active = active

        log(
            f"[END   #{rid}] "
            f"bytes={sent} "
            f"time={elapsed:.3f}s "
            f"speed={sent / 1048576 / elapsed:.2f} MiB/s "
            f"active_now={now_active}"
        )

server = ThreadingHTTPServer(
    ("0.0.0.0", PORT),
    Handler
)

print(f"Index:")
print(f"  http://{HOST_IP}:{PORT}/index.tfl")
print()
print(f"File:")
print(f"  {NAME}")
print()
print("Waiting for Tinfoil...")

server.serve_forever()
