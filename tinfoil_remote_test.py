import json
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

HOST_IP = "192.168.10.146"
PORT = 8090

url = input("Paste AllDebrid direct URL: ").strip()

class H(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path not in ("/", "/index.tfl"):
            self.send_error(404)
            return

        data = json.dumps({
            "files": [url],
            "directories": [],
            "success": "AllDebrid direct URL test"
        }).encode()

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

        print("Tinfoil fetched index", flush=True)

print(f"Open in Tinfoil: http://{HOST_IP}:{PORT}/index.tfl")
ThreadingHTTPServer(("0.0.0.0", PORT), H).serve_forever()
