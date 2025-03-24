from http.server import HTTPServer, SimpleHTTPRequestHandler
import os

PORT = 8000

class Handler(SimpleHTTPRequestHandler):
    def guess_type(self, path):
        if path.endswith('.exe'):
            return 'application/octet-stream'
        return super().guess_type(path)

# Create and start the server
print(f'Server running at http://localhost:{PORT}')
print(f'Access the phishing page at http://localhost:{PORT}/index.html')
httpd = HTTPServer(('', PORT), Handler)
try:
    httpd.serve_forever()
except KeyboardInterrupt:
    print('Server stopped')