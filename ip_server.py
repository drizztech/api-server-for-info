import http.server
import socketserver
import socket

# Get the IP address of the device
def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    except:
        ip = 'Unable to determine IP'
    finally:
        s.close()
    return ip

ip_address = get_ip()

class IPHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        html = f"""
        <html>
        <head><title>Device IP</title></head>
        <body>
        <h1>Connected Device IP Address: {ip_address}</h1>
        </body>
        </html>
        """
        self.wfile.write(html.encode())

if __name__ == '__main__':
    with socketserver.TCPServer(('', 3333), IPHandler) as httpd:
        print(f"Server running on port 3333. IP: {ip_address}")
        httpd.serve_forever()