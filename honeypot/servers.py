"""Servidores falsos (SSH e HTTP) que registram tentativas de acesso.

Importante: são serviços de baixa interação — apenas capturam credenciais/
requisições e respondem de forma convincente, sem nunca conceder acesso real.
"""

from __future__ import annotations

import socket
import threading

from .store import EventStore

# Banner SSH falso convincente (não é um servidor SSH real).
SSH_BANNER = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n"

HTTP_RESPONSE = (
    "HTTP/1.1 401 Unauthorized\r\n"
    "Server: nginx/1.24.0\r\n"
    "WWW-Authenticate: Basic realm=\"Admin\"\r\n"
    "Content-Type: text/html\r\n"
    "Content-Length: 54\r\n"
    "Connection: close\r\n\r\n"
    "<html><body><h1>401 Unauthorized</h1></body></html>"
)


def _recv_line(sock: socket.socket, limit: int = 4096) -> str:
    try:
        return sock.recv(limit).decode("latin-1", "ignore")
    except OSError:
        return ""


def handle_ssh(sock: socket.socket, addr, store: EventStore) -> None:
    ip, port = addr[0], addr[1]
    try:
        sock.sendall(SSH_BANNER)
        data = _recv_line(sock)
        # Registramos a tentativa de handshake / client banner.
        client_banner = data.split("\r\n")[0][:200] if data else ""
        store.log("ssh", ip, port, raw=client_banner, user_agent=client_banner)
    except OSError:
        pass
    finally:
        sock.close()


def parse_http_request(raw: str) -> dict:
    lines = raw.split("\r\n")
    method = path = ""
    user_agent = ""
    auth_user = auth_pass = ""
    if lines and lines[0]:
        parts = lines[0].split(" ")
        if len(parts) >= 2:
            method, path = parts[0], parts[1]
    for line in lines[1:]:
        low = line.lower()
        if low.startswith("user-agent:"):
            user_agent = line.split(":", 1)[1].strip()
        elif low.startswith("authorization: basic "):
            import base64
            try:
                decoded = base64.b64decode(line.split(" ", 2)[2]).decode("latin-1")
                if ":" in decoded:
                    auth_user, auth_pass = decoded.split(":", 1)
            except Exception:
                pass
    return {"method": method, "path": path, "user_agent": user_agent,
            "username": auth_user, "password": auth_pass}


def handle_http(sock: socket.socket, addr, store: EventStore) -> None:
    ip, port = addr[0], addr[1]
    try:
        raw = _recv_line(sock)
        info = parse_http_request(raw)
        store.log("http", ip, port, method=info["method"], path=info["path"],
                  user_agent=info["user_agent"], username=info["username"],
                  password=info["password"], raw=raw.split("\r\n")[0][:200])
        sock.sendall(HTTP_RESPONSE.encode("latin-1"))
    except OSError:
        pass
    finally:
        sock.close()


class Honeypot:
    def __init__(self, store: EventStore, on_event=None):
        self.store = store
        self.on_event = on_event
        self._threads: list[threading.Thread] = []
        self._servers: list[socket.socket] = []
        self._running = False

    def _serve(self, host: str, port: int, handler) -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, port))
        srv.listen(50)
        srv.settimeout(1.0)
        self._servers.append(srv)
        while self._running:
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if self.on_event:
                self.on_event(addr[0], port)
            t = threading.Thread(target=handler, args=(conn, addr, self.store),
                                 daemon=True)
            t.start()
        srv.close()

    def start(self, ssh_port: int = 2222, http_port: int = 8080,
              host: str = "0.0.0.0") -> None:
        self._running = True
        for port, handler in [(ssh_port, handle_ssh), (http_port, handle_http)]:
            t = threading.Thread(target=self._serve, args=(host, port, handler),
                                 daemon=True)
            t.start()
            self._threads.append(t)

    def stop(self) -> None:
        self._running = False
        for srv in self._servers:
            try:
                srv.close()
            except OSError:
                pass
