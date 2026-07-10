import socket
import time

from honeypot.store import EventStore
from honeypot.servers import Honeypot, parse_http_request


def test_store_log_and_stats():
    store = EventStore(":memory:")
    store.log("ssh", "1.2.3.4", 5555, username="root", password="123456")
    store.log("ssh", "1.2.3.4", 5556, username="admin", password="123456")
    store.log("http", "9.9.9.9", 80, method="GET", path="/admin")
    s = store.stats()
    assert s["total"] == 3
    assert s["by_service"]["ssh"] == 2
    assert s["top_ips"][0] == ("1.2.3.4", 2)
    assert ("123456", 2) in s["top_passwords"]


def test_parse_http_basic_auth():
    import base64
    cred = base64.b64encode(b"admin:senha123").decode()
    raw = (f"GET /admin HTTP/1.1\r\nHost: x\r\n"
           f"User-Agent: curl/8.0\r\nAuthorization: Basic {cred}\r\n\r\n")
    info = parse_http_request(raw)
    assert info["method"] == "GET"
    assert info["path"] == "/admin"
    assert info["user_agent"] == "curl/8.0"
    assert info["username"] == "admin"
    assert info["password"] == "senha123"


def test_honeypot_captures_http_connection():
    store = EventStore(":memory:")
    hp2 = Honeypot(store)
    hp2.start(ssh_port=32222, http_port=38080, host="127.0.0.1")
    time.sleep(0.3)
    try:
        with socket.create_connection(("127.0.0.1", 38080), timeout=2) as s:
            s.sendall(b"GET /wp-admin HTTP/1.1\r\nUser-Agent: evilbot\r\n\r\n")
            s.recv(256)
        time.sleep(0.3)
    finally:
        hp2.stop()
    stats = store.stats()
    assert stats["by_service"].get("http", 0) >= 1


def test_honeypot_captures_ssh_banner():
    store = EventStore(":memory:")
    hp = Honeypot(store)
    hp.start(ssh_port=32223, http_port=38081, host="127.0.0.1")
    time.sleep(0.3)
    try:
        with socket.create_connection(("127.0.0.1", 32223), timeout=2) as s:
            banner = s.recv(64)
            assert b"SSH-2.0" in banner
            s.sendall(b"SSH-2.0-libssh_0.9\r\n")
        time.sleep(0.3)
    finally:
        hp.stop()
    assert store.stats()["by_service"].get("ssh", 0) >= 1
