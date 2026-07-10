"""CLI do Honeypot."""

from __future__ import annotations

import argparse
import time

from .store import EventStore
from .servers import Honeypot


def _print_stats(store: EventStore) -> None:
    s = store.stats()
    print("\n=== Estatísticas do Honeypot ===")
    print(f"Total de eventos: {s['total']}")
    print(f"Por serviço: {s['by_service']}")
    print("\nTop IPs atacantes:")
    for ip, c in s["top_ips"]:
        print(f"  {ip:<20} {c}")
    print("\nTop usuários tentados:")
    for u, c in s["top_usernames"]:
        print(f"  {u:<20} {c}")
    print("\nTop senhas tentadas:")
    for p, c in s["top_passwords"]:
        print(f"  {p:<20} {c}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Honeypot SSH/HTTP de baixa interação — registra ataques."
    )
    parser.add_argument("--ssh-port", type=int, default=2222)
    parser.add_argument("--http-port", type=int, default=8080)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--db", default="honeypot.db")
    parser.add_argument("--stats", action="store_true", help="mostra estatísticas e sai")
    args = parser.parse_args(argv)

    store = EventStore(args.db)

    if args.stats:
        _print_stats(store)
        return 0

    def on_event(ip, port):
        print(f"[!] Conexão de {ip} na porta {port}")

    hp = Honeypot(store, on_event=on_event)
    hp.start(ssh_port=args.ssh_port, http_port=args.http_port, host=args.host)
    print(f"[*] Honeypot ativo — SSH:{args.ssh_port} HTTP:{args.http_port}")
    print("[*] Ctrl+C para parar e ver estatísticas.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Encerrando...")
    finally:
        hp.stop()
        _print_stats(store)
        store.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
