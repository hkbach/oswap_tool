"""Minimal TLS-only socket server for exercising tls_check.check_tls()
offline, using a locally-generated cert (expired or self-signed-untrusted).
Not part of the shipped tool — a throwaway test harness.
"""
import socket
import ssl
import sys
import threading


def serve_once_forever(port: int, certfile: str, keyfile: str):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
    # Some cert/key combos (from cryptography-built certs) work fine with default settings.
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", port))
    sock.listen(5)
    while True:
        conn, _ = sock.accept()
        try:
            with ctx.wrap_socket(conn, server_side=True) as ssock:
                try:
                    ssock.recv(4096)
                except Exception:
                    pass
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass


if __name__ == "__main__":
    port = int(sys.argv[1])
    certfile = sys.argv[2]
    keyfile = sys.argv[3]
    serve_once_forever(port, certfile, keyfile)
