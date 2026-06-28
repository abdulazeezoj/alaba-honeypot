"""
Paramiko-based decoy SSH server.

Behavior:
- Accepts every authentication attempt (the classic honeypot trick: a real
  attacker-facing SSH service would reject most attempts, but we WANT the
  attacker to log in so we can see what they do next). Every username/
  password pair tried is logged regardless of whether we "accept" it.
- Once authenticated, the client gets a fake interactive shell. We don't
  execute anything for real -- every typed command is logged and given a
  canned response so the session feels plausible without giving the
  attacker an actual machine to act on.
- Each client connection runs on its own thread (Paramiko's Transport is
  blocking I/O), and each thread gets its own SQLite connection via
  honeypot.db's thread-local connection handling.
"""

from __future__ import annotations

import logging
import os
import socket
import threading

import paramiko

from honeypot import db
from honeypot.geoip import enricher

logger = logging.getLogger("honeypot.ssh")

HOST_KEY_PATH = os.path.join(os.path.dirname(__file__), "keys", "host_key")

# Fake command responses, just enough to make a scripted credential-stuffing
# bot or a curious human believe they're in a real (if boring) shell.
FAKE_RESPONSES = {
    "ls": "bin  boot  dev  etc  home  lib  media  mnt  opt  proc  root  run  sbin  srv  tmp  usr  var",
    "pwd": "/root",
    "id": "uid=0(root) gid=0(root) groups=0(root)",
    "uname -a": "Linux ubuntu-prod-01 5.15.0-92-generic #102-Ubuntu SMP x86_64 GNU/Linux",
    "whoami": "root",
}


def ensure_host_key() -> paramiko.RSAKey:
    """Generate a persistent RSA host key on first run, reuse afterward."""
    os.makedirs(os.path.dirname(HOST_KEY_PATH), exist_ok=True)
    if os.path.exists(HOST_KEY_PATH):
        return paramiko.RSAKey(filename=HOST_KEY_PATH)
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(HOST_KEY_PATH)
    logger.info("generated new SSH host key at %s", HOST_KEY_PATH)
    return key


class HoneypotSSHServer(paramiko.ServerInterface):
    """
    One instance per client connection. Paramiko calls check_auth_* for
    every authentication attempt the client makes; we log all of them and
    accept on the first attempt so the session moves on to a shell.
    """

    def __init__(self, connection_id: int, client_ip: str):
        super().__init__()
        self.connection_id = connection_id
        self.client_ip = client_ip
        self.event = threading.Event()

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username: str, password: str) -> int:
        logger.info("auth attempt from %s -> %s:%s", self.client_ip, username, password)
        db.log_credential(self.connection_id, username, password, "password", accepted=True)
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_publickey(self, username: str, key: paramiko.PKey) -> int:
        fingerprint = key.get_fingerprint().hex()
        logger.info("pubkey auth attempt from %s -> user=%s fp=%s", self.client_ip, username, fingerprint)
        db.log_credential(self.connection_id, username, fingerprint, "publickey", accepted=False)
        # Reject pubkey auth so well-behaved clients fall back to password,
        # which is the credential-harvesting path we actually care about.
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username: str) -> str:
        return "password,publickey"

    def check_channel_shell_request(self, channel) -> bool:
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes) -> bool:
        return True

    def check_channel_exec_request(self, channel, command: bytes) -> bool:
        cmd = command.decode(errors="replace")
        logger.info("exec request from %s: %s", self.client_ip, cmd)
        db.log_command(self.connection_id, cmd)
        try:
            channel.send(b"")
        finally:
            channel.send_exit_status(0)
        return True


def _handle_shell(channel: paramiko.Channel, connection_id: int, client_ip: str) -> None:
    """Minimal fake interactive shell loop: echo a prompt, log every line typed."""
    try:
        channel.send(b"Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-92-generic x86_64)\r\n\r\n")
        prompt = b"root@ubuntu-prod-01:~# "
        channel.send(prompt)
        buf = b""
        while True:
            data = channel.recv(1024)
            if not data:
                break
            # Echo back so the client's terminal looks responsive.
            channel.send(data)
            buf += data
            if b"\r" in buf or b"\n" in buf:
                line = buf.replace(b"\r", b"").replace(b"\n", b"").decode(errors="replace").strip()
                buf = b""
                if not line:
                    channel.send(b"\r\n" + prompt)
                    continue
                logger.info("command from %s: %s", client_ip, line)
                db.log_command(connection_id, line)
                if line in ("exit", "logout", "quit"):
                    channel.send(b"\r\nlogout\r\n")
                    break
                response = FAKE_RESPONSES.get(line, f"-bash: {line.split()[0]}: command not found" if line else "")
                channel.send(f"\r\n{response}\r\n".encode())
                channel.send(prompt)
    except Exception:
        logger.exception("error in fake shell for %s", client_ip)
    finally:
        channel.close()


def _client_thread(client_sock: socket.socket, client_addr: tuple, host_key: paramiko.RSAKey) -> None:
    client_ip, client_port = client_addr[0], client_addr[1]
    connection_id = db.open_connection(client_ip, client_port, protocol="ssh")
    enricher.submit(client_ip)

    transport = paramiko.Transport(client_sock)
    transport.add_server_key(host_key)
    server = HoneypotSSHServer(connection_id, client_ip)

    try:
        transport.start_server(server=server)
        channel = transport.accept(timeout=20)
        if channel is None:
            return

        if server.event.wait(10):
            _handle_shell(channel, connection_id, client_ip)
    except (paramiko.SSHException, EOFError, ConnectionResetError) as exc:
        logger.info("session with %s ended: %s", client_ip, exc)
    except Exception:
        logger.exception("unexpected error handling %s", client_ip)
    finally:
        db.close_connection(connection_id)
        try:
            transport.close()
        except Exception:
            pass


def serve(host: str = "0.0.0.0", port: int = 2222) -> None:
    """
    Run the SSH honeypot forever, accepting connections and spawning a
    handler thread per client. Intended to be run on its own thread from
    run.py so it doesn't block the Flask dashboard.

    NOTE: port 2222 is used by default because binding port 22 requires
    root privileges on most systems. Run with sudo/CAP_NET_BIND_SERVICE
    and pass port=22, or front it with an iptables/firewall redirect rule,
    if you want it reachable on the standard port.
    """
    host_key = ensure_host_key()
    db.init_db()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(100)
    logger.info("SSH honeypot listening on %s:%d", host, port)

    while True:
        try:
            client_sock, client_addr = sock.accept()
        except OSError:
            break
        thread = threading.Thread(
            target=_client_thread,
            args=(client_sock, client_addr, host_key),
            daemon=True,
            name=f"ssh-client-{client_addr[0]}",
        )
        thread.start()
