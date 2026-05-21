"""Client node for a DIMY-style privacy-preserving contact tracing demo.

Each node periodically creates an ephemeral X25519 public key, splits it into
Shamir shares, broadcasts those shares over UDP, reconstructs peer EphIDs, and
stores derived encounter identifiers in rolling Bloom filters. A TCP backend is
used for contact Bloom filter uploads and query Bloom filter checks.
"""

import hashlib
import json
import random
import secrets
import socket
import sys
import threading
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from pyshamir import combine, split

FILTER_SIZE_BYTES = 102400
UDP_BROADCAST_PORT = 50000
DEFAULT_SERVER_IP = "127.0.0.1"
DEFAULT_SERVER_PORT = 55000
SHARE_BROADCAST_INTERVAL_SECONDS = 3
DBF_ROTATION_MULTIPLIER = 6
RETENTION_MULTIPLIER = 36
MAX_STORED_DBF_COUNT = 5


def configure_stdio():
    """Keep console output readable on terminals with different encodings."""
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        if stream and hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


class BloomFilter:
    """Small Bloom filter implementation backed by a bytearray."""

    def __init__(self):
        self.size_bytes = FILTER_SIZE_BYTES
        self.num_bits = self.size_bytes * 8
        self.bit_array = bytearray(self.size_bytes)
        self.k_hashes = 3

    def _get_indices(self, item_string):
        indices = []
        for salt in range(self.k_hashes):
            salted = f"{item_string}_{salt}".encode("utf-8")
            digest = hashlib.sha256(salted).hexdigest()
            indices.append(int(digest, 16) % self.num_bits)
        return indices

    def add(self, item):
        """Set all Bloom filter bits for an item."""
        for index in self._get_indices(item):
            self.bit_array[index // 8] |= 1 << (index % 8)

    def merge(self, other_filter):
        """Merge another Bloom filter into this filter."""
        for index in range(self.size_bytes):
            self.bit_array[index] |= other_filter.bit_array[index]

    def popcount(self):
        """Return the number of set bits."""
        return sum(byte.bit_count() for byte in self.bit_array)


class DimyIDProtocol:
    """EphID generation and encounter identifier derivation."""

    @staticmethod
    def generate_new_ephid():
        """Generate a fresh X25519 EphID and its SHA-256 hash."""
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()
        ephid_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        ephid_hex = ephid_bytes.hex()
        ephid_hash = hashlib.sha256(ephid_bytes).hexdigest()
        return ephid_hex, ephid_hash, private_key

    @staticmethod
    def compute_encid(private_key, peer_ephid_hex):
        """Derive an encounter identifier from local and peer EphIDs."""
        peer_bytes = bytes.fromhex(peer_ephid_hex)
        peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_bytes)
        shared_secret = private_key.exchange(peer_public_key)
        return hashlib.sha256(shared_secret).hexdigest()


class DimyNode:
    """Runs the DIMY client protocol threads for one participant node."""

    VALID_EPHID_PERIODS = {15, 18, 21, 24, 27, 30}
    VALID_DROP_PERCENTAGES = {30, 40, 50, 60, 70}

    def __init__(
        self,
        ephid_period,
        threshold,
        share_count,
        drop_percentage,
        server_ip=DEFAULT_SERVER_IP,
        server_port=DEFAULT_SERVER_PORT,
    ):
        if ephid_period not in self.VALID_EPHID_PERIODS:
            raise ValueError(
                f"ephid_period must be in {sorted(self.VALID_EPHID_PERIODS)}"
            )
        if threshold < 3 or share_count < 5 or threshold >= share_count:
            raise ValueError(
                "threshold >= 3, share_count >= 5, and threshold < share_count"
            )
        if drop_percentage not in self.VALID_DROP_PERCENTAGES:
            raise ValueError(
                "drop_percentage must be in " f"{sorted(self.VALID_DROP_PERCENTAGES)}"
            )

        self.ephid_period = ephid_period
        self.threshold = threshold
        self.share_count = share_count
        self.drop_probability = drop_percentage / 100.0

        self.server_ip = server_ip
        self.server_port = int(server_port)

        self.node_id = secrets.token_hex(8)
        self.udp_port = UDP_BROADCAST_PORT
        self.is_running = True
        self.has_uploaded_cbf = False

        self.state_lock = threading.Lock()

        self.current_ephid_hash = None
        self.current_packets = []
        self.broadcast_index = 0

        self.private_keys_by_hash = {}
        self.ephid_created_at = {}

        self.received_shares = {}
        self.completed_encounters = set()

        self.dbf_list = []
        self.current_dbf = BloomFilter()
        self.current_dbf_started_at = time.time()
        self.encounter_context = {}

    def _log(self, component, message):
        print("-" * 8)
        print(f"[{time.strftime('%H:%M:%S')}] [{component}] {message}")
        print("-" * 8)

    def thread_generate_ephid(self):
        """Generate EphIDs, split them into shares, and prepare UDP packets."""
        while self.is_running:
            ephid_hex, ephid_hash, private_key = DimyIDProtocol.generate_new_ephid()
            ephid_bytes = bytes.fromhex(ephid_hex)
            shares = split(ephid_bytes, self.share_count, self.threshold)

            packets = []
            for share in shares:
                payload = {
                    "sender_id": self.node_id,
                    "ephid_hash": ephid_hash,
                    "share": share.hex(),
                }
                packet = json.dumps(payload, separators=(",", ":")).encode("utf-8")
                packets.append(packet)

            with self.state_lock:
                self.current_ephid_hash = ephid_hash
                self.current_packets = packets
                self.broadcast_index = 0

                self.private_keys_by_hash[ephid_hash] = private_key
                self.ephid_created_at[ephid_hash] = time.time()
                self._drop_expired_ephids()

            self._log(
                "Identity",
                "Generated new 32-byte EphID. " f"hash={ephid_hash}, ephid={ephid_hex}",
            )
            self._log(
                "Sharing",
                f"Prepared Shamir {self.threshold}-of-{self.share_count} shares.",
            )
            time.sleep(self.ephid_period)

    def _drop_expired_ephids(self):
        """Remove private keys that are outside the retention window."""
        cutoff = time.time() - self.ephid_period * RETENTION_MULTIPLIER
        expired_hashes = [
            ephid_hash
            for ephid_hash, created_at in self.ephid_created_at.items()
            if created_at < cutoff and ephid_hash != self.current_ephid_hash
        ]

        for ephid_hash in expired_hashes:
            del self.ephid_created_at[ephid_hash]
            del self.private_keys_by_hash[ephid_hash]

    def thread_broadcast_udp(self):
        """Broadcast one prepared share packet at each interval."""
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        try:
            while self.is_running:
                packet = None
                with self.state_lock:
                    if self.current_packets:
                        packet = self.current_packets[
                            self.broadcast_index % len(self.current_packets)
                        ]
                        self.broadcast_index += 1
                        share_index = (self.broadcast_index - 1) % self.share_count + 1

                if packet is not None:
                    udp_socket.sendto(packet, ("<broadcast>", self.udp_port))
                    self._log(
                        "Broadcast",
                        f"Sent UDP share {share_index}/{self.share_count}; "
                        f"payload_bytes={len(packet)}",
                    )

                time.sleep(SHARE_BROADCAST_INTERVAL_SECONDS)
        finally:
            udp_socket.close()

    def thread_receive_udp(self):
        """Receive peer shares and construct encounter identifiers."""
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        udp_socket.bind(("", self.udp_port))
        udp_socket.settimeout(1.0)

        try:
            while self.is_running:
                try:
                    data, addr = udp_socket.recvfrom(4096)
                except socket.timeout:
                    continue

                drop_sample = random.random()
                if drop_sample < self.drop_probability:
                    self._log(
                        "Receiver",
                        f"Dropped share from {addr[0]}:{addr[1]}; "
                        f"sample={drop_sample:.3f}, "
                        f"threshold={self.drop_probability:.2f}",
                    )
                    continue

                payload = self._decode_share_payload(data)
                if payload is None:
                    continue

                sender_id = payload["sender_id"]
                ephid_hash = payload["ephid_hash"]
                share_hex = payload["share"]

                if sender_id == self.node_id:
                    continue

                self._log(
                    "Receiver",
                    f"Stored share from node={sender_id}; "
                    f"sample={drop_sample:.3f}, "
                    f"threshold={self.drop_probability:.2f}",
                )

                context = self._get_or_create_encounter_context(sender_id, ephid_hash)
                if context is None:
                    continue

                local_hash = context["local_hash"]
                local_private_key = context["local_private_key"]
                encounter_key = (sender_id, ephid_hash, local_hash)

                if encounter_key in self.completed_encounters:
                    continue

                share_count, shares_hex = self._store_share(
                    encounter_key,
                    share_hex,
                )
                self._log(
                    "Reconstruction",
                    f"Collected peer shares. peer={sender_id}, "
                    f"peer_hash={ephid_hash}, unique_shares={share_count}/"
                    f"{self.threshold}",
                )

                if share_count < self.threshold:
                    continue

                recovered_bytes = self._recover_ephid(shares_hex, ephid_hash)
                if recovered_bytes is None:
                    continue

                enc_id = self._derive_encid(local_private_key, recovered_bytes, addr)
                if enc_id is None:
                    continue

                self._store_encounter(encounter_key, sender_id, ephid_hash, enc_id)
        finally:
            udp_socket.close()

    def _decode_share_payload(self, data):
        """Decode and validate a UDP share payload."""
        try:
            payload = json.loads(data.decode("utf-8"))
            return {
                "sender_id": payload["sender_id"],
                "ephid_hash": payload["ephid_hash"],
                "share": payload["share"],
            }
        except (KeyError, ValueError, UnicodeDecodeError, json.JSONDecodeError):
            return None

    def _get_or_create_encounter_context(self, sender_id, ephid_hash):
        """Bind a peer EphID to the local EphID active when first observed."""
        context_key = (sender_id, ephid_hash)
        with self.state_lock:
            if context_key not in self.encounter_context:
                local_hash = self.current_ephid_hash
                local_private_key = self.private_keys_by_hash.get(local_hash)

                if not local_hash or not local_private_key:
                    return None

                self.encounter_context[context_key] = {
                    "local_hash": local_hash,
                    "local_private_key": local_private_key,
                }

            return self.encounter_context[context_key]

    def _store_share(self, encounter_key, share_hex):
        """Store a unique share and return the reconstruction candidate set."""
        with self.state_lock:
            share_bucket = self.received_shares.setdefault(encounter_key, set())
            share_bucket.add(share_hex)
            share_count = len(share_bucket)
            shares_hex = list(share_bucket)[: self.threshold]

        return share_count, shares_hex

    def _recover_ephid(self, shares_hex, expected_hash):
        """Recover and verify a peer EphID from Shamir shares."""
        try:
            shares_bytes = [bytes.fromhex(item) for item in shares_hex]
            recovered_bytes = combine(shares_bytes)
        except ValueError:
            return None

        actual_hash = hashlib.sha256(recovered_bytes).hexdigest()
        if actual_hash != expected_hash:
            self._log(
                "Reconstruction",
                "Failed EphID hash verification. "
                f"expected={expected_hash}, actual={actual_hash}",
            )
            return None

        self._log(
            "Reconstruction",
            f"Recovered peer EphID successfully. verify_hash={actual_hash}",
        )
        return recovered_bytes

    def _derive_encid(self, local_private_key, recovered_bytes, addr):
        """Derive an EncID from the local private key and recovered peer EphID."""
        try:
            enc_id = DimyIDProtocol.compute_encid(
                local_private_key,
                recovered_bytes.hex(),
            )
        except ValueError as exc:
            self._log(
                "Encounter",
                f"Failed to construct EncID from {addr}; error={exc}",
            )
            return None

        self._log("Encounter", f"Derived EncID. encid={enc_id}")
        return enc_id

    def _store_encounter(self, encounter_key, sender_id, ephid_hash, enc_id):
        """Encode an encounter identifier into the current daily Bloom filter."""
        context_key = (sender_id, ephid_hash)
        with self.state_lock:
            before_bits = self.current_dbf.popcount()
            self.current_dbf.add(enc_id)
            after_bits = self.current_dbf.popcount()
            self.completed_encounters.add(encounter_key)
            self.received_shares.pop(encounter_key, None)
            self.encounter_context.pop(context_key, None)

        self._log(
            "BloomFilter",
            f"Encoded EncID into DBF. peer={sender_id}, "
            f"dbf_bits={before_bits}->{after_bits}",
        )

    def thread_rotate_dbf(self):
        """Rotate daily Bloom filters and retain only recent filters."""
        while self.is_running:
            time.sleep(self.ephid_period * DBF_ROTATION_MULTIPLIER)
            now = time.time()

            with self.state_lock:
                self.dbf_list.append((self.current_dbf_started_at, self.current_dbf))
                self.current_dbf = BloomFilter()
                self.current_dbf_started_at = now

                cutoff = now - self.ephid_period * RETENTION_MULTIPLIER
                self.dbf_list = [
                    (started_at, dbf)
                    for started_at, dbf in self.dbf_list
                    if started_at >= cutoff
                ]
                if len(self.dbf_list) > MAX_STORED_DBF_COUNT:
                    self.dbf_list = self.dbf_list[-MAX_STORED_DBF_COUNT:]

                dbf_count = len(self.dbf_list) + 1

            self._log(
                "BloomFilter",
                "Rotated DBF. "
                f"window={self.ephid_period * DBF_ROTATION_MULTIPLIER}s, "
                f"retention={self.ephid_period * RETENTION_MULTIPLIER}s, "
                f"dbf_count={dbf_count}",
            )

    def thread_query_backend(self):
        """Periodically query the backend unless this node uploaded a CBF."""
        while self.is_running:
            time.sleep(self.ephid_period * RETENTION_MULTIPLIER)
            if not self.is_running or self.has_uploaded_cbf:
                continue

            self._log(
                "Query",
                "Combining DBFs into a query Bloom filter. "
                f"window={self.ephid_period * RETENTION_MULTIPLIER / 60:.1f} min",
            )
            self.send_filter_to_server("QUERY")

    def build_combined_filter(self):
        """Merge retained DBFs and the active DBF into one Bloom filter."""
        combined_filter = BloomFilter()
        with self.state_lock:
            previous_dbfs = [dbf for _, dbf in self.dbf_list]
            current_dbf = self.current_dbf

        for dbf in previous_dbfs:
            combined_filter.merge(dbf)
        combined_filter.merge(current_dbf)
        return combined_filter

    def send_filter_to_server(self, action="QUERY"):
        """Upload a CBF or query with a QBF over TCP."""
        combined_filter = self.build_combined_filter()
        filter_bits = combined_filter.popcount()

        try:
            with socket.create_connection(
                (self.server_ip, self.server_port),
                timeout=5,
            ) as tcp_socket:
                if action == "UPLOAD_CBF":
                    self._upload_cbf(tcp_socket, combined_filter, filter_bits)
                elif action == "QUERY":
                    self._query_qbf(tcp_socket, combined_filter, filter_bits)
                else:
                    self._log("Backend", f"Unknown action: {action}")
        except OSError as exc:
            self._log("Backend", f"Failed to connect to server: {exc}")

    def _upload_cbf(self, tcp_socket, combined_filter, filter_bits):
        self._log(
            "Upload",
            f"Uploading CBF to {self.server_ip}:{self.server_port}; "
            f"cbf_bits={filter_bits}",
        )
        tcp_socket.sendall(b"UPLOAD_CBF")
        tcp_socket.recv(1024)
        tcp_socket.sendall(combined_filter.bit_array)
        response = tcp_socket.recv(1024).decode("utf-8", errors="replace")
        self._log("Upload", f"Server response: {response}")

        if response == "UPLOAD_SUCCESS":
            self.has_uploaded_cbf = True
            self._log("Upload", "CBF uploaded. Automatic QBF queries are disabled.")

    def _query_qbf(self, tcp_socket, combined_filter, filter_bits):
        self._log(
            "Query",
            f"Sending QBF to {self.server_ip}:{self.server_port}; "
            f"qbf_bits={filter_bits}",
        )
        tcp_socket.sendall(b"QUERY_QBF")
        tcp_socket.recv(1024)
        tcp_socket.sendall(combined_filter.bit_array)
        response = tcp_socket.recv(1024).decode("utf-8", errors="replace")
        self._log("Query", f"Server response: {response}")

    def start(self):
        """Start all client worker threads."""
        threads = [
            threading.Thread(target=self.thread_generate_ephid, daemon=True),
            threading.Thread(target=self.thread_broadcast_udp, daemon=True),
            threading.Thread(target=self.thread_receive_udp, daemon=True),
            threading.Thread(target=self.thread_rotate_dbf, daemon=True),
            threading.Thread(target=self.thread_query_backend, daemon=True),
        ]
        for thread in threads:
            thread.start()

        print("=" * 66)
        print(
            "DIMY client is running...\n"
            f"node_id={self.node_id}\n"
            f"t={self.ephid_period}s, "
            f"k={self.threshold}, "
            f"n={self.share_count}, "
            f"drop_probability={int(self.drop_probability * 100)}%"
        )
        if self.share_count * SHARE_BROADCAST_INTERVAL_SECONDS > self.ephid_period:
            print(
                "[Warning] A full share round may take longer than one EphID period: "
                f"{self.share_count * SHARE_BROADCAST_INTERVAL_SECONDS}s > "
                f"{self.ephid_period}s."
            )
        print("-" * 66)

    def stop(self):
        """Signal all client threads to stop."""
        self.is_running = False


def run_cli(node):
    """Read interactive commands for manual upload and query actions."""
    try:
        while node.is_running:
            try:
                command = (
                    input(
                        "\n[Enter 'q' to query exposure risk | "
                        "enter 'i' to upload this node's CBF]\n"
                    )
                    .strip()
                    .lower()
                )
            except EOFError:
                while node.is_running:
                    time.sleep(1)
                break

            if command == "i":
                node.send_filter_to_server("UPLOAD_CBF")
            elif command == "q":
                node.send_filter_to_server("QUERY")
    except KeyboardInterrupt:
        print("\nShutting down the DIMY client node...")
    finally:
        node.stop()


def main(argv=None):
    configure_stdio()
    argv = argv or sys.argv
    if len(argv) < 5:
        print(
            "Usage: python Dimy.py [t] [k] [n] [drop_percent] "
            "[server_ip] [server_port]"
        )
        return 1

    try:
        ephid_period = int(argv[1])
        threshold = int(argv[2])
        share_count = int(argv[3])
        drop_percentage = int(argv[4])
        server_ip = argv[5] if len(argv) > 5 else DEFAULT_SERVER_IP
        server_port = argv[6] if len(argv) > 6 else DEFAULT_SERVER_PORT
        node = DimyNode(
            ephid_period,
            threshold,
            share_count,
            drop_percentage,
            server_ip,
            server_port,
        )
    except ValueError as exc:
        print(f"Parameter error: {exc}")
        return 1

    node.start()
    run_cli(node)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
