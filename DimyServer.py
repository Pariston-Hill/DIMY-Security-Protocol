"""TCP backend server for the DIMY protocol demo."""

import socket
import threading

FILTER_SIZE_BYTES = 102400
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 55000
EXPOSURE_MATCH_THRESHOLD = 3


class DimyServer:
    """Stores contact Bloom filters and answers exposure queries."""

    def __init__(self, host=DEFAULT_HOST, port=DEFAULT_PORT):
        self.host = host
        self.port = port
        self.cbf_storage = []
        self.is_running = True

    def _log(self, component, message):
        print(f"[{component}] {message}")

    def recv_exactly(self, conn, size):
        """Read exactly size bytes from a TCP connection."""
        chunks = bytearray()
        while len(chunks) < size:
            chunk = conn.recv(size - len(chunks))
            if not chunk:
                raise ConnectionError(
                    f"Expected {size} bytes but received {len(chunks)} bytes."
                )
            chunks.extend(chunk)
        return chunks

    def handle_client(self, conn, addr):
        """Handle one upload or query request from a client node."""
        self._log("Server", f"Accepted connection from {addr}.")
        try:
            request_type = conn.recv(1024).decode("utf-8", errors="replace").strip()

            if request_type == "UPLOAD_CBF":
                conn.sendall(b"READY")
                cbf_data = self.recv_exactly(conn, FILTER_SIZE_BYTES)
                self.cbf_storage.append(cbf_data)
                bit_count = sum(byte.bit_count() for byte in cbf_data)
                self._log(
                    "Upload",
                    f"Stored CBF from {addr}. "
                    f"total_cbfs={len(self.cbf_storage)}, cbf_bits={bit_count}",
                )
                conn.sendall(b"UPLOAD_SUCCESS")
                return

            if request_type == "QUERY_QBF":
                conn.sendall(b"READY")
                qbf_data = self.recv_exactly(conn, FILTER_SIZE_BYTES)
                qbf_bits = sum(byte.bit_count() for byte in qbf_data)
                self._log("Query", f"Received QBF from {addr}. qbf_bits={qbf_bits}")

                is_positive = bool(self.cbf_storage) and self.check_filters(qbf_data)
                result = b"POSITIVE" if is_positive else b"NEGATIVE"
                self._log("Query", f"Exposure result={result.decode('utf-8')}.")
                conn.sendall(result)
                return

            self._log("Server", f"Unknown request from {addr}: {request_type}")
        except Exception as exc:
            self._log("Server", f"Client handling error for {addr}: {exc}")
        finally:
            conn.close()

    def check_filters(self, qbf):
        """Return True when a query filter overlaps enough with a stored CBF."""
        for cbf in self.cbf_storage:
            overlap_bits = 0
            for index, qbf_byte in enumerate(qbf):
                overlap_bits += (qbf_byte & cbf[index]).bit_count()
                if overlap_bits >= EXPOSURE_MATCH_THRESHOLD:
                    return True
        return False

    def start(self):
        """Start the TCP server loop."""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(5)
        server_socket.settimeout(1.0)

        self._log("Server", f"Listening on {self.host}:{self.port}.")

        try:
            while self.is_running:
                try:
                    conn, addr = server_socket.accept()
                except socket.timeout:
                    continue

                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(conn, addr),
                    daemon=True,
                )
                client_thread.start()
        except KeyboardInterrupt:
            self.is_running = False
            self._log("Server", "Server is shutting down...")
        finally:
            server_socket.close()


def main():
    server = DimyServer()
    server.start()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
