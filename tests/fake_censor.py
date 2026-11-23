"""Fake TSPU / Censor test server for deterministic CI testing of netdoctor probes and classifier."""

from __future__ import annotations

import asyncio
import datetime
import ssl
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def create_self_signed_ssl_context(hostname: str = "example.com") -> tuple[ssl.SSLContext, Path, Path]:
    """Generate a temporary self-signed certificate and return an SSL server context."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        ]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=7))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
        .sign(key, hashes.SHA256())
    )

    tmp_dir = Path(tempfile.mkdtemp(prefix="netdoctor_cert_"))
    cert_path = tmp_dir / "cert.pem"
    key_path = tmp_dir / "key.pem"

    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    return ctx, cert_path, key_path


class _UdpCensorProtocol(asyncio.DatagramProtocol):
    def __init__(self, drop_udp: bool = False) -> None:
        self.drop_udp = drop_udp
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        if self.drop_udp or not self.transport:
            return
        # Echo back a simulated QUIC Version Negotiation / Server Initial response
        self.transport.sendto(b"\xc0\x00\x00\x00\x01\x08response", addr)


class FakeCensorServer:
    """Configurable local server that simulates TSPU censorship modes:
    - mode='ok': passes TLS with any SNI, serves full HTTP response, echoes QUIC UDP
    - mode='sni_dpi': aborts connection during TLS ClientHello if SNI matches blocked_sni, passes neutral SNI
    - mode='throttle': completes TLS handshake, sends only 16 bytes of HTTP response and stalls/closes
    - mode='quic_block': drops all UDP packets while allowing TCP/TLS
    - mode='ip_block': immediately resets/closes TCP before TLS handshake
    """

    def __init__(
        self,
        mode: str = "ok",
        blocked_sni: str = "discord.com",
    ) -> None:
        self.mode = mode
        self.blocked_sni = blocked_sni
        self.ssl_ctx, self._cert_path, self._key_path = create_self_signed_ssl_context("example.com")
        self._aborted_by_sni = False
        self.ssl_ctx.sni_callback = self._on_sni
        self.tcp_server: asyncio.AbstractServer | None = None
        self.udp_transport: asyncio.DatagramTransport | None = None
        self.tcp_port: int = 0
        self.udp_port: int = 0

    def _on_sni(self, ssl_sock: ssl.SSLObject, server_name: str | None, ssl_ctx: ssl.SSLContext) -> int | None:
        if self.mode == "sni_dpi" and server_name == self.blocked_sni:
            return ssl.ALERT_DESCRIPTION_INTERNAL_ERROR
        return None

    async def _handle_tcp(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if self.mode == "ip_block":
            writer.close()
            return

        try:
            # Wait briefly for HTTP request if TLS succeeded
            data = await asyncio.wait_for(reader.read(1024), timeout=1.5)
            if not data:
                writer.close()
                return

            if self.mode == "throttle":
                # Send tiny truncated header and stall until client times out
                writer.write(b"HTTP/1.1 200 OK\r\n")
                await writer.drain()
                await asyncio.sleep(5.0)
            else:
                body = b"X" * 4096
                resp = (
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: text/plain\r\n"
                    + f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
                    + body
                )
                writer.write(resp)
                await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        if self.mode == "ip_block":
            # Raw TCP server that immediately closes without TLS
            self.tcp_server = await asyncio.start_server(self._handle_tcp, "127.0.0.1", 0)
        else:
            self.tcp_server = await asyncio.start_server(
                self._handle_tcp,
                "127.0.0.1",
                0,
                ssl=self.ssl_ctx,
            )
        self.tcp_port = self.tcp_server.sockets[0].getsockname()[1]

        drop_udp = self.mode in ("quic_block", "ip_block")
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _UdpCensorProtocol(drop_udp=drop_udp),
            local_addr=("127.0.0.1", 0),
        )
        self.udp_transport = transport  # type: ignore[assignment]
        self.udp_port = transport.get_extra_info("sockname")[1]

    async def stop(self) -> None:
        if self.tcp_server:
            self.tcp_server.close()
            await self.tcp_server.wait_closed()
        if self.udp_transport:
            self.udp_transport.close()
        self._cert_path.unlink(missing_ok=True)
        self._key_path.unlink(missing_ok=True)
        try:
            self._cert_path.parent.rmdir()
        except OSError:
            pass
