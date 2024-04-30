"""A TLS echo server example using tlslib with asyncio."""

import asyncio
from pathlib import Path

from examples.asyncio_example.unix_events_tls import DefaultEventLoopPolicy
from tlslib import stdlib as ossl
from tlslib import tlslib as tls

backend = ossl.STDLIB_BACKEND

_CERT = Path(__file__).parent / "cert"


async def handle_echo(reader, writer):
    """Echo handler"""
    data = await reader.read(100)
    message = data.decode()
    addr = writer.get_extra_info("peername")

    print(f"Received {message!r} from {addr!r}")

    print(f"Send: {message!r}")
    writer.write(data)
    await writer.drain()

    print("Close the connection")
    writer.close()
    await writer.wait_closed()


async def main():
    """Main server function"""

    # Certs taken from x509-limbo webpki::san::exact-localhost-dns-san test case
    cert_chain = tls.SigningChain(
        leaf=(
            backend.certificate.from_file(Path(__file__).parent / "cert/leaf.pem"),
            backend.private_key.from_file(Path(__file__).parent / "cert/key.pem"),
        ),
        chain=(),
    )

    server_config = tls.TLSServerConfiguration(certificate_chain=(cert_chain,), trust_store=None)
    server_ctx = backend.server_context(server_config)

    server = await asyncio.start_server(handle_echo, "localhost", 8888, tls=server_ctx)

    addrs = ", ".join(str(sock.getsockname()) for sock in server.sockets)
    print(f"Serving on {addrs}")

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.set_event_loop_policy(DefaultEventLoopPolicy())
    asyncio.run(main())
