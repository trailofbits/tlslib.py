"""An TLS echo server example using tlslib with asyncio."""

import asyncio
from pathlib import Path

from examples.asyncio_example.unix_events_tls import DefaultEventLoopPolicy
from tlslib import stdlib as ossl
from tlslib import tlslib as tls

backend = ossl.STDLIB_BACKEND


async def tls_echo_client(message: str):
    """Echo client"""

    # Certs taken from x509-limbo webpki::san::exact-localhost-dns-san test case
    trust_store = backend.trust_store.from_file(Path(__file__).parent / "cert/root.pem")

    client_config = tls.TLSClientConfiguration(trust_store=trust_store)
    client_ctx = backend.client_context(client_config)

    reader, writer = await asyncio.open_connection(
        "localhost", 8888, tls=client_ctx, server_hostname="localhost"
    )

    print(f"Send: {message!r}")
    writer.write(message.encode())
    await writer.drain()

    data = await reader.read(100)
    print(f"Received: {data.decode()!r}")

    print("Close the connection")
    writer.close()
    await writer.wait_closed()


if __name__ == "__main__":
    """Main"""
    asyncio.set_event_loop_policy(DefaultEventLoopPolicy())
    asyncio.run(tls_echo_client("Hello World!"))
