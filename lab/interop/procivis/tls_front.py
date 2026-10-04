# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""TLS in front of core-server, inside its container, so Procivis's base URL can be https.

core-server listens on plain HTTP. Its base URL is what it writes into the credential offer and
into the credential's `iss`, and an `iss` that an issuer certificate binds by a DNS name has to be
an https URL on that name. This terminates TLS for that name and passes the bytes through.

  python3 tls_front.py CERT KEY LISTEN_PORT UPSTREAM_PORT
"""
import asyncio
import ssl
import sys

CERT, KEY, LISTEN, UPSTREAM = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])


async def pipe(reader, writer):
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    finally:
        writer.close()


async def handle(client_reader, client_writer):
    try:
        upstream_reader, upstream_writer = await asyncio.open_connection("127.0.0.1", UPSTREAM)
    except OSError:
        client_writer.close()
        return
    await asyncio.gather(pipe(client_reader, upstream_writer), pipe(upstream_reader, client_writer),
                         return_exceptions=True)


async def main():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(CERT, KEY)
    server = await asyncio.start_server(handle, "0.0.0.0", LISTEN, ssl=context)
    async with server:
        await server.serve_forever()


asyncio.run(main())
