#!/usr/bin/env python3
"""
High‑performance asyncio HTTP/HTTPS proxy – transparent LAN support.

Now strips hop‑by‑hop headers (Proxy‑Connection etc.) so that simple
LAN devices (like NAS, cameras) work perfectly.

Usage:
    python3 proxy.py
    (listens on [::]:8080 – dual‑stack, IPv4+IPv6)
"""

import asyncio
import os
import resource
import socket
import time
from urllib.parse import urlparse

# ------------------------------
# Configuration (all overridable)
# ------------------------------
PROXY_PORT      = int(os.environ.get("PROXY_PORT", 8080))
CHUNK_SIZE      = 65536                # 64 KB streaming chunks
MAX_CONNECTIONS = int(os.environ.get("MAX_CONNS", 500))
IDLE_TIMEOUT    = int(os.environ.get("IDLE_TIMEOUT", 60))        # seconds
CONNECT_TIMEOUT = int(os.environ.get("CONNECT_TIMEOUT", 10))     # seconds
ACQUIRE_TIMEOUT = int(os.environ.get("ACQUIRE_TIMEOUT", 10))     # semaphore wait

# ANSI colors for terminal output
COLOR_RESET   = "\033[0m"
COLOR_RED     = "\033[91m"
COLOR_YELLOW  = "\033[93m"
COLOR_GREEN   = "\033[92m"

def timestamp():
    return time.strftime("%Y-%m-%d %H:%M:%S")

def log_info(msg):
    print(f"{COLOR_GREEN}[{timestamp()}] {msg}{COLOR_RESET}")

def log_warning(msg):
    print(f"{COLOR_YELLOW}[{timestamp()}] WARNING: {msg}{COLOR_RESET}")

def log_error(msg):
    print(f"{COLOR_RED}[{timestamp()}] ERROR: {msg}{COLOR_RESET}")

# ------------------------------
# Increase file descriptor limit
# ------------------------------
def raise_fd_limit():
    """Attempt to raise the open‑files limit."""
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        desired = min(65536, hard) if hard > 0 else 65536
        resource.setrlimit(resource.RLIMIT_NOFILE, (desired, hard))
        log_info(f"Raised open files limit: {soft} -> {desired}")
    except Exception as e:
        log_warning(f"Could not raise file descriptor limit: {e}")

# ------------------------------
# Utility: parse CONNECT host:port
# ------------------------------
def parse_connect_host_port(target: str):
    """Parse 'host:port' from CONNECT, supporting IPv6 brackets."""
    if target.startswith('['):
        if ']' not in target:
            raise ValueError("Missing closing bracket for IPv6 address")
        bracket_end = target.index(']')
        host = target[1:bracket_end]
        rest = target[bracket_end+1:]
        if not rest.startswith(':'):
            raise ValueError("Missing port after IPv6 address")
        port_str = rest[1:]
        if not port_str:
            raise ValueError("Empty port")
        port = int(port_str)
        return host, port
    else:
        if ':' not in target:
            raise ValueError("Missing port")
        host, port_str = target.rsplit(':', 1)
        port = int(port_str)
        return host, port

# ------------------------------
# Header sanitisation (fix for LAN devices)
# ------------------------------
def sanitise_headers(headers: dict, target_host: str, target_port: int) -> dict:
    """
    Remove hop‑by‑hop headers and rebuild a correct Host header.
    This makes the proxy transparent to simple servers (e.g. embedded devices).
    """
    # Hop‑by‑hop headers that must not be forwarded
    hop_by_hop = {
        "proxy-connection",
        "connection",
        "keep-alive",
        "transfer-encoding",
        "te",
        "trailer",
        "upgrade",
    }
    clean = {}
    for name, value in headers.items():
        if name.lower() in hop_by_hop:
            continue
        clean[name] = value

    # Rebuild Host header (required by HTTP/1.1)
    # Include port only if it's non‑default
    if target_port == 80:
        clean["host"] = target_host
    else:
        clean["host"] = f"{target_host}:{target_port}"

    # Mark the request as having passed through us
    clean["via"] = "1.1 python-asyncio-proxy"

    return clean

# ------------------------------
# Low‑level I/O helpers (with timeouts)
# ------------------------------
async def read_headers(reader: asyncio.StreamReader) -> dict:
    headers = {}
    while True:
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=IDLE_TIMEOUT)
        except asyncio.TimeoutError:
            break
        if line in (b"\r\n", b"\n", b""):
            break
        name, _, value = line.decode(errors="replace").partition(":")
        headers[name.strip().lower()] = value.strip()
    return headers

async def write_headers(writer: asyncio.StreamWriter, headers: dict) -> None:
    for name, value in headers.items():
        writer.write(f"{name}: {value}\r\n".encode())
    writer.write(b"\r\n")

async def copy_chunked(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """Stream chunked transfer encoding body."""
    while True:
        try:
            size_line = await asyncio.wait_for(reader.readline(), timeout=IDLE_TIMEOUT)
        except asyncio.TimeoutError:
            break
        writer.write(size_line)
        if size_line == b"":
            break
        hex_part = size_line.split(b";", 1)[0].strip()
        try:
            chunk_size = int(hex_part, 16)
        except ValueError:
            break
        if chunk_size == 0:
            while True:
                try:
                    trailer = await asyncio.wait_for(reader.readline(), timeout=IDLE_TIMEOUT)
                except asyncio.TimeoutError:
                    return
                writer.write(trailer)
                if trailer in (b"\r\n", b"\n", b""):
                    break
            break
        # Stream chunk data in smaller parts
        remaining = chunk_size + 2
        while remaining > 0:
            try:
                chunk = await asyncio.wait_for(reader.read(min(CHUNK_SIZE, remaining)), timeout=IDLE_TIMEOUT)
            except asyncio.TimeoutError:
                return
            if not chunk:
                return
            writer.write(chunk)
            remaining -= len(chunk)
    await writer.drain()

async def stream_exact_length(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, length: int) -> None:
    """Stream exactly `length` bytes in fixed-size chunks."""
    remaining = length
    while remaining > 0:
        try:
            chunk = await asyncio.wait_for(reader.read(min(CHUNK_SIZE, remaining)), timeout=IDLE_TIMEOUT)
        except asyncio.TimeoutError:
            raise asyncio.IncompleteReadError(partial=length - remaining, expected=length)
        if not chunk:
            raise asyncio.IncompleteReadError(partial=length - remaining, expected=length)
        writer.write(chunk)
        remaining -= len(chunk)
        if remaining % (CHUNK_SIZE * 4) == 0:
            await writer.drain()
    await writer.drain()

async def relay(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """Full‑duplex raw relay with idle timeout."""
    try:
        while True:
            try:
                data = await asyncio.wait_for(reader.read(CHUNK_SIZE), timeout=IDLE_TIMEOUT)
            except asyncio.TimeoutError:
                break
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
        pass
    finally:
        writer.close()

# ------------------------------
# Connection handlers
# ------------------------------
async def safe_write_response(writer: asyncio.StreamWriter, response: bytes):
    """Write an HTTP error response and close the socket safely."""
    try:
        writer.write(response)
        await asyncio.wait_for(writer.drain(), timeout=5)
    except Exception:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass

async def handle_connect(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    host: str,
    port: int,
    client_addr: str
) -> None:
    """Handle CONNECT tunnel (HTTPS)."""
    try:
        remote_reader, remote_writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=CONNECT_TIMEOUT
        )
    except Exception as e:
        log_error(f"{client_addr} -> CONNECT {host}:{port} FAILED ({e})")
        await safe_write_response(client_writer, b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        return

    try:
        client_writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await client_writer.drain()
    except Exception:
        remote_writer.close()
        client_writer.close()
        return

    log_info(f"{client_addr} -> CONNECT {host}:{port} TUNNEL ESTABLISHED")

    tasks = [
        asyncio.create_task(relay(client_reader, remote_writer)),
        asyncio.create_task(relay(remote_reader, client_writer)),
    ]
    await asyncio.gather(*tasks, return_exceptions=True)

    remote_writer.close()
    client_writer.close()
    log_info(f"{client_addr} -> CONNECT {host}:{port} TUNNEL CLOSED")

async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """Main client handler."""
    peername = writer.get_extra_info("peername")
    if peername:
        if peername[0].startswith("::ffff:"):
            ip = peername[0][7:]
            client_addr = f"{ip}:{peername[1]}"
        elif ":" in peername[0]:
            client_addr = f"[{peername[0]}]:{peername[1]}"
        else:
            client_addr = f"{peername[0]}:{peername[1]}"
    else:
        client_addr = "unknown"

    try:
        request_line = await asyncio.wait_for(reader.readline(), timeout=IDLE_TIMEOUT)
        if not request_line:
            log_warning(f"{client_addr} -> EMPTY REQUEST")
            writer.close()
            return
        method, url, version = request_line.decode(errors="replace").strip().split()
    except (ValueError, ConnectionResetError, asyncio.TimeoutError) as e:
        log_warning(f"{client_addr} -> MALFORMED / TIMEOUT: {e}")
        writer.close()
        return

    # ---------- CONNECT method (HTTPS) ----------
    if method.upper() == "CONNECT":
        try:
            host, port = parse_connect_host_port(url)
        except ValueError as e:
            log_warning(f"{client_addr} -> CONNECT BAD URL: {url} ({e})")
            await safe_write_response(writer, b"HTTP/1.1 400 Bad Request\r\n\r\n")
            return

        await read_headers(reader)
        await handle_connect(reader, writer, host, port, client_addr)
        return

    # ---------- Plain HTTP request ----------
    headers = await read_headers(reader)

    parsed = urlparse(url)
    if parsed.scheme not in ("http", ""):
        log_warning(f"{client_addr} -> UNSUPPORTED SCHEME: {parsed.scheme}")
        await safe_write_response(writer, b"HTTP/1.1 400 Bad Request\r\n\r\n")
        return

    host = parsed.hostname or headers.get("host", "localhost")
    port = parsed.port or 80
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"

    # Sanitise headers (removes hop‑by‑hop, fixes Host)
    clean_headers = sanitise_headers(headers, host, port)

    log_info(f"{client_addr} -> {method} {host}:{port}{path}")

    try:
        remote_reader, remote_writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=CONNECT_TIMEOUT
        )
    except Exception as e:
        log_error(f"{client_addr} -> {method} {host}:{port}{path} FAILED ({e})")
        await safe_write_response(writer, b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        return

    # Forward request line and sanitised headers
    try:
        req_line = f"{method} {path} {version}\r\n".encode()
        remote_writer.write(req_line)
        await write_headers(remote_writer, clean_headers)

        content_length = headers.get("content-length")
        transfer_encoding = headers.get("transfer-encoding", "")
        chunked = "chunked" in transfer_encoding.lower()

        if content_length and int(content_length) > 0:
            await stream_exact_length(reader, remote_writer, int(content_length))
        elif chunked:
            await copy_chunked(reader, remote_writer)

        await remote_writer.drain()
    except Exception as e:
        log_warning(f"{client_addr} -> REQUEST FORWARDING FAILED: {e}")
        remote_writer.close()
        writer.close()
        return

    # Read response status line
    try:
        status_line = await asyncio.wait_for(remote_reader.readline(), timeout=IDLE_TIMEOUT)
        if not status_line:
            log_warning(f"{client_addr} -> EMPTY RESPONSE FROM {host}")
            remote_writer.close()
            writer.close()
            return
    except Exception as e:
        log_warning(f"{client_addr} -> FAILED TO READ RESPONSE: {e}")
        remote_writer.close()
        writer.close()
        return

    writer.write(status_line)
    resp_headers = await read_headers(remote_reader)
    await write_headers(writer, resp_headers)

    # WebSocket upgrade detection
    status_code = int(status_line.decode().split()[1])
    upgrade = resp_headers.get("upgrade", "").lower()
    if status_code == 101 and upgrade == "websocket":
        log_info(f"{client_addr} -> WEBSOCKET UPGRADE {host}:{port}{path}")
        tasks = [
            asyncio.create_task(relay(remote_reader, writer)),
            asyncio.create_task(relay(reader, remote_writer)),
        ]
        await asyncio.gather(*tasks, return_exceptions=True)
        remote_writer.close()
        writer.close()
        return

    # Relay response body (streaming)
    resp_cl = resp_headers.get("content-length")
    resp_te = resp_headers.get("transfer-encoding", "")
    resp_chunked = "chunked" in resp_te.lower()

    try:
        if resp_cl and int(resp_cl) > 0:
            await stream_exact_length(remote_reader, writer, int(resp_cl))
        elif resp_chunked:
            await copy_chunked(remote_reader, writer)
        else:
            await writer.drain()
    except Exception as e:
        log_warning(f"{client_addr} -> RESPONSE BODY RELAY FAILED: {e}")
    finally:
        remote_writer.close()
        writer.close()
        log_info(f"{client_addr} -> {method} {host}:{port}{path} COMPLETED")

# ------------------------------
# Connection limiter with timeout
# ------------------------------
_conn_sem = asyncio.Semaphore(MAX_CONNECTIONS)

async def limited_handle_client(reader, writer):
    try:
        acquired = await asyncio.wait_for(_conn_sem.acquire(), timeout=ACQUIRE_TIMEOUT)
    except asyncio.TimeoutError:
        log_warning("Proxy overloaded – rejecting new connection (503)")
        await safe_write_response(
            writer,
            b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n"
        )
        return
    try:
        await handle_client(reader, writer)
    finally:
        _conn_sem.release()

# ------------------------------
# Main server loop (dual‑stack)
# ------------------------------
async def main():
    raise_fd_limit()

    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM, 0)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    except (AttributeError, OSError):
        pass
    sock.bind(("::", PROXY_PORT))
    sock.listen(256)
    sock.setblocking(False)

    server = await asyncio.start_server(limited_handle_client, sock=sock)
    log_info(f"PROXY LISTENING ON [::]:{PROXY_PORT} (dual‑stack, IPv4+IPv6)")
    log_info(f"Max concurrent connections: {MAX_CONNECTIONS}")
    log_info(f"Idle timeout: {IDLE_TIMEOUT}s, Connect timeout: {CONNECT_TIMEOUT}s")
    log_info("Ready for public connections (ensure firewall/port forwarding is set).")

    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log_warning("Proxy stopped by user.")
