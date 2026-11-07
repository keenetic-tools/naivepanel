"""Счётчик активных соединений через listen-порт naive (roadmap 2.2).

Источник — /proc/net/tcp и /proc/net/tcp6: они есть на любом Linux/OpenWrt,
читаются без root и не требуют пакетов `ss`/`netstat`, которых на роутере
по умолчанию нет.
"""
from __future__ import annotations

import ipaddress
from collections.abc import Iterator
from pathlib import Path

ESTABLISHED = "01"


def _ipv4(hex_addr: str) -> str | None:
    """8 hex-символов /proc (little-endian) → dotted-quad."""
    try:
        raw = int(hex_addr, 16).to_bytes(4, "little")
    except (ValueError, OverflowError):
        return None
    return ".".join(str(b) for b in raw)


def _ipv6(hex_addr: str) -> str | None:
    """32 hex-символа /proc (4 little-endian слова) → IPv6, mapped → IPv4."""
    if len(hex_addr) != 32:
        return None
    try:
        raw = b"".join(
            int(hex_addr[i:i + 8], 16).to_bytes(4, "little")
            for i in range(0, 32, 8)
        )
        addr = ipaddress.IPv6Address(raw)
    except (ValueError, OverflowError):
        return None
    if addr.ipv4_mapped:
        return str(addr.ipv4_mapped)
    return str(addr)


def _addr(hex_addr: str) -> str | None:
    if len(hex_addr) == 8:
        return _ipv4(hex_addr)
    if len(hex_addr) == 32:
        return _ipv6(hex_addr)
    return None


def parse_proc_net(text: str) -> Iterator[tuple[int, str, str]]:
    """Строки /proc/net/tcp{,6} → (local_port, remote_ip, state).

    Заголовок и битые строки пропускаются; состояние отдаётся как есть
    (фильтрация ESTABLISHED — забота вызывающего).
    """
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 4:
            continue
        local, remote, state = parts[1], parts[2], parts[3]
        try:
            _, port_hex = local.split(":", 1)
            port = int(port_hex, 16)
            remote_addr = remote.split(":", 1)[0]
        except ValueError:
            continue
        addr = _addr(remote_addr)
        if addr is None:
            continue
        yield port, addr, state


def _read(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def snapshot(ports: set[int], allow_loopback: bool,
             tcp_path: Path = Path("/proc/net/tcp"),
             tcp6_path: Path = Path("/proc/net/tcp6")) -> dict | None:
    """Снимок ESTABLISHED на listen-портах: {"established", "clients"}.

    `established` считает все сокеты, включая loopback: за локальным
    форвардером (xray и т.п.) реальные клиенты видны только как 127.0.0.1,
    и без них счётчик терял бы нагрузку. `clients` — уникальные не-loopback
    адреса (прямые клиенты), если allow_loopback=False; при loopback-only
    listen loopback считается и клиентом.

    None — если портов нет или не читается ни один из файлов /proc
    (например, на macOS). Один доступный файл — уже достаточный результат.
    """
    if not ports:
        return None
    texts = [_read(tcp_path), _read(tcp6_path)]
    if all(text is None for text in texts):
        return None

    established = 0
    clients: set[str] = set()
    for text in texts:
        if text is None:
            continue
        for port, addr, state in parse_proc_net(text):
            if state != ESTABLISHED or port not in ports:
                continue
            established += 1
            if not allow_loopback:
                try:
                    if ipaddress.ip_address(addr).is_loopback:
                        continue
                except ValueError:
                    continue
            clients.add(addr)
    return {"established": established, "clients": len(clients)}
