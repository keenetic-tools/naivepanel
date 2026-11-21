#!/usr/bin/env python3
"""Подпись релизов NaivePanel (SEC-07, Task 18).

Ed25519 (RFC 8032) на чистом stdlib — ни installer на роутере, ни CI не
тянут крипто-зависимостей. Формат .minisig совместим с minisign/signify:
comment-line + base64(alg "Ed" + keyid(8) + sig(64)), далее trusted comment
и base64(global_sig + comment). Верификатор из этого файла встроен в
install.sh между маркерами #@np-verify-begin/end — правки сюда обязаны
переноситься туда (тест test_install_sh_embeds_verifier_markers ловит
расползание, crypto-эквивалентность покрывает e2e-сценарий docker-e2e.sh).

Ключ подписи — maintainer-секрет: хранить офлайн, в репозиторий не коммитить
(файл в .gitignore). Публичный ключ (keyid + pubkey) зашит в install.sh —
это trust anchor: подмена релиза чужим ключом невозможна без коммита.

Usage:
  python3 tools/release_sign.py keygen --secret naivepanel-release.sec
  python3 tools/release_sign.py sign --secret naivepanel-release.sec \
      --data SHA256SUMS [--out SHA256SUMS.minisig]
  python3 tools/release_sign.py verify --data SHA256SUMS \
      --sig SHA256SUMS.minisig --keyid <hex> --pubkey <hex>
  python3 tools/release_sign.py verify-repo          # ключ из install.sh
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import secrets
import sys
import time
from dataclasses import dataclass
from pathlib import Path

# --- Ed25519 (RFC 8032, reference implementation) ----------------------------

_Q = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _Q - 2, _Q) % _Q
_I = pow(2, (_Q - 1) // 4, _Q)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * pow(_D * y * y + 1, _Q - 2, _Q) % _Q
    x = pow(xx, (_Q + 3) // 8, _Q)
    if (x * x - xx) % _Q != 0:
        x = (x * _I) % _Q
    if x % 2 != 0:
        x = _Q - x
    return x


_BY = 4 * pow(5, _Q - 2, _Q) % _Q
_B = (_xrecover(_BY), _BY)
_IDENTITY = (0, 1)


def _edwards(p: tuple[int, int], q: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = p
    x2, y2 = q
    x3 = (x1 * y2 + x2 * y1) * pow(1 + _D * x1 * x2 * y1 * y2, _Q - 2, _Q) % _Q
    y3 = (y1 * y2 + x1 * x2) * pow(1 - _D * x1 * x2 * y1 * y2, _Q - 2, _Q) % _Q
    return (x3, y3)


def _scalarmult(p: tuple[int, int], e: int) -> tuple[int, int]:
    q = _IDENTITY
    while e > 0:
        if e & 1:
            q = _edwards(q, p)
        p = _edwards(p, p)
        e >>= 1
    return q


def _encodeint(y: int) -> bytes:
    return y.to_bytes(32, "little")


def _encodepoint(p: tuple[int, int]) -> bytes:
    x, y = p
    bits = bytearray(_encodeint(y))
    bits[31] |= (x & 1) << 7
    return bytes(bits)


def _bit(h: bytes, i: int) -> int:
    return (h[i // 8] >> (i % 8)) & 1


def _secret_scalar(seed: bytes) -> tuple[int, bytes]:
    h = hashlib.sha512(seed).digest()
    a = 2**254 + sum(2**i * _bit(h, i) for i in range(3, 254))
    return a, h[32:]


def publickey(seed: bytes) -> bytes:
    a, _ = _secret_scalar(seed)
    return _encodepoint(_scalarmult(_B, a))


def _hint(m: bytes) -> int:
    return int.from_bytes(hashlib.sha512(m).digest(), "little")


def signature(m: bytes, seed: bytes, pk: bytes) -> bytes:
    a, prefix = _secret_scalar(seed)
    r = _hint(prefix + m)
    rp = _encodepoint(_scalarmult(_B, r))
    s = (r + _hint(rp + pk + m) * a) % _L
    return rp + _encodeint(s)


def _isoncurve(p: tuple[int, int]) -> bool:
    x, y = p
    return (-x * x + y * y - 1 - _D * x * x * y * y) % _Q == 0


def _decodepoint(s: bytes) -> tuple[int, int]:
    y = int.from_bytes(s, "little") & ((1 << 255) - 1)
    x = _xrecover(y)
    if x & 1 != _bit(s, 255):
        x = _Q - x
    p = (x, y)
    if not _isoncurve(p):
        raise ValueError("point is not on curve")
    return p


def checkvalid(sig: bytes, m: bytes, pk: bytes) -> bool:
    """Ed25519 verify; ValueError на некорректных точках/длинах."""
    if len(sig) != 64 or len(pk) != 32:
        raise ValueError("bad signature or key length")
    r = _decodepoint(sig[:32])
    a = _decodepoint(pk)
    s = int.from_bytes(sig[32:], "little")
    h = _hint(sig[:32] + pk + m)
    return _scalarmult(_B, s) == _edwards(r, _scalarmult(a, h))


# --- Формат minisign/signify ---------------------------------------------------

_SIG_ALGORITHM = b"Ed"


@dataclass
class KeyPair:
    key_id: str          # 16 hex — случайный идентификатор ключа (как minisign)
    pub_key: str         # 64 hex — Ed25519 public key
    secret_path: Path


def _load_secret(path: Path) -> tuple[bytes, bytes, str]:
    """secret-файл: простые строки hex; sec = seed(32) || pub(32)."""
    fields = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            fields[k.strip()] = v.strip()
    try:
        seed = bytes.fromhex(fields["sec"])[:32]
        pub = bytes.fromhex(fields["pub"])
        key_id = fields["keyid"]
    except (KeyError, ValueError) as exc:
        raise ValueError(f"bad secret key file {path}: {exc}") from exc
    if len(seed) != 32 or len(pub) != 32 or len(key_id) != 16:
        raise ValueError(f"bad secret key file {path}")
    return seed, pub, key_id


def keygen(secret_path: Path, force: bool = False) -> KeyPair:
    if secret_path.exists() and not force:
        raise SystemExit(f"{secret_path} exists — refuse to overwrite "
                         "(use --force or choose another path)")
    secret_path.parent.mkdir(parents=True, exist_ok=True)
    seed = secrets.token_bytes(32)
    pub = publickey(seed)
    key_id = secrets.token_bytes(8).hex()
    secret_path.write_text(
        "# NaivePanel release signing key — KEEP OFFLINE, never commit\n"
        f"keyid: {key_id}\n"
        f"pub: {pub.hex()}\n"
        f"sec: {(seed + pub).hex()}\n", encoding="utf-8")
    secret_path.chmod(0o600)
    return KeyPair(key_id=key_id, pub_key=pub.hex(), secret_path=secret_path)


def sign(data: Path, secret_path: Path, out: Path | None = None) -> Path:
    seed, pub, key_id = _load_secret(secret_path)
    msg = data.read_bytes()
    sig = signature(msg, seed, pub)
    # global signature over (sig || trusted_comment) — как в minisign
    comment = f"timestamp:{int(time.time())}\tfile:{data.name}".encode()
    gsig = signature(sig + comment, seed, pub)
    blob = _SIG_ALGORITHM + bytes.fromhex(key_id) + sig
    out = out or data.with_name(data.name + ".minisig")
    out.write_text(
        "untrusted comment: signature from naivepanel-release-sign\n"
        + base64.b64encode(blob).decode() + "\n"
        + "trusted comment: " + comment.decode() + "\n"
        + base64.b64encode(gsig + comment).decode() + "\n",
        encoding="utf-8")
    return out


def _parse_minisig(sig_path: Path) -> tuple[bytes, bytes, bytes]:
    """.minisig → (key_id, signature, trusted_comment_blob)."""
    lines = sig_path.read_text(encoding="utf-8").splitlines()
    if len(lines) < 2 or not lines[0].startswith("untrusted comment:"):
        raise ValueError(f"{sig_path}: not a minisign signature")
    try:
        blob = base64.b64decode(lines[1], validate=True)
    except Exception as exc:
        raise ValueError(f"{sig_path}: bad base64") from exc
    if blob[:2] != _SIG_ALGORITHM:
        raise ValueError(f"{sig_path}: unsupported algorithm")
    if len(blob) != 74:
        raise ValueError(f"{sig_path}: bad signature blob length")
    trusted = b""
    if len(lines) >= 4 and lines[2].startswith("trusted comment:"):
        try:
            trusted = base64.b64decode(lines[3], validate=True)
        except Exception:
            trusted = b""
    return blob[2:10], blob[10:], trusted


def verify(data: Path, sig_path: Path, key_id: str, pub_key: str) -> bool:
    """True/False на валидной структуре; ValueError на битом формате."""
    sig_key_id, sig, _trusted = _parse_minisig(sig_path)
    if sig_key_id.hex() != key_id.lower():
        return False
    return checkvalid(sig, data.read_bytes(), bytes.fromhex(pub_key))


# --- Ключ из install.sh + CLI ---------------------------------------------------

def key_from_install_sh(install_sh: Path) -> tuple[str, str]:
    src = install_sh.read_text(encoding="utf-8")
    key_id = re_search(r'^NP_SIGN_KEYID="([0-9a-f]{16})"', src)
    pub = re_search(r'^NP_SIGN_PUBKEY="([0-9a-f]{64})"', src)
    if key_id is None or pub is None:
        raise ValueError(f"{install_sh}: NP_SIGN_KEYID/NP_SIGN_PUBKEY not found")
    return key_id, pub


def re_search(pattern: str, src: str) -> str | None:
    import re
    m = re.search(pattern, src, re.M)
    return m.group(1) if m else None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    kg = sub.add_parser("keygen", help="сгенерировать ключевую пару")
    kg.add_argument("--secret", type=Path, required=True)
    kg.add_argument("--force", action="store_true")

    sg = sub.add_parser("sign", help="подписать файл (minisign-формат)")
    sg.add_argument("--secret", type=Path, required=True)
    sg.add_argument("--data", type=Path, required=True)
    sg.add_argument("--out", type=Path)

    vf = sub.add_parser("verify", help="проверить подпись")
    vf.add_argument("--data", type=Path, required=True)
    vf.add_argument("--sig", type=Path, required=True)
    vf.add_argument("--keyid", required=True)
    vf.add_argument("--pubkey", required=True)

    vr = sub.add_parser("verify-repo",
                        help="проверить SHA256SUMS.minisig ключом из install.sh")
    vr.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])

    args = ap.parse_args(argv)
    if args.cmd == "keygen":
        kp = keygen(args.secret, force=args.force)
        print(f"keyid: {kp.key_id}\npub:   {kp.pub_key}\n"
              f"secret: {kp.secret_path} (chmod 600, keep offline)")
    elif args.cmd == "sign":
        out = sign(args.data, args.secret, args.out)
        print(out)
    elif args.cmd == "verify":
        ok = verify(args.data, args.sig, args.keyid, args.pubkey)
        print("OK" if ok else "FAIL")
        return 0 if ok else 1
    elif args.cmd == "verify-repo":
        key_id, pub = key_from_install_sh(args.root / "install.sh")
        ok = verify(args.root / "SHA256SUMS",
                    args.root / "SHA256SUMS.minisig", key_id, pub)
        print("OK" if ok else "FAIL")
        return 0 if ok else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
