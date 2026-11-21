"""Тесты подписи релизов (SEC-07, Task 18).

Каноническая криптография — tools/release_sign.py (stdlib-only Ed25519,
RFC 8032): keygen → sign → verify, негативы (подмена данных, чужой ключ,
битая подпись, чужой keyid) и формат minisign (проверка структуры файла).
install.sh встраивает ту же verify-логику хердоком — маркеры
#@np-verify-begin/end гарантируют, что встраиваемый блок не расползся.
"""
import importlib.util
import re
import subprocess
from pathlib import Path

import pytest

APP_DIR = Path(__file__).resolve().parents[1]


def _tool():
    spec = importlib.util.spec_from_file_location(
        "release_sign", APP_DIR / "tools" / "release_sign.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


rs = pytest.importorskip("sys") and _tool()


@pytest.fixture()
def keypair(tmp_path):
    sk = tmp_path / "release.sec"
    kp = rs.keygen(sk)
    assert sk.exists()
    return kp


def test_keygen_sign_verify_roundtrip(keypair, tmp_path):
    data = tmp_path / "SHA256SUMS"
    data.write_text("aa  file1\nbb  file2\n", encoding="utf-8")
    sig = rs.sign(data, keypair.secret_path, tmp_path / "SHA256SUMS.minisig")
    assert rs.verify(data, sig, keypair.key_id, keypair.pub_key)
    # криптоподпись детерминирована (Ed25519): blob строки 2 совпадает;
    # файлы целиком могут отличаться — trusted comment несёт timestamp
    sig2 = rs.sign(data, keypair.secret_path, tmp_path / "again.minisig")
    assert sig.read_text().splitlines()[1] == sig2.read_text().splitlines()[1]


def test_verify_rejects_tampered_data(keypair, tmp_path):
    data = tmp_path / "SHA256SUMS"
    data.write_text("aa  file1\n", encoding="utf-8")
    sig = rs.sign(data, keypair.secret_path)
    data.write_text("AA  file1\n", encoding="utf-8")
    assert not rs.verify(data, sig, keypair.key_id, keypair.pub_key)


def test_verify_rejects_wrong_key_and_keyid(keypair, tmp_path):
    data = tmp_path / "SHA256SUMS"
    data.write_text("aa  file1\n", encoding="utf-8")
    sig = rs.sign(data, keypair.secret_path)
    other = rs.keygen(tmp_path / "other.sec")
    assert not rs.verify(data, sig, other.key_id, other.pub_key)
    # верный ключ, чужой keyid — minisign-файл не примет чужую подпись
    assert not rs.verify(data, sig, other.key_id, keypair.pub_key)


def test_verify_rejects_garbage_sig(keypair, tmp_path):
    data = tmp_path / "SHA256SUMS"
    data.write_text("aa  file1\n", encoding="utf-8")
    sig = tmp_path / "bad.minisig"
    sig.write_text("untrusted comment: x\nAAAA\n", encoding="utf-8")
    with pytest.raises((ValueError, subprocess.CalledProcessError)):
        rs.verify(data, sig, keypair.key_id, keypair.pub_key)


def test_minisig_file_format(keypair, tmp_path):
    """Структура .minisig совместима с minisign: comment-line + base64 blob."""
    import base64
    data = tmp_path / "SHA256SUMS"
    data.write_text("aa  file1\n", encoding="utf-8")
    sig = rs.sign(data, keypair.secret_path)
    lines = sig.read_text(encoding="utf-8").splitlines()
    assert lines[0].startswith("untrusted comment: ")
    blob = base64.b64decode(lines[1])
    assert blob[:2] == b"Ed"                    # алгоритм Ed25519
    assert blob[2:10].hex() == keypair.key_id   # key id ключа подписанта
    assert len(blob) == 74                      # 2 alg + 8 keyid + 64 sig
    assert lines[2].startswith("trusted comment: ")
    base64.b64decode(lines[3])                  # global sig + comment


def test_cli_verify_matches_embedded_key():
    """Коммиченная подпись репозитория сходится с ключом, зашитым в install.sh."""
    key_id, pub = rs.key_from_install_sh(APP_DIR / "install.sh")
    assert rs.verify(APP_DIR / "SHA256SUMS",
                     APP_DIR / "SHA256SUMS.minisig", key_id, pub)


def test_install_sh_embeds_verifier_markers():
    src = (APP_DIR / "install.sh").read_text(encoding="utf-8")
    assert "#@np-verify-begin" in src and "#@np-verify-end" in src
    # извлечённый блок — валидный python (встраиваемый верификатор)
    block = re.search(r"#@np-verify-begin\n(.*?)#@np-verify-end", src, re.S)
    assert block, "маркеры верификатора не найдены"
    compile(block.group(1), "npverify.py", "exec")
    # подпись обязательна: fetch .minisig и fail-closed
    assert 'fetch "$BASE/SHA256SUMS.minisig"' in src
    assert "release signature verification failed" in src
