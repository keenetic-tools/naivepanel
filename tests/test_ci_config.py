"""Мета-тесты CI и release-артефактов (Task 16).

Проверяют не код панели, а гейты вокруг него: pinned-зависимости, матрицу
Python, обязательные проверки, отсутствие «мягких» продолжений и целостность
SHA256SUMS. Так конфигурация не может тихо деградировать без падения тестов.
"""
import hashlib
import re
from pathlib import Path

APP_DIR = Path(__file__).resolve().parents[1]
WORKFLOWS = APP_DIR / ".github" / "workflows"

USES_RE = re.compile(r"^\s*-\s+uses:\s*(\S+)", re.MULTILINE)
PIN_RE = re.compile(r"^[^\s@]+@[0-9a-f]{40}$")


def _workflow(name: str) -> str:
    return (WORKFLOWS / name).read_text(encoding="utf-8")


def _pins(path: Path) -> list[tuple[str, str]]:
    """Возвращает (package, constraint) из requirements-файла без маркеров."""
    pins: list[tuple[str, str]] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-r ", "--")):
            continue
        name, _, constraint = line.partition(";")[0].partition("==")
        if constraint:
            pins.append((name.strip(), "==" + constraint.strip()))
    return pins


def test_workflows_use_only_pinned_actions():
    for name in ("ci.yml", "e2e.yml"):
        uses = USES_RE.findall(_workflow(name))
        assert uses, f"{name}: no actions found"
        for ref in uses:
            assert PIN_RE.match(ref), f"{name}: action not pinned by SHA: {ref}"


def test_ci_has_required_matrix_and_gates():
    ci = _workflow("ci.yml")
    assert '["3.10", "3.11", "3.12", "3.13"]' in ci
    # мягкое продолжение допустимо только как YAML-ключ с true
    assert not re.search(r"^\s*continue-on-error\s*:\s*true", ci, re.MULTILINE)
    assert "python -m pytest -q" in ci
    assert "ruff check ." in ci
    assert "bandit -q -ll -r naivepanel.py panel" in ci
    assert "pip-audit -r requirements-runtime.txt --strict" in ci


def test_ci_shellcheck_covers_all_release_scripts():
    ci = _workflow("ci.yml")
    shellcheck_line = next(
        (line for line in ci.splitlines()
         if line.strip().startswith("shellcheck ") and "install.sh" in line),
        "",
    )
    for script in ("install.sh", "S99naiveproxy", "S99naivepanel", "docker-e2e.sh"):
        assert script in shellcheck_line, f"ShellCheck does not cover {script}"


def test_e2e_runs_nightly_and_on_tags():
    e2e = _workflow("e2e.yml")
    assert "schedule:" in e2e and "workflow_dispatch:" in e2e
    assert "tags:" in e2e
    assert "./docker-e2e.sh" in e2e


def test_docker_e2e_ships_panel_package_and_is_arch_aware():
    script = (APP_DIR / "docker-e2e.sh").read_text(encoding="utf-8")
    # Без panel/ установка с Entware падает: install.sh тянет модули пакета.
    assert 'cp "$REPO_DIR"/panel/*.py "$WWW/panel/"' in script
    # c0f2715: x86_64-фид Entware — x64-k3.2 (x86-64 в фиде отсутствует)
    assert 'x86_64|amd64)  ENTWARE_ARCH=x64-k3.2' in script
    assert 'aarch64) ENTWARE_ARCH=aarch64-k3.10' in script
    assert 'bin.entware.net/$ENTWARE_ARCH/' in script


def test_dev_and_runtime_dependencies_are_exactly_pinned():
    runtime = dict(_pins(APP_DIR / "requirements-runtime.txt"))
    dev = dict(_pins(APP_DIR / "requirements-dev.txt"))
    for package in ("Flask", "Werkzeug", "waitress", "bcrypt"):
        assert package in runtime, f"runtime pin missing: {package}"
    for package in ("pytest", "ruff", "bandit", "pip-audit"):
        assert package in dev, f"dev pin missing: {package}"
    assert "-r requirements-runtime.txt" in (APP_DIR / "requirements-dev.txt").read_text()


def test_sha256sums_matches_every_shipped_file():
    sums: dict[str, str] = {}
    for line in (APP_DIR / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        digest, name = line.split(maxsplit=1)
        sums[name] = digest

    shipped = [
        "S99naivepanel",
        "S99naiveproxy",
        "naivepanel.py",
        "templates/index.html",
        *(f"panel/{p.name}" for p in sorted((APP_DIR / "panel").glob("*.py"))),
    ]
    assert set(sums) == set(shipped), "SHA256SUMS covers a different file set"
    for name in shipped:
        actual = hashlib.sha256((APP_DIR / name).read_bytes()).hexdigest()
        assert sums[name] == actual, f"SHA256SUMS stale for {name}"
