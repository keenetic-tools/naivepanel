# Self-update Resilience Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make panel self-update record installer failures reliably, recover immediately after router reboot, provide an explicit retry UI, and cover the real flow with Entware E2E.

**Architecture:** A single daemon waiter owns each installer `Popen.wait()` and conditionally writes terminal state under the existing launch lock. State remains atomic and backward-compatible, gains `boot_id`/`exit_code`, and uses non-destructive PID checks only as a restart fallback. The existing native dialog receives compact status/error presentation and a checked manual retry; the real signed update path is tested in Docker with a temporary test key.

**Tech Stack:** Python 3.10+, Flask, stdlib threading/subprocess, vanilla JS/CSS, native `<dialog>`, pytest, shell/Docker Entware E2E.

Design and decisions: `docs/plans/2026-11-22-self-update-resilience-design.md`.

---

### Task 1: Installer waiter and terminal failure state

**Files:**
- Modify: `panel/updates.py` around `_UPDATE_LAUNCH_LOCK`, `_pid_alive`, `_update_state`
- Modify: `panel/app.py` around `api_update_apply`
- Test: `tests/test_naivepanel.py` self-update state/apply tests

**Step 1: Write failing waiter tests**

Add tests which create real short-lived `Popen` wrappers and assert:

```python
def test_update_waiter_records_exit_code(app):
    started = time.time()
    proc = subprocess.Popen(["/bin/sh", "-c", "exit 3"])
    app._update_state_write({"phase": "running", "target": "v9.9.9",
                             "started": started, "pid": proc.pid})
    app._start_update_waiter(proc, "v9.9.9", started)
    deadline = time.time() + 5
    while time.time() < deadline:
        st = app._update_state_read()
        if st.get("phase") == "failed":
            break
        time.sleep(0.02)
    assert st["exit_code"] == 3
    assert st["finished"] >= started
    assert "code 3" in st["error"]
```

Also test that a waiter with an old `started`/`pid` does not overwrite a newer running state, and that `api_update_apply` returns the persisted timestamp as `attempt_started` together with the same `pid`.

**Step 2: Run tests to verify they fail**

Run: `./.venv/bin/python -m pytest -q tests/test_naivepanel.py -k 'update_waiter or apply_returns_attempt'`
Expected: FAIL because `_start_update_waiter` and the response fields do not exist.

**Step 3: Implement the minimal waiter**

In `panel/updates.py`:

- Change `_UPDATE_LAUNCH_LOCK` to `threading.RLock()`.
- Protect `_update_state()` reconciliation with that lock.
- Add `_start_update_waiter(proc, target, started)`. The waiter calls only
  `proc.wait()`, re-reads state under the lock, and on nonzero rc writes
  `failed` only when `phase`, `pid`, and `started` still match.
- Include `finished`, numeric `exit_code`, and `error="installer exited with code N"`.
- Leave state `running` on rc 0; the restarted target version owns `done`.

In `panel/app.py`:

- Persist `started = time.time()` once and reuse it.
- Start the waiter after the running state write, while still under the lock.
  Register `(pid, started)` before starting its thread so polling cannot win
  the zombie race and discard the real exit status.
- Make the shell wrapper end in `exit "$rc"`; otherwise its final `echo`
  masks a failed installer with status zero.
- Return `started: true`, `attempt_started`, and `pid` in the 202 JSON.

**Step 4: Run waiter and existing update tests**

Run: `./.venv/bin/python -m pytest -q tests/test_naivepanel.py -k 'update_state or update_waiter or apply_'`
Expected: PASS; no zombie remains after the real waiter tests.

**Step 5: Commit only if requested**

```bash
git add panel/updates.py panel/app.py tests/test_naivepanel.py
git commit -m "fix(updates): record installer exit status with waiter"
```

---

### Task 2: Non-destructive PID checks, boot recovery, durable state

**Files:**
- Modify: `panel/updates.py`
- Test: `tests/test_naivepanel.py`
- Test: `tests/test_naivepanel.py::test_update_state_marks_failed_when_installer_zombie`

**Step 1: Replace/extend tests with reboot and legacy cases**

Write failing tests for:

```python
def test_update_state_reboot_does_not_trust_reused_pid(app, monkeypatch):
    monkeypatch.setattr(app.upd, "_boot_id", lambda: "new-boot")
    app._update_state_write({"phase": "running", "target": "v9.9.9",
                             "started": time.time(), "pid": os.getpid(),
                             "boot_id": "old-boot"})
    st = app._update_state()
    assert st["phase"] == "failed"
    assert "reboot" in st["error"]
```

Cover target==current => `done` even with another boot ID, absent boot IDs => legacy behavior, and a non-child zombie through a mocked `/proc/<pid>/stat` containing `) Z `. Adjust the old own-zombie test: the waiter, not `_pid_alive`, owns child reaping.

**Step 2: Run tests to verify they fail**

Run: `./.venv/bin/python -m pytest -q tests/test_naivepanel.py -k 'reboot or legacy or zombie'`
Expected: FAIL because boot ID is not stored or reconciled.

**Step 3: Implement boot recovery and non-destructive checks**

- Add `_boot_id()` reading `/proc/sys/kernel/random/boot_id`, returning `None` on
  `OSError` or empty content.
- Store `boot_id` in newly launched state.
- In `_update_state`, preserve target==current first; then differing non-null boot
  IDs => `failed` with `error="update interrupted by router reboot"` and
  `finished`, without consulting PID.
- Remove `os.waitpid` from `_pid_alive`; parse `/proc/<pid>/stat` first and use
  `os.kill(pid, 0)` only if procfs is unavailable.
- After `_save_json(cfg.UPDATE_STATE, st)`, fsync `cfg.UPDATE_STATE.parent` via
  a directory fd where supported, inside the existing `OSError` handling.

**Step 4: Run all self-update tests**

Run: `./.venv/bin/python -m pytest -q tests/test_naivepanel.py -k 'update_state or update_waiter or apply_'`
Expected: PASS, including reboot with a live reused PID.

**Step 5: Commit only if requested**

```bash
git add panel/updates.py panel/app.py tests/test_naivepanel.py
git commit -m "fix(updates): recover interrupted updates after reboot"
```

---

### Task 3: Focused update dialog and checked manual retry

**Files:**
- Modify: `templates/index.html` `updDlg`
- Modify: `panel/static/styles.css` dialog rules
- Modify: `panel/static/app.js` `checkUpdate`, `applyUpdate`, `renderUpdLog`, naive/rollback reset paths
- Test: `tests/test_naivepanel.py` UI contract tests

**Step 1: Add failing UI contract tests**

Assert the dialog has a labelled title, error block, installer/panel `<details>`,
and a retry action. Assert JS matches `pid`/`attempt_started` from the apply
response against `pid`/`started` in state before accepting failed state and
calls the release check without automatic apply. Include naive and
rollback markers proving their existing flow remains present.

**Step 2: Run UI contract tests**

Run: `./.venv/bin/python -m pytest -q tests/test_naivepanel.py -k 'ui_has_update or update_retry'`
Expected: FAIL on missing retry/status elements.

**Step 3: Implement the dialog and state flow**

- Add a semantic heading/status area, compact error text, collapsible logs, and
  a retry button using existing design tokens and native `<details>`.
- Split release checking from retry application so the retry action first awaits
  `checkUpdate(true)`, never applies stale `upd`, and requires normal confirmation.
- Preserve the automatic check after failure. While checking, disable retry and
  show `Проверяю релиз…`; on failure offer another check, not stale apply.
- Accept failed state only when both `pid` and state `started` match the current
  apply response's `pid` and `attempt_started`.
- Render `exit_code`/`error` with `textContent`; keep all log content text-only.
- Reset all panel-only controls for naive and rollback uses of the shared dialog.
- Keep keyboard focus, >=44px mobile targets, bounded log height, and no horizontal
  overflow. Do not redesign unrelated cards.

**Step 4: Run contract tests and JS syntax**

Run: `./.venv/bin/python -m pytest -q tests/test_naivepanel.py -k 'ui or update_naive or rollback'`
Run: `node --check panel/static/app.js`
Expected: PASS and exit 0.

**Step 5: Browser-check the real states**

Run the panel with isolated paths. Exercise running, failed, retry-check,
check-error, naive update, and rollback dialog states. Capture 390px and 1440px
in dark/light; verify keyboard summary/details operation, focus return, and no
horizontal scroll. Save only temporary screenshots under `tmp/shots/` and remove
artifacts not needed by the task.

**Step 6: Commit only if requested**

```bash
git add templates/index.html panel/static/app.js panel/static/styles.css tests/test_naivepanel.py docs/UI-GUIDELINES.md
git commit -m "feat(ui): add clear self-update failure and retry flow"
```

---

### Task 4: Real self-update failure/retry in Docker Entware E2E

**Files:**
- Modify: `docker-e2e.sh`
- Modify: `.github/workflows/e2e.yml` only if comments/name need clarification
- Modify: `README.md` development/release instructions

**Step 1: Add an E2E failure expectation before implementation**

Extend the generated entrypoint so it requires `failed` and `exit_code=3` after
the first real `/api/update/apply`, then requires a 202 retry and target version
after the second. Run it against the old script to confirm the new checks fail
because the scenario/fields are absent.

**Step 2: Build an isolated signed next release**

- Serve static fake GitHub release/tag JSON through the existing local HTTPS
  server and point `NAIVEPANEL_UPDATE_API` at it.
- Copy the working release to a test-only next tag, change only the served
  `APP_VERSION`, regenerate sums for both served releases, and sign both with
  a temporary key from `tools/release_sign.py` (working files can differ from
  the last published signature).
- Patch only the served installers to trust that temporary public key; never
  change repository sums/signature or use the real release key.
- Inject a one-shot `exit 3` before file changes; the second attempt must execute
  the real installer and signature verification.
- Poll panel down/up and assert the served target version and final `done` state.

**Step 3: Add a real non-child zombie Linux check**

Start a helper Python parent which spawns a short-lived child and remains alive
without waiting. From a different Python process call `_pid_alive(child_pid)` and
require `False` via `/proc`. Terminate/reap the helper during cleanup.

**Step 4: Run the full E2E**

Run: `./docker-e2e.sh`
Expected: previous install/API/naive checks still pass, first self-update fails
with exit 3, retry succeeds, target version is active, non-child zombie is dead,
and the final marker is `==> E2E DONE`.

**Step 5: Document pre-tag execution**

Document running `e2e.yml` through `workflow_dispatch` on the release candidate
and waiting for success before tagging. Keep existing tag and nightly triggers.

**Step 6: Commit only if requested**

```bash
git add docker-e2e.sh .github/workflows/e2e.yml README.md tests/test_naivepanel.py
git commit -m "test(e2e): cover self-update failure retry and reboot primitives"
```

---

### Task 5: Documentation, roadmap, and full verification

**Files:**
- Modify: `README.md`
- Modify: `docs/UI-GUIDELINES.md`
- Modify: `docs/ROADMAP.md`
- Reference: `docs/plans/2026-11-22-self-update-resilience-design.md`

**Step 1: Update behavior documentation**

Describe waiter-owned exit status, new 202/state fields, boot-ID recovery,
manual retry UI, and the explicit limitation that power loss during the current
multi-file copy can still require SSH recovery.

**Step 2: Record future projects in ROADMAP**

Add P1 power-loss-safe installation as an independent reliability project and a
future full UI redesign as a separate design project. Do not mark either done.

**Step 3: Run the complete local gate**

```bash
./.venv/bin/python -m pytest -q
./.venv/bin/ruff check .
./.venv/bin/bandit -q -ll -r naivepanel.py panel
sh -n install.sh S99naiveproxy S99naivepanel docker-e2e.sh
node --check panel/static/app.js
shasum -a 256 -c SHA256SUMS
git diff --check
```

Expected: all tests pass; static checks exit 0. If release files changed, refresh
`SHA256SUMS` and its signature only with the maintainer's explicit instruction.

**Step 4: Run the final Docker and UI gate**

Run `./docker-e2e.sh` after all changes, inspect the full output, and repeat the
browser matrix from Task 3. Check `git status --short`; remove only temporary
artifacts created by this implementation.

**Step 5: Review and report**

Compare the final diff against the approved design, list exact verification and
any remaining limitation. Do not tag, publish, push, or edit GitHub releases
without a separate explicit request.

**Step 6: Commit only if requested**

```bash
git add README.md docs/UI-GUIDELINES.md docs/ROADMAP.md docs/plans/2026-11-22-self-update-resilience-design.md docs/plans/2026-11-22-self-update-resilience-implementation-plan.md
git commit -m "docs: record update resilience and future design work"
```
