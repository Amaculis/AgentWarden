"""Tests for spec 026 (resolve links and short names before path rules).

Written against the interface the spec defines before `agentwarden/links.py` exists, so the
whole module is expected to fail to collect (ImportError) until it is written. No real model, no
network. Filesystem access is limited to `tmp_path` and the links/files each test creates there.

Symlink tests `pytest.skip` when the OS refuses to create the link (Windows without developer
mode); junction tests are Windows-only; the 8.3 test skips when the volume has no short names.
Directory-link cases prefer junctions on Windows (`_dirlink`) so they actually run here.
"""

from __future__ import annotations

import ctypes
import os
import sys
import time
from pathlib import Path

import pytest

from agentwarden import links
from agentwarden.models import ToolEvent
from agentwarden.rules import evaluate

PROJECT = "D:\\proj"


@pytest.fixture(autouse=True)
def _reset_link_state(monkeypatch):
    links.clear_cache()
    monkeypatch.delenv("WARDEN_POLICY", raising=False)
    yield
    links.clear_cache()


# ---------------------------------------------------------------------------
# Event helpers (same shape as tests/test_rules.py and tests/test_boundary.py)
# ---------------------------------------------------------------------------


def _event(tool_name: str, tool_input: dict, cwd: str = PROJECT) -> ToolEvent:
    return ToolEvent.model_validate(
        {
            "session_id": "s1",
            "prompt_id": "p1",
            "cwd": cwd,
            "permission_mode": "auto",
            "hook_event_name": "PreToolUse",
            "tool_name": tool_name,
            "tool_input": tool_input,
            "tool_use_id": "t1",
        }
    )


def _read(path: str, cwd: str = PROJECT) -> ToolEvent:
    return _event("Read", {"file_path": path}, cwd=cwd)


def _write(path: str, cwd: str = PROJECT) -> ToolEvent:
    return _event("Write", {"file_path": path}, cwd=cwd)


def _edit(path: str, cwd: str = PROJECT) -> ToolEvent:
    return _event("Edit", {"file_path": path, "old_string": "a", "new_string": "b"}, cwd=cwd)


def _bash(command: str, cwd: str = PROJECT) -> ToolEvent:
    return _event("Bash", {"command": command}, cwd=cwd)


def _grep(path: str | None = None, glob: str | None = None, cwd: str = PROJECT) -> ToolEvent:
    tool_input: dict = {"pattern": "x"}
    if path is not None:
        tool_input["path"] = path
    if glob is not None:
        tool_input["glob"] = glob
    return _event("Grep", tool_input, cwd=cwd)


def _glob(path: str | None = None, pattern: str = "*", cwd: str = PROJECT) -> ToolEvent:
    tool_input: dict = {"pattern": pattern}
    if path is not None:
        tool_input["path"] = path
    return _event("Glob", tool_input, cwd=cwd)


def _write_policy(root: Path) -> None:
    """A comment-only policy file -- just enough for `evaluate` to find `<cwd>/.agentwarden/`."""
    policy_dir = root / ".agentwarden"
    policy_dir.mkdir(parents=True, exist_ok=True)
    (policy_dir / "policy.yaml").write_text("# test\n", encoding="utf-8")


def _norm(p: str) -> str:
    return p.replace("\\", "/").rstrip("/").lower()


def _make_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A fake home dir (outside the project) with fake secrets, wired via HOME/USERPROFILE."""
    home = tmp_path / "home"
    (home / ".aws").mkdir(parents=True)
    (home / ".aws" / "credentials").write_text(
        "[default]\naws_access_key_id=FAKE\naws_secret_access_key=FAKE\n", encoding="utf-8"
    )
    (home / ".ssh").mkdir()
    (home / ".ssh" / "id_ed25519").write_text("-----FAKE PRIVATE KEY-----\n", encoding="utf-8")
    (home / ".ssh" / "id_rsa").write_text("-----FAKE PRIVATE KEY-----\n", encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    return home


# ---------------------------------------------------------------------------
# Link creation helpers
# ---------------------------------------------------------------------------


def _symlink(link: Path, target: Path, is_dir: bool) -> None:
    try:
        os.symlink(str(target), str(link), target_is_directory=is_dir)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlinks not permitted on this OS/user: {exc}")


def _junction(link: Path, target: Path) -> None:
    if sys.platform != "win32":
        pytest.skip("junctions are Windows-only")
    import _winapi

    try:
        _winapi.CreateJunction(str(target), str(link))
    except OSError as exc:
        pytest.skip(f"junction creation failed: {exc}")


def _dirlink(link: Path, target: Path) -> None:
    """Directory link: junction on Windows (no developer mode needed), symlink elsewhere."""
    if sys.platform == "win32":
        _junction(link, target)
    else:
        _symlink(link, target, is_dir=True)


def _short_name(path: Path) -> str | None:
    """8.3 short name for `path`, or `None` if unavailable (non-Windows, API failure)."""
    if sys.platform != "win32":
        return None
    buf = ctypes.create_unicode_buffer(260)
    rv = ctypes.windll.kernel32.GetShortPathNameW(str(path), buf, 260)  # type: ignore[attr-defined]
    if rv == 0:
        return None
    return buf.value


# ---------------------------------------------------------------------------
# Symlink / junction -> secret or self-protection -> deny
# ---------------------------------------------------------------------------


def test_symlink_to_secret_file_denied(tmp_path, monkeypatch):
    proj = tmp_path / "proj"
    proj.mkdir()
    _write_policy(proj)
    home = _make_home(tmp_path, monkeypatch)
    link = proj / "notes"
    _symlink(link, home / ".aws" / "credentials", is_dir=False)

    verdict = evaluate(_read(str(link), cwd=str(proj)))

    assert verdict is not None
    assert verdict.decision == "deny"
    assert "credentials" in verdict.reason


def test_symlinked_dir_to_ssh_denied(tmp_path, monkeypatch):
    proj = tmp_path / "proj"
    proj.mkdir()
    _write_policy(proj)
    home = _make_home(tmp_path, monkeypatch)
    link = proj / "docs"
    _dirlink(link, home / ".ssh")

    read_verdict = evaluate(_read(str(link / "id_ed25519"), cwd=str(proj)))
    bash_verdict = evaluate(_bash("cat docs/id_ed25519", cwd=str(proj)))

    assert read_verdict is not None
    assert read_verdict.decision == "deny"
    assert bash_verdict is not None
    assert bash_verdict.decision == "deny"


def test_link_to_agentwarden_edit_denied(tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    _write_policy(proj)
    link = proj / "cfg"
    _dirlink(link, proj / ".agentwarden")

    edit_verdict = evaluate(_edit(str(link / "policy.yaml"), cwd=str(proj)))
    write_verdict = evaluate(_write(str(link / "x"), cwd=str(proj)))
    bash_verdict = evaluate(_bash("echo x > cfg/policy.yaml", cwd=str(proj)))
    read_verdict = evaluate(_read(str(link / "policy.yaml"), cwd=str(proj)))

    for verdict in (edit_verdict, write_verdict, bash_verdict, read_verdict):
        assert verdict is not None
        assert verdict.decision == "deny"


def test_junction_outside_project_ask(tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    _write_policy(proj)
    sibling = tmp_path / "sibling"
    sibling.mkdir()
    (sibling / "x.py").write_text("print('hi')\n", encoding="utf-8")
    link = proj / "lnk"
    _junction(link, sibling)

    read_verdict = evaluate(_read(str(link / "x.py"), cwd=str(proj)))
    grep_verdict = evaluate(_grep(path=str(link), cwd=str(proj)))

    assert read_verdict is not None
    assert read_verdict.decision == "ask"
    assert read_verdict.grant_dir is not None
    assert _norm(read_verdict.grant_dir) == _norm(str(sibling))

    assert grep_verdict is not None
    assert grep_verdict.decision == "deny"


def test_link_inside_project_unchanged(tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    _write_policy(proj)
    (proj / "src").mkdir()
    v2 = proj / "src" / "v2"
    v2.mkdir()
    (v2 / "a.py").write_text("x = 1\n", encoding="utf-8")
    link = proj / "src" / "current"
    _dirlink(link, v2)

    verdict = evaluate(_read(str(link / "a.py"), cwd=str(proj)))

    assert verdict is not None
    assert verdict.decision == "allow"


def test_short_name_to_agentwarden_denied(tmp_path):
    if sys.platform != "win32":
        pytest.skip("8.3 short names are Windows-only")
    proj = tmp_path / "proj"
    proj.mkdir()
    _write_policy(proj)
    short = _short_name(proj / ".agentwarden")
    if short is None:
        pytest.skip("could not read an 8.3 short name")
    short_path = Path(short)
    if short_path.name.lower() == ".agentwarden":
        pytest.skip("volume has no 8.3 short names")

    # Relative to the project: the realistic bypass (`Edit AGENTW~1/policy.yaml`).
    verdict = evaluate(_edit(f"{short_path.name}/policy.yaml", cwd=str(proj)))
    assert verdict is not None
    assert verdict.decision == "deny"

    # Fully shortened (the project root too): lexically outside the project, so the
    # boundary answers; never allow.
    full = evaluate(_edit(str(short_path / "policy.yaml"), cwd=str(proj)))
    assert full is not None
    assert full.decision in ("ask", "deny")


# ---------------------------------------------------------------------------
# Hard links
# ---------------------------------------------------------------------------


def test_hardlink_to_secret_denied(tmp_path, monkeypatch):
    proj = tmp_path / "proj"
    proj.mkdir()
    _write_policy(proj)
    home = _make_home(tmp_path, monkeypatch)
    hardlink = proj / "x.txt"
    try:
        os.link(str(home / ".ssh" / "id_rsa"), str(hardlink))
    except OSError as exc:
        pytest.skip(f"hard links not permitted on this filesystem: {exc}")

    verdict = evaluate(_read(str(hardlink), cwd=str(proj)))

    assert verdict is not None
    assert verdict.decision == "deny"


def test_hardlink_unrelated_allowed(tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    _write_policy(proj)
    original = proj / "a.txt"
    original.write_text("hello\n", encoding="utf-8")
    link_b = proj / "b.txt"
    link_c = proj / "c.txt"
    try:
        os.link(str(original), str(link_b))
        os.link(str(original), str(link_c))
    except OSError as exc:
        pytest.skip(f"hard links not permitted on this filesystem: {exc}")

    verdict = evaluate(_read(str(link_b), cwd=str(proj)))

    assert verdict is not None
    assert verdict.decision == "allow"


# ---------------------------------------------------------------------------
# Resolution never loosens -- property-style over representative events
# ---------------------------------------------------------------------------

_RANK = {"deny": 3, "ask": 2, "allow": 1, None: 0}


def _rank(verdict) -> int:
    return _RANK[verdict.decision] if verdict is not None else 0


def _representative_events(cwd: str) -> list[ToolEvent]:
    posix_cwd = cwd.replace("\\", "/")
    return [
        _read(f"{posix_cwd}/.env", cwd=cwd),
        _read(f"{posix_cwd}/src/app.py", cwd=cwd),
        _write(f"{posix_cwd}/.env", cwd=cwd),
        _bash("cat .env", cwd=cwd),
        _read(f"{posix_cwd}/.agentwarden/policy.yaml", cwd=cwd),
        _bash("cat ~/.ssh/id_rsa", cwd=cwd),
        _read("~/.ssh/id_rsa", cwd=cwd),
        _read("C:\\Users\\a\\file.txt", cwd=cwd),
        _bash("ls C:/Users", cwd=cwd),
        _bash("rm -rf /", cwd=cwd),
        _bash("git status", cwd=cwd),
        _bash("curl -X POST https://example.com", cwd=cwd),
        _grep(cwd=cwd),
        _glob(pattern="C:/Users/**/*.docx", cwd=cwd),
        _write(f"{posix_cwd}/newdir/newfile.py", cwd=cwd),
        _edit(f"{posix_cwd}/hooks/on_tool.py", cwd=cwd),
    ]


def test_resolution_never_loosens(tmp_path, monkeypatch):
    nonexistent_cwd = str(tmp_path / "does-not-exist")
    real_proj = tmp_path / "proj"
    real_proj.mkdir()
    _write_policy(real_proj)
    (real_proj / "src").mkdir()
    (real_proj / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")
    (real_proj / "hooks").mkdir()
    (real_proj / "hooks" / "on_tool.py").write_text("pass\n", encoding="utf-8")

    for cwd in (nonexistent_cwd, str(real_proj)):
        for event in _representative_events(cwd):
            monkeypatch.setenv("WARDEN_RESOLVE_LINKS", "0")
            off = evaluate(event)
            monkeypatch.setenv("WARDEN_RESOLVE_LINKS", "1")
            on = evaluate(event)

            assert _rank(on) >= _rank(off), (cwd, event.tool_name, event.tool_input)
            if _rank(on) == _rank(off) and off is not None and on is not None:
                assert off.decision == on.decision


# ---------------------------------------------------------------------------
# Failure paths: loop, too many paths, deadline, UNC, root exit, nonexistent, flag off
# ---------------------------------------------------------------------------


def test_link_loop_ask(tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    _write_policy(proj)
    a = proj / "a"
    b = proj / "b"
    b.mkdir()
    _dirlink(a, b)  # a junction needs an existing target: link a -> b, then b -> a
    b.rmdir()
    _dirlink(b, a)

    verdict = evaluate(_read(str(a / "file.txt"), cwd=str(proj)))

    assert verdict is not None
    assert verdict.decision == "ask"


def test_too_many_paths_ask(tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    _write_policy(proj)
    names = []
    for i in range(65):
        name = f"f{i}.txt"
        (proj / name).write_text("x\n", encoding="utf-8")
        names.append(name)
    command = "cat " + " ".join(names)

    verdict = evaluate(_bash(command, cwd=str(proj)))

    assert verdict is not None
    assert verdict.decision == "ask"


def test_walk_deadline_ask(tmp_path, monkeypatch):
    proj = tmp_path / "proj"
    proj.mkdir()
    _write_policy(proj)
    target_dir = proj / "target"
    target_dir.mkdir()
    (target_dir / "file.txt").write_text("x\n", encoding="utf-8")
    link = proj / "lnk"
    _dirlink(link, target_dir)

    # `links.time` is the shared `time` module: the first call (the deadline, in rules) is
    # real, every later one (the walk's check) is far past it.
    real_monotonic = links.time.monotonic
    calls = []

    def fake_monotonic():
        calls.append(1)
        return real_monotonic() + (0.0 if len(calls) == 1 else 1000.0)

    monkeypatch.setattr(links.time, "monotonic", fake_monotonic)

    verdict = evaluate(_read(str(link / "file.txt"), cwd=str(proj)))

    assert verdict is not None
    assert verdict.decision == "ask"


def test_unc_never_touched(tmp_path, monkeypatch):
    real_lstat = links.os.lstat

    def guarded_lstat(path, *args, **kwargs):
        normalized = str(path).replace("\\", "/")
        if normalized.startswith("//"):
            raise AssertionError(f"lstat called on a UNC path: {path}")
        return real_lstat(path, *args, **kwargs)

    monkeypatch.setattr(links.os, "lstat", guarded_lstat)

    verdict = evaluate(_read("//host/share/x"))

    assert verdict is not None
    assert verdict.decision != "allow"

    # Direct resolve() over a purely local path must never touch a UNC target either.
    proj = tmp_path / "proj"
    proj.mkdir()
    local_file = proj / "notes.txt"
    local_file.write_text("x\n", encoding="utf-8")

    resolution = links.resolve(str(local_file), roots=[str(proj)], deadline=time.monotonic() + 1.0)

    assert resolution.error is None
    assert resolution.changed is False


def test_walk_stops_at_root_exit(tmp_path, monkeypatch):
    proj = tmp_path / "proj"
    proj.mkdir()
    _write_policy(proj)
    outside = tmp_path / "outside"
    (outside / "deep").mkdir(parents=True)

    link = proj / "lnk"
    _junction(link, outside)

    recorded: list[str] = []
    real_lstat = links.os.lstat

    def recording_lstat(path, *args, **kwargs):
        recorded.append(str(path))
        return real_lstat(path, *args, **kwargs)

    monkeypatch.setattr(links.os, "lstat", recording_lstat)

    verdict = evaluate(_read(str(link / "deep" / "x.py"), cwd=str(proj)))

    assert verdict is not None
    outside_norm = _norm(str(outside))
    for recorded_path in recorded:
        assert not _norm(recorded_path).startswith(outside_norm), recorded_path


def test_nonexistent_path_lexical_only(tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    _write_policy(proj)

    verdict = evaluate(_write(str(proj / "new" / "dir" / "file.py"), cwd=str(proj)))

    assert verdict is None


def test_resolve_links_flag_off(tmp_path, monkeypatch):
    monkeypatch.setenv("WARDEN_RESOLVE_LINKS", "0")
    proj = tmp_path / "proj"
    proj.mkdir()
    _write_policy(proj)
    home = _make_home(tmp_path, monkeypatch)
    link = proj / "cloud"
    _dirlink(link, home / ".aws")  # a junction on Windows: runs without developer mode

    verdict = evaluate(_read(str(link / "credentials"), cwd=str(proj)))

    assert verdict is not None
    assert verdict.decision == "allow"


def test_dirlink_to_aws_denied(tmp_path, monkeypatch):
    """Same as the flag-off case with resolution on: `cloud/credentials` is the AWS secret."""
    proj = tmp_path / "proj"
    proj.mkdir()
    _write_policy(proj)
    home = _make_home(tmp_path, monkeypatch)
    link = proj / "cloud"
    _dirlink(link, home / ".aws")

    verdict = evaluate(_read(str(link / "credentials"), cwd=str(proj)))

    assert verdict is not None
    assert verdict.decision == "deny"
    assert "credentials" in verdict.reason


# ---------------------------------------------------------------------------
# Link creation pinned (lexical, Behaviour 8) -- no new rule, no real files needed
# ---------------------------------------------------------------------------


def test_link_creation_pinned():
    ln_verdict = evaluate(_bash("ln -s ~/.ssh x"))
    new_item_verdict = evaluate(
        _event(
            "PowerShell",
            {"command": "New-Item -ItemType SymbolicLink -Target ~/.aws/credentials -Path x"},
        )
    )
    mklink_verdict = evaluate(_bash("mklink /J lnk C:\\Users"))

    assert ln_verdict is not None
    assert ln_verdict.decision in ("deny", "ask")  # `~/.ssh` alone: boundary ask today
    assert new_item_verdict is not None
    assert new_item_verdict.decision == "deny"
    assert mklink_verdict is not None
    assert mklink_verdict.decision in ("deny", "ask")


# ---------------------------------------------------------------------------
# Direct links.resolve() tests
# ---------------------------------------------------------------------------


def test_resolve_dir_junction_reports_changed(tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    target = proj / "target"
    target.mkdir()
    link = proj / "lnk"
    _junction(link, target)

    resolution = links.resolve(str(link), roots=[str(proj)], deadline=time.monotonic() + 1.0)

    assert resolution.changed is True
    assert resolution.error is None
    assert _norm(resolution.resolved).endswith("/target")


def test_resolve_plain_path_unchanged(tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    plain = proj / "plain.txt"
    plain.write_text("x\n", encoding="utf-8")

    resolution = links.resolve(str(plain), roots=[str(proj)], deadline=time.monotonic() + 1.0)

    assert resolution.changed is False
    assert resolution.error is None


# ---------------------------------------------------------------------------
# Reviewer finding: the hard-link check must not follow planted links either
# ---------------------------------------------------------------------------


def _record_fs(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, str]]:
    """`(function, path)` for every lstat / listdir / stat (the global `os` module: delegate)."""
    seen: list[tuple[str, str]] = []
    for name in ("lstat", "listdir", "stat"):
        real = getattr(links.os, name)

        def spy(path, *a, _real=real, _name=name, **kw):
            seen.append((_name, str(path).replace("\\", "/").lower()))
            return _real(path, *a, **kw)

        monkeypatch.setattr(links.os, name, spy)
    return seen


def _followed(seen: list[tuple[str, str]], link: Path) -> list[tuple[str, str]]:
    """Calls that went through `link`: anything below it, or a following call on it."""
    key = str(link).replace("\\", "/").lower()
    return [
        (fn, path)
        for fn, path in seen
        if path.startswith(key + "/") or (path == key and fn != "lstat")
    ]


def test_protected_inodes_never_follow_planted_links(tmp_path, monkeypatch):
    proj = tmp_path / "proj"
    proj.mkdir()
    _write_policy(proj)
    home = _make_home(tmp_path, monkeypatch)
    outside = tmp_path / "outside"
    (outside / "sub").mkdir(parents=True)
    (outside / "sub" / "credentials").write_text("x\n", encoding="utf-8")
    _dirlink(proj / ".agentwarden" / "evil", outside)  # planted inside .agentwarden
    _dirlink(home / ".kube", outside / "sub")  # home secret dir is a link
    seen = _record_fs(monkeypatch)

    table = links.protected_inodes(str(proj), [str(proj)], lambda name: False)

    assert not _followed(seen, proj / ".agentwarden" / "evil")
    assert not _followed(seen, home / ".kube")
    assert all("outside" not in path.lower() for path, _ in table.values())


def test_hardlink_check_does_not_stat_through_links(tmp_path, monkeypatch):
    proj = tmp_path / "proj"
    proj.mkdir()
    _write_policy(proj)
    _make_home(tmp_path, monkeypatch)
    target = proj / "a.txt"
    target.write_text("x\n", encoding="utf-8")
    os.link(target, proj / "b.txt")  # nlink 2: the protected table is built
    outside = tmp_path / "outside"
    outside.mkdir()
    _dirlink(proj / ".agentwarden" / "evil", outside)
    seen = _record_fs(monkeypatch)

    verdict = evaluate(_read(str(proj / "b.txt"), cwd=str(proj)))

    assert verdict is not None
    assert verdict.decision == "allow"
    assert not _followed(seen, proj / ".agentwarden" / "evil")
