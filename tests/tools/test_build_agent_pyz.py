"""tools/build_agent_pyz.py: what goes into the agent archive, that it is reproducible and small, and that it runs like `python -m agent`."""
import hashlib
import importlib.util
import io
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent.parent
SCRIPT = REPO / "tools" / "build_agent_pyz.py"
spec = importlib.util.spec_from_file_location("build_agent_pyz", SCRIPT)
build_agent_pyz = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build_agent_pyz)


def build_to(tmp_path, *extra, name="agent.pyz"):
    out = tmp_path / name
    done = subprocess.run([sys.executable, str(SCRIPT), "--output", str(out), *extra], capture_output=True, text=True, cwd=tmp_path)
    return done, out


def names(path):
    return zipfile.ZipFile(path).namelist()


def agent_sources():
    return sorted(p.name for p in (REPO / "agent").glob("*.py"))


def test_it_contains_exactly_the_agent_source_and_a_launcher(tmp_path):
    done, out = build_to(tmp_path)
    assert done.returncode == 0, done.stderr
    assert names(out) == ["__main__.py"] + [f"agent/{n}" for n in agent_sources()]
    assert "agent/__main__.py" in names(out) and "agent/runner.py" in names(out) and "agent/tls_scan.py" in names(out)


def test_it_is_far_below_the_five_megabyte_limit_and_says_so(tmp_path):
    done, out = build_to(tmp_path)
    size = out.stat().st_size
    assert 10_000 < size < 500_000 and size < 5 * 1024 * 1024
    assert f"{size:,} bytes" in done.stdout and "limit 5,242,880 bytes" in done.stdout
    assert hashlib.sha256(out.read_bytes()).hexdigest() in done.stdout


def test_it_refuses_an_archive_over_the_limit_and_writes_nothing(tmp_path):
    done, out = build_to(tmp_path, "--limit-bytes", "1000")
    assert done.returncode == 1 and "over the limit" in done.stderr
    assert not out.exists()


def test_no_environment_cache_test_or_unrelated_file_is_packaged(tmp_path):
    source = tmp_path / "agent"
    shutil.copytree(REPO / "agent", source, ignore=shutil.ignore_patterns("__pycache__"))
    (source / "__pycache__").mkdir()
    (source / "__pycache__" / "runner.cpython-311.pyc").write_bytes(b"junk")
    (source / "__pycache__" / "stray.py").write_text("not part of the agent")
    (source / "notes.txt").write_text("not source")
    (source / "secret.pem").write_text("-----BEGIN PRIVATE KEY-----")
    (source / ".venv").mkdir()
    (source / ".venv" / "ignored.txt").write_text("x")
    done, out = build_to(tmp_path, "--source", str(source))
    assert done.returncode == 0, done.stderr
    listed = names(out)
    assert listed == ["__main__.py"] + [f"agent/{n}" for n in agent_sources()]
    assert not any(part in name for name in listed for part in ("__pycache__", ".pyc", ".txt", ".pem", ".venv", "tests", "backend", "frontend"))
    assert b"PRIVATE KEY" not in out.read_bytes()


def test_the_same_source_gives_the_same_bytes_whatever_the_time_or_line_endings(tmp_path):
    first = build_to(tmp_path, name="a.pyz")[1].read_bytes()
    source = tmp_path / "agent"
    shutil.copytree(REPO / "agent", source, ignore=shutil.ignore_patterns("__pycache__"))
    for path in source.glob("*.py"):                          # a checkout with other timestamps and Windows line endings
        data = path.read_bytes().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
        path.write_bytes(data)
        os.utime(path, (1_000_000_000, 1_000_000_000))
    second = build_to(tmp_path, "--source", str(source), name="b.pyz")[1].read_bytes()
    assert first == second
    assert build_to(tmp_path, name="c.pyz")[1].read_bytes() == first


def test_every_packaged_file_is_the_current_source(tmp_path):
    out = build_to(tmp_path)[1]
    with zipfile.ZipFile(out) as archive:
        for name in agent_sources():
            assert archive.read(f"agent/{name}") == (REPO / "agent" / name).read_bytes().replace(b"\r\n", b"\n")
        assert archive.read("__main__.py") == b"from agent.__main__ import main\nraise SystemExit(main())\n"


def test_the_archive_has_a_shebang_and_a_valid_zip_with_fixed_timestamps(tmp_path):
    out = build_to(tmp_path)[1]
    data = out.read_bytes()
    assert data.startswith(b"#!/usr/bin/env python3\n")
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        assert archive.testzip() is None
        assert {info.date_time for info in archive.infolist()} == {(1980, 1, 1, 0, 0, 0)}


def test_a_folder_that_is_not_the_agent_is_refused(tmp_path):
    (tmp_path / "other").mkdir()
    (tmp_path / "other" / "x.py").write_text("print(1)")
    done, out = build_to(tmp_path, "--source", str(tmp_path / "other"))
    assert done.returncode != 0 and "no __main__.py" in done.stderr and not out.exists()
    done, out = build_to(tmp_path, "--source", str(tmp_path / "missing"))
    assert done.returncode != 0 and "does not exist" in done.stderr


def test_help_is_identical_to_python_m_agent_and_needs_nothing_from_the_repository(tmp_path):
    out = build_to(tmp_path)[1]
    work = tmp_path / "elsewhere"
    work.mkdir()
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    packaged = subprocess.run([sys.executable, str(out), "--help"], capture_output=True, text=True, cwd=work, env=env)
    module = subprocess.run([sys.executable, "-m", "agent", "--help"], capture_output=True, text=True, cwd=REPO, env=env)
    assert packaged.returncode == 0 and packaged.stderr == ""
    assert packaged.stdout == module.stdout and "--server" in packaged.stdout and "--once" in packaged.stdout


def test_bad_arguments_fail_the_same_way_as_the_module(tmp_path):
    out = build_to(tmp_path)[1]
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    packaged = subprocess.run([sys.executable, str(out), "--server", "http://example.com:80"], capture_output=True, text=True, cwd=tmp_path, env=env)
    module = subprocess.run([sys.executable, "-m", "agent", "--server", "http://example.com:80"], capture_output=True, text=True, cwd=REPO, env=env)
    assert packaged.returncode == module.returncode != 0
    assert packaged.stderr == module.stderr


def test_the_agent_package_is_standard_library_only():
    """The archive bundles no dependency, so every import in the agent must be the standard library or the agent itself."""
    import ast
    stdlib = set(sys.stdlib_module_names)
    for path in (REPO / "agent").glob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            modules = [a.name for a in node.names] if isinstance(node, ast.Import) else [node.module or ""] if isinstance(node, ast.ImportFrom) and node.level == 0 else []
            for module in modules:
                top = module.split(".")[0]
                assert top in stdlib or top == "agent", f"{path.name} imports {module}, which is not in the standard library"
