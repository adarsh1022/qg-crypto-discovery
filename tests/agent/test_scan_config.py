"""ScanConfig validation/defaults and default_roots()."""
import os

import pytest

from agent import scan_config
from agent.scan_config import ConfigError, ScanConfig, default_roots


def cfg(tmp_path, **kw):
    return ScanConfig(roots=(str(tmp_path),), **kw)


def test_defaults_match_the_approved_values(tmp_path):
    c = cfg(tmp_path)
    assert c.max_file_bytes == 16 * 1024 * 1024
    assert c.max_depth == 12
    assert c.max_entries == 1_000_000
    assert c.max_candidates == 50_000
    assert c.max_certs_per_file == 1000
    assert c.time_budget_seconds == 600
    assert c.expiring_days == 30
    assert c.extensions == (".pem", ".crt", ".cer", ".cert", ".der", ".pfx", ".p12")


def test_node_modules_and_system_dirs_are_excluded_by_default(tmp_path):
    names = cfg(tmp_path).exclude_dir_names
    assert {"node_modules", ".git", "winsxs", "$recycle.bin", "system volume information"} <= set(names)


def test_extensions_are_normalised(tmp_path):
    assert cfg(tmp_path, extensions=("PEM", ".Crt", "crt", " .der ")).extensions == (".pem", ".crt", ".der")


def test_roots_are_normalised_and_kept_absolute(tmp_path):
    messy = str(tmp_path) + os.sep + "a" + os.sep + ".." + os.sep
    assert cfg(tmp_path).roots == (os.path.normpath(str(tmp_path)),)
    assert ScanConfig(roots=(messy,)).roots == (os.path.normpath(messy),)


def test_exclude_paths_are_normalised(tmp_path):
    c = cfg(tmp_path, exclude_paths=(str(tmp_path / "X" / ".." / "Skip"),))
    assert c.exclude_paths == (os.path.normcase(str(tmp_path / "Skip")),)


@pytest.mark.parametrize("kwargs", [
    dict(roots=("relative/path",)), dict(roots=("\\\\server\\share",)), dict(roots=("//server/share",)),
    dict(roots=()), dict(roots=("",)), dict(roots=(5,)), dict(roots="C:\\single-string"),
    dict(extensions=()), dict(extensions=("",)), dict(extensions=(".",)), dict(extensions=("a/b",)),
    dict(extensions=(5,)), dict(exclude_dir_names=("a/b",)), dict(exclude_dir_names=("",)),
    dict(exclude_paths=("relative",)),
    dict(max_file_bytes=0), dict(max_file_bytes=-1), dict(max_file_bytes=True), dict(max_file_bytes=1.5),
    dict(max_entries=0), dict(max_candidates=0), dict(max_certs_per_file=0),
    dict(max_depth=-1), dict(max_depth="3"), dict(expiring_days=-1), dict(expiring_days=True),
    dict(time_budget_seconds=0), dict(time_budget_seconds=-5), dict(time_budget_seconds="10"),
])
def test_invalid_configuration_is_rejected(tmp_path, kwargs):
    kwargs.setdefault("roots", (str(tmp_path),))
    with pytest.raises(ConfigError):
        ScanConfig(**kwargs)


def test_zero_depth_is_allowed(tmp_path):
    assert cfg(tmp_path, max_depth=0).max_depth == 0


def test_from_dict(tmp_path):
    c = ScanConfig.from_dict({"roots": [str(tmp_path)], "extensions": ["pem"], "max_depth": 3,
                              "exclude_dir_names": ["Skip"], "time_budget_seconds": 2.5})
    assert c.roots == (os.path.normpath(str(tmp_path)),) and c.extensions == (".pem",)
    assert c.max_depth == 3 and c.exclude_dir_names == ("skip",) and c.time_budget_seconds == 2.5


@pytest.mark.parametrize("bad", [{"nonsense": 1}, {"roots": ["C:\\x"], "extensionz": []}, [], "x", None])
def test_from_dict_rejects_unknown_or_wrong_shapes(bad):
    with pytest.raises(ConfigError):
        ScanConfig.from_dict(bad)


def test_config_is_frozen(tmp_path):
    with pytest.raises(Exception):
        cfg(tmp_path).max_depth = 99


def test_omitted_roots_use_default_roots(tmp_path, monkeypatch):
    monkeypatch.setattr(scan_config, "default_roots", lambda: [str(tmp_path)])
    assert ScanConfig().roots == (str(tmp_path),)
    monkeypatch.setattr(scan_config, "default_roots", lambda: [])
    with pytest.raises(ConfigError):
        ScanConfig()


# ---------------------------------------------------------------- default_roots
def test_default_roots_only_include_existing_directories(tmp_path):
    for d in ("home/Downloads", "home/Documents", "pd", "pf/Git"):
        (tmp_path / d).mkdir(parents=True)
    env = {"USERPROFILE": str(tmp_path / "home"), "ProgramData": str(tmp_path / "pd"),
           "ProgramFiles": str(tmp_path / "pf")}
    roots = default_roots(env, known_folder=lambda guid: None)
    assert roots == [str(tmp_path / "home" / "Downloads"), str(tmp_path / "home" / "Documents"),
                     str(tmp_path / "pd"), str(tmp_path / "pf" / "Git")]
    assert not any(r.endswith("Desktop") or ".aspnet" in r for r in roots)      # absent -> not guessed


def test_default_roots_skip_missing_programdata_and_git(tmp_path):
    (tmp_path / "home" / "Downloads").mkdir(parents=True)
    env = {"USERPROFILE": str(tmp_path / "home"), "ProgramData": str(tmp_path / "nope"),
           "ProgramFiles": str(tmp_path / "nopf")}
    assert default_roots(env, known_folder=lambda guid: None) == [str(tmp_path / "home" / "Downloads")]
    assert default_roots({"USERPROFILE": str(tmp_path / "empty")}, known_folder=lambda g: None) == []


def test_default_roots_prefer_redirected_known_folders_and_dedupe(tmp_path):
    (tmp_path / "home" / "Documents").mkdir(parents=True)
    (tmp_path / "onedrive" / "Desktop").mkdir(parents=True)
    redirected = {scan_config._FOLDERID_DESKTOP: str(tmp_path / "onedrive" / "Desktop"),
                  scan_config._FOLDERID_DOCUMENTS: str(tmp_path / "home" / "Documents")}
    roots = default_roots({"USERPROFILE": str(tmp_path / "home")}, known_folder=redirected.get)
    assert roots == [str(tmp_path / "home" / "Documents"), str(tmp_path / "onedrive" / "Desktop")]


def test_real_default_roots_exist_and_include_programdata():
    roots = default_roots()
    assert all(os.path.isdir(r) for r in roots)
    assert len({os.path.normcase(r) for r in roots}) == len(roots)
    pd = os.environ.get("ProgramData")
    if pd and os.path.isdir(pd):
        assert os.path.normpath(pd) in roots


@pytest.mark.skipif(os.name != "nt", reason="Windows known folders")
def test_known_folder_lookup_returns_a_real_path_or_none():
    for guid in (scan_config._FOLDERID_DOWNLOADS, scan_config._FOLDERID_DOCUMENTS):
        value = scan_config._windows_known_folder(guid)
        assert value is None or os.path.isabs(value)
    assert scan_config._windows_known_folder("00000000-0000-0000-0000-000000000000") is None
