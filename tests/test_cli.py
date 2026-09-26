import copy
import json
import stat

import pytest

from infradrift import cli
from infradrift.snapshot import StateSnapshot

from .test_diff import BASE


def run(capsys, *argv):
    with pytest.raises(SystemExit) as exc:
        cli.main(list(argv))
    out = capsys.readouterr()
    return exc.value.code, out.out, out.err


@pytest.fixture
def files(tmp_path):
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    StateSnapshot(**copy.deepcopy(BASE)).save(a)
    cur = copy.deepcopy(BASE)
    cur["packages"]["apt"]["nginx"] = "1.26.0-1"      # INFO
    StateSnapshot(**cur).save(b)
    return a, b


def test_saved_baseline_is_private(files):
    assert stat.S_IMODE(files[0].stat().st_mode) == 0o600


def test_diff_json_is_clean_and_exit_codes(capsys, files):
    code, out, _ = run(capsys, "diff", *map(str, files), "-f", "json")
    assert code == 1 and json.loads(out)["summary"]["info"] == 1
    assert run(capsys, "diff", *map(str, files), "--fail-on", "warning")[0] == 0


def test_terminal_report_plain_when_piped(capsys, files):
    code, out, _ = run(capsys, "diff", *map(str, files))
    assert "[apt] nginx upgraded" in out and "\033[" not in out


def test_markdown_output_file(capsys, files, tmp_path):
    target = tmp_path / "drift.md"
    code, _, err = run(capsys, "diff", *map(str, files), "-o", str(target))
    assert target.read_text().startswith("# infradrift") and "Report saved" in err


def test_check_with_fake_collection(capsys, files, monkeypatch):
    monkeypatch.setattr(cli, "take_snapshot", lambda **kw: StateSnapshot(**copy.deepcopy(BASE)))
    code, out, err = run(capsys, "check", "-b", str(files[0]), "-f", "json")
    assert code == 0 and json.loads(out)["summary"]["total"] == 0


def test_different_user_warning(capsys, tmp_path):
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    StateSnapshot(**copy.deepcopy(BASE)).save(a)
    cur = copy.deepcopy(BASE)
    cur["meta"]["user"] = "alice"
    StateSnapshot(**cur).save(b)
    _, _, err = run(capsys, "diff", str(a), str(b))
    assert 'Baseline taken as "root"' in err


def test_errors_exit_2(capsys, tmp_path):
    code, _, err = run(capsys, "check", "-b", str(tmp_path / "nope.json"))
    assert code == 2 and "Baseline not found" in err
    bad = tmp_path / "bad.json"
    bad.write_text("not json")
    assert run(capsys, "diff", str(bad), str(bad))[0] == 2
