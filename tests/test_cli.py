import pytest

from owasp_tool import __version__
from owasp_tool.cli import main


def test_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_no_args_prints_help(capsys):
    assert main([]) == 0
    assert "usage: owasp-tool" in capsys.readouterr().out


def test_list_checks(capsys):
    assert main(["list-checks"]) == 0
    assert "security-headers" in capsys.readouterr().out


def test_scan_requires_authorized_flag(capsys):
    assert main(["scan", "https://example.test"]) == 2
    assert "--authorized" in capsys.readouterr().err


def test_scan_rejects_invalid_url():
    with pytest.raises(SystemExit) as exc:
        main(["scan", "not-a-url", "--authorized"])
    assert exc.value.code == 2


def test_scan_rejects_unknown_check(capsys):
    assert main(["scan", "https://example.test", "--authorized", "--checks", "nope"]) == 2
    assert "nope" in capsys.readouterr().err
