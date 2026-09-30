"""FR-FIX-11: product text says "non-intrusive", never "passive"; the User-Agent carries the real version."""

from __future__ import annotations

import pytest

from owasp_scanner import __version__, cli, http_utils, web
from owasp_scanner.html_report import render_html
from owasp_scanner.models import ScanResult
from owasp_scanner.output import build_report


def _product_texts() -> dict[str, str]:
    report = build_report(ScanResult(target="https://t.example/", started_at="2026-01-01T00:00:00Z"))
    texts = {
        "CLI banner": cli.CONSENT_BANNER,
        "User-Agent": http_utils.USER_AGENT,
        "HTML report": render_html(report),
    }
    for name in ("index.html", "app.js"):
        texts[name] = (web._STATIC_DIR / name).read_text(encoding="utf-8")
    return texts


@pytest.mark.parametrize("where", sorted(_product_texts()))
def test_product_text_does_not_say_passive(where):
    assert "passive" not in _product_texts()[where].lower()


def test_cli_help_does_not_say_passive(capsys):
    with pytest.raises(SystemExit):
        cli.main(["--help"])
    with pytest.raises(SystemExit):
        web.main(["--help"])
    assert "passive" not in capsys.readouterr().out.lower()


def test_user_agent_identifies_the_scanner_and_its_version():
    assert (
        http_utils.USER_AGENT == f"TECHVIFY-OWASP-Scanner/{__version__} (+non-intrusive security configuration check)"
    )


def test_ui_footer_points_at_the_current_srs():
    html = (web._STATIC_DIR / "index.html").read_text(encoding="utf-8")
    assert "docs/SRS-owasp-scanner.md" in html and "<code>SRS.md</code>" not in html
