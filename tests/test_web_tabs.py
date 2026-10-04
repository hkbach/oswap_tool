"""FR-UI-15: the result area has two tabs, Findings and Scanned URLs. The markup, without running the page."""

from __future__ import annotations

import re
from pathlib import Path

from websec_scanner import web

STATIC = Path(web.__file__).with_name("static")
PAGE = (STATIC / "index.html").read_text(encoding="utf-8")


def tag(element_id: str) -> str:
    match = re.search(rf'<[a-z]+[^>]*\bid="{element_id}"[^>]*>', PAGE)
    assert match, f"#{element_id} is missing from the page"
    return match.group(0)


def test_there_is_a_tablist_with_one_tab_for_each_panel():
    assert 'role="tablist"' in PAGE
    for name in ("findings", "urls"):
        button = tag(f"tab-{name}")
        assert 'role="tab"' in button and f'aria-controls="panel-{name}"' in button
        panel = tag(f"panel-{name}")
        assert 'role="tabpanel"' in panel and f'aria-labelledby="tab-{name}"' in panel


def test_findings_is_the_tab_shown_first():
    assert 'aria-selected="true"' in tag("tab-findings") and 'tabindex="0"' in tag("tab-findings")
    assert 'aria-selected="false"' in tag("tab-urls") and 'tabindex="-1"' in tag("tab-urls")
    assert "hidden" not in tag("panel-findings") and "hidden" in tag("panel-urls")


def test_the_tabs_are_buttons_so_the_keyboard_reaches_them():
    assert tag("tab-findings").startswith("<button") and tag("tab-urls").startswith("<button")
    assert 'type="button"' in tag("tab-findings")


def test_the_findings_controls_are_inside_the_findings_panel():
    findings = PAGE.index('id="panel-findings"')
    urls = PAGE.index('id="panel-urls"')
    for element in ("group-by", "severity-filter", "groups", "no-findings"):
        assert findings < PAGE.index(f'id="{element}"') < urls, element


def test_the_summary_and_the_errors_stay_above_both_tabs():
    tabs = PAGE.index('role="tablist"')
    for element in ("gate", "summary", "crawl-line", "errors"):
        assert PAGE.index(f'id="{element}"') < tabs, element


def test_the_urls_panel_has_a_table_with_five_columns():
    table = PAGE[PAGE.index('id="pages-table"') :]
    head = table[: table.index("</thead>")]
    assert re.findall(r"<th[^>]*>([^<]*)</th>", head) == ["URL", "Status", "Depth", "Checked", "Findings"]
    assert 'id="pages-body"' in table and 'id="pages-notes"' in PAGE
