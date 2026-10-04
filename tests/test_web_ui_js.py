"""FR-UI-14: the page's own JavaScript (static/app.js), run under Node against a minimal fake DOM.

The page is the one part of the product no other test executes. These tests load the real app.js and
call its functions, so "the checkbox adds crawl to the request only when ticked" and "text from a
scanned site is only ever shown as text" are checked on the code that ships, not on its spelling.
Skipped when Node is not installed.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

NODE = shutil.which("node")
pytestmark = pytest.mark.skipif(NODE is None, reason="Node.js is not installed")

HARNESS = Path(__file__).with_name("ui_harness.js")
APP_JS = Path(__file__).resolve().parents[1] / "websec_scanner" / "static" / "app.js"


def run(expression: str):
    done = subprocess.run(  # noqa: S603 - Node on this repository's own harness, a fixed argument list
        [NODE, str(HARNESS), str(APP_JS), expression], capture_output=True, text=True, timeout=60, check=False
    )
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)


def finding(**overrides):
    base = {
        "severity": "MEDIUM",
        "title": "Missing CSP",
        "owasp_category": "A05",
        "cwe": "CWE-693",
        "confidence": "high",
        "id": "HDR-CONTENT-SECURITY-POLICY-MISSING",
        "description": "d",
        "evidence": "",
        "recommendation": "",
        "url": "http://t.test/",
        "references": [],
        "cvss_score": None,
        "affected_urls": ["http://t.test/"],
        "affected_count": 1,
    }
    base.update(overrides)
    return base


# --- the request ---------------------------------------------------------------------------------------


def test_the_request_has_no_crawl_unless_the_box_is_ticked():
    assert run("scanPayload('http://t.test/', ['headers', 'cookies'], false)") == {
        "target": "http://t.test/",
        "authorized": True,
        "checks": ["headers", "cookies"],
    }


def test_a_ticked_box_adds_exactly_one_boolean():
    payload = run("scanPayload('http://t.test/', ['headers'], true)")
    assert payload == {"target": "http://t.test/", "authorized": True, "checks": ["headers"], "crawl": True}


def test_no_other_crawl_field_is_ever_sent():
    sent = run("Object.keys(scanPayload('http://t.test/', ['headers', 'cookies', 'tls'], true))")
    assert sorted(sent) == ["authorized", "checks", "crawl", "target"]


def test_when_the_list_of_test_targets_did_not_load_no_checks_are_sent_and_the_crawl_still_can_be():
    assert run("scanPayload('http://t.test/', null, true)") == {
        "target": "http://t.test/",
        "authorized": True,
        "crawl": True,
    }


@pytest.mark.parametrize(
    ("selected", "applies"),
    [
        (["headers"], True),
        (["cookies"], True),
        (["tls", "cors", "exposed-files"], False),
        ([], False),
        (None, True),
    ],
)
def test_the_crawl_only_applies_when_a_page_check_is_selected(selected, applies):
    assert run(f"crawlApplies({json.dumps(selected)})") is applies


def test_a_ticked_box_is_not_sent_when_no_page_check_is_selected():
    assert "crawl" not in run("scanPayload('http://t.test/', ['tls', 'cors'], true)")


def test_the_hint_states_the_limits_the_server_gave():
    hint = run("crawlHint({max_depth: 1, max_pages: 7, max_duration: 12.5})")
    assert "7 pages" in hint and "1 level(s) deep" in hint and "12.5 s" in hint and "robots.txt is respected" in hint


# --- the result ----------------------------------------------------------------------------------------------


def test_a_finding_seen_on_several_pages_lists_the_others():
    f = finding(affected_urls=["http://t.test/", "http://t.test/a", "http://t.test/b"], affected_count=3)
    tree = run(f"dump(findingItem({json.dumps(f)}, 'ctx'))")
    text = json.dumps(tree)
    assert "Also seen on" in text and "http://t.test/a, http://t.test/b" in text
    assert "more page(s)" not in text  # every page fit on the line


def test_pages_beyond_the_listed_ones_are_counted():
    f = finding(affected_urls=["http://t.test/", "http://t.test/a"], affected_count=30)
    assert "and 28 more page(s)" in json.dumps(run(f"dump(findingItem({json.dumps(f)}, 'ctx'))"))


def test_a_finding_on_one_page_has_no_also_seen_on_row():
    assert "Also seen on" not in json.dumps(run(f"dump(findingItem({json.dumps(finding())}, 'ctx'))"))


def test_a_hostile_url_is_shown_as_text_never_as_markup():
    hostile = "http://t.test/<img src=x onerror=alert(1)>"
    f = finding(affected_urls=["http://t.test/", hostile], affected_count=2)
    tree = run(f"dump(findingItem({json.dumps(f)}, 'ctx'))")
    nodes: list[dict] = []

    def walk(node):
        nodes.append(node)
        for child in node.get("children", []):
            walk(child)

    walk(tree)
    assert not any(n.get("tag") == "img" for n in nodes)  # no element was made from the text
    assert hostile in json.dumps(tree)  # it is on the page, as a string of characters
    source = APP_JS.read_text(encoding="utf-8")  # the file's comment says "never innerHTML": look for the use
    assert not re.search(r"\.(innerHTML|outerHTML)|insertAdjacentHTML|document\.write", source)


def test_the_crawl_line_shows_the_servers_sentence_and_hides_without_one():
    shown = run(
        "(showCrawlLine({crawl_message: '3 page(s) visited: all reachable pages were visited'}), "
        "{hidden: __byId('crawl-line').hidden, text: __byId('crawl-line').textContent})"
    )
    assert shown == {"hidden": False, "text": "Crawl: 3 page(s) visited: all reachable pages were visited"}
    hidden = run(
        "(showCrawlLine({crawl_message: null}), "
        "{hidden: __byId('crawl-line').hidden, text: __byId('crawl-line').textContent})"
    )
    assert hidden == {"hidden": True, "text": ""}


def test_the_json_download_has_no_web_only_field_but_keeps_the_crawl():
    result = {
        "target": "http://t.test/",
        "crawl": {"pages_visited": 3},
        "crawl_message": "3 page(s) visited",
        "gate_failed": False,
        "gate_status": "pass",
        "gate_message": "m",
        "groups": [],
        "owasp_groups": [],
        "report_id": "x",
        "report_url": "/api/report/x.html",
        "findings": [],
    }
    saved = run(f"(lastResult = {json.dumps(result)}, downloadJson(), JSON.parse(__blob))")
    assert saved == {"target": "http://t.test/", "crawl": {"pages_visited": 3}, "findings": []}


def test_the_web_only_fields_the_download_drops_are_the_servers_list():
    from websec_scanner import web

    source = APP_JS.read_text(encoding="utf-8")
    dropped = re.search(r"const \{([^}]*)\.\.\.report \} = lastResult", source)
    assert dropped, "the JSON download no longer drops the web-only fields in one destructuring"
    names = {name.strip() for name in dropped.group(1).split(",") if name.strip()}
    assert names == set(web.WEB_ONLY_FIELDS)


# --- the code that reads the box -------------------------------------------------------------------------------------

SCAN = (
    "(__byId('target').value = 'http://t.test/', __byId('authorized').checked = true, "
    "__byId('crawl').checked = %s, __setBoxes(%s), groupsLoaded = true, "
    "runScan({preventDefault() {}}).then(() => JSON.parse(__lastFetch.body)))"
)


def scan_body(ticked: bool, groups: list[str]):
    boxes = json.dumps([{"value": g, "checked": True} for g in groups])
    return run(SCAN % (json.dumps(ticked), boxes))


def test_running_a_scan_sends_the_boxes_state():
    assert scan_body(True, ["headers", "tls"]) == {
        "target": "http://t.test/",
        "authorized": True,
        "checks": ["headers", "tls"],
        "crawl": True,
    }
    assert "crawl" not in scan_body(False, ["headers", "tls"])


def test_running_a_scan_with_the_box_ticked_but_no_page_check_sends_no_crawl():
    assert "crawl" not in scan_body(True, ["tls", "cors"])


def test_the_box_is_disabled_with_a_note_when_no_page_check_is_selected():
    only_tls = run(
        "(groupsLoaded = true, __setBoxes([{value: 'tls', checked: true}]), updateCrawlAvailability(), "
        "{disabled: __byId('crawl').disabled, noteHidden: __byId('crawl-note').hidden})"
    )
    assert only_tls == {"disabled": True, "noteHidden": False}
    with_cookies = run(
        "(groupsLoaded = true, __setBoxes([{value: 'cookies', checked: true}]), updateCrawlAvailability(), "
        "{disabled: __byId('crawl').disabled, noteHidden: __byId('crawl-note').hidden})"
    )
    assert with_cookies == {"disabled": False, "noteHidden": True}


def test_while_a_scan_runs_the_box_is_disabled_and_afterwards_it_follows_the_selection():
    busy = run("(setBusy(true, 'http://t.test/'), __byId('crawl').disabled)")
    assert busy is True
    done = run(
        "(groupsLoaded = true, __setBoxes([{value: 'headers', checked: true}]), "
        "setBusy(true, 'x'), setBusy(false, 'x'), __byId('crawl').disabled)"
    )
    assert done is False


def test_the_hint_is_filled_from_what_the_server_says():
    expression = (
        "(__fetchImpl = () => Promise.resolve({ok: true, json: async () => ({groups: [], "
        "crawl: {max_depth: 3, max_pages: 11, max_duration: 5}})}), "
        "loadGroups().then(() => __byId('crawl-hint').textContent))"
    )
    hint = run(expression)
    assert "11 pages" in hint and "3 level(s) deep" in hint and "5 s" in hint


def test_changing_the_selected_test_targets_updates_the_box():
    """The change listener of each group box calls updateGroupsCount, which keeps the crawl box in step."""
    expression = (
        "(groupsLoaded = true, __setBoxes([{value: 'tls', checked: true}]), updateGroupsCount(), "
        "{disabled: __byId('crawl').disabled, count: __byId('groups-count').textContent})"
    )
    assert run(expression) == {"disabled": True, "count": "1 of 1 selected"}


RESULT = {
    "target": "http://t.test/",
    "started_at": "2026-10-04T01:00:00Z",
    "finished_at": "2026-10-04T01:00:05Z",
    "final_url": "http://t.test/",
    "checks_run": ["security-headers"],
    "summary": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 1, "LOW": 0, "INFO": 0},
    "gate_status": "pass",
    "gate_message": "No findings at or above the --fail-on high threshold: the CLI exits with code 0.",
    "groups": [],
    "owasp_groups": [],
    "errors": [],
    "findings": [],
    "report_url": "/api/report/x.html",
}


def test_a_result_with_a_crawl_shows_the_crawl_line():
    message = "3 page(s) visited: all reachable pages were visited"
    shown = run(
        f"(renderResult({json.dumps({**RESULT, 'crawl_message': message})}), "
        "{hidden: __byId('crawl-line').hidden, text: __byId('crawl-line').textContent})"
    )
    assert shown == {"hidden": False, "text": "Crawl: 3 page(s) visited: all reachable pages were visited"}


def test_a_result_without_a_crawl_hides_the_crawl_line_left_by_an_earlier_scan():
    expression = (
        f"(renderResult({json.dumps({**RESULT, 'crawl_message': '3 page(s) visited: x'})}), "
        f"renderResult({json.dumps({**RESULT, 'crawl_message': None})}), "
        "{hidden: __byId('crawl-line').hidden, text: __byId('crawl-line').textContent})"
    )
    assert run(expression) == {"hidden": True, "text": ""}
