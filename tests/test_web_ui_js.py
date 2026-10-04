"""FR-UI-14: the page's own JavaScript (static/app.js), run under Node against a minimal fake DOM.

The page is the one part of the product no other test executes. These tests load the real app.js and
call its functions, so "the checkbox adds crawl to the request only when ticked" and "text from a
scanned site is only ever shown as text" are checked on the code that ships, not on its spelling.
Skipped when Node is not installed.
"""

from __future__ import annotations

import atexit
import json
import queue
import re
import shutil
import subprocess
import threading
from pathlib import Path

import pytest

NODE = shutil.which("node")
pytestmark = pytest.mark.skipif(NODE is None, reason="Node.js is not installed")

HARNESS = Path(__file__).with_name("ui_harness.js")
APP_JS = Path(__file__).resolve().parents[1] / "websec_scanner" / "static" / "app.js"


class _Harness:
    """One long-lived Node process: starting Node once instead of once per test. Each expression still gets a
    fresh fake DOM and a fresh load of app.js inside it (see ui_harness.js), so tests cannot affect each other."""

    TIMEOUT = 60  # seconds for one expression

    def __init__(self) -> None:
        self._process = subprocess.Popen(  # noqa: S603 - Node on this repository's own harness, a fixed argument list
            [NODE, str(HARNESS), str(APP_JS), "--serve"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
        )
        self._replies: queue.Queue[str | None] = queue.Queue()
        threading.Thread(target=self._read, daemon=True).start()
        atexit.register(self.close)

    def _read(self) -> None:
        for line in self._process.stdout:
            self._replies.put(line)
        self._replies.put(None)  # the process ended

    def evaluate(self, expression: str):
        self._process.stdin.write(json.dumps({"expression": expression}) + "\n")
        self._process.stdin.flush()
        try:
            line = self._replies.get(timeout=self.TIMEOUT)
        except queue.Empty:
            self.close()
            raise AssertionError(f"Node did not answer within {self.TIMEOUT} s for: {expression[:200]}") from None
        assert line is not None, f"Node ended: {self._process.stderr.read()}"
        reply = json.loads(line)
        assert reply["ok"], reply["error"]
        return reply["value"]

    def close(self) -> None:
        if self._process.poll() is None:
            self._process.kill()
        for stream in (self._process.stdin, self._process.stdout, self._process.stderr):
            if stream:
                stream.close()


_harness: _Harness | None = None


def run(expression: str):
    global _harness
    if _harness is None or _harness._process.poll() is not None:
        _harness = _Harness()
    return _harness.evaluate(expression)


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


# --- the two tabs (FR-UI-15) ---------------------------------------------------------------------------------------

STATE = (
    "{findings: [__byId('tab-findings').getAttribute('aria-selected'), __byId('tab-findings').tabIndex, "
    "__byId('panel-findings').hidden], urls: [__byId('tab-urls').getAttribute('aria-selected'), "
    "__byId('tab-urls').tabIndex, __byId('panel-urls').hidden]}"
)


def test_selecting_a_tab_shows_its_panel_and_hides_the_other():
    assert run(f"(selectTab('urls'), {STATE})") == {
        "findings": ["false", -1, True],
        "urls": ["true", 0, False],
    }
    assert run(f"(selectTab('urls'), selectTab('findings'), {STATE})") == {
        "findings": ["true", 0, False],
        "urls": ["false", -1, True],
    }


def press(key: str, start: str = "findings"):
    expression = (
        f"(selectTab('{start}'), (() => {{ let prevented = false; "
        f"tabKeydown({{key: '{key}', preventDefault() {{ prevented = true; }}}}); return prevented; }})(), "
        f"{STATE}.urls[0] === 'true' ? 'urls' : 'findings')"
    )
    return run(expression)


def test_the_arrow_keys_move_between_the_tabs_and_wrap():
    assert press("ArrowRight", "findings") == "urls"
    assert press("ArrowRight", "urls") == "findings"
    assert press("ArrowLeft", "findings") == "urls"
    assert press("ArrowLeft", "urls") == "findings"


def test_home_and_end_go_to_the_first_and_last_tab():
    assert press("End", "findings") == "urls"
    assert press("Home", "urls") == "findings"


def test_the_tab_that_is_reached_by_key_gets_the_focus():
    focused = run(
        "(selectTab('findings'), tabKeydown({key: 'ArrowRight', preventDefault() {}}), __byId('tab-urls').focused)"
    )
    assert focused is True


def test_other_keys_do_nothing_and_are_not_swallowed():
    expression = (
        "(selectTab('findings'), (() => { let prevented = false; "
        "tabKeydown({key: 'a', preventDefault() { prevented = true; }}); return prevented; })())"
    )
    assert run(expression) is False
    assert press("a", "urls") == "urls"


PAGES = [
    {"url": "http://t.test/", "status": 200, "depth": 0, "checked": True, "findings": 4},
    {"url": "http://t.test/a", "status": 200, "depth": 1, "checked": True, "findings": 6},
    {"url": "http://t.test/doc.pdf", "status": 200, "depth": 1, "checked": False, "findings": 0},
    {"url": "http://t.test/gone", "status": 404, "depth": 1, "checked": False, "findings": 0},
]
CRAWL = {"pages_visited": 4, "stopped_reason": "complete"}


def rows(result):
    tree = run(f"(renderPages({json.dumps(result)}), dump(__byId('pages-body')))")
    return [[cell["text"] for cell in row["children"]] for row in tree["children"]]


def test_each_page_is_a_row_with_its_url_status_depth_check_and_findings():
    result = {**RESULT, "pages": PAGES, "crawl": CRAWL}
    assert rows(result) == [
        ["http://t.test/", "200", "0", "Yes", "4"],
        ["http://t.test/a", "200", "1", "Yes", "6"],
        ["http://t.test/doc.pdf", "200", "1", "No", "0"],
        ["http://t.test/gone", "404", "1", "No", "0"],
    ]


def test_the_tab_labels_carry_the_counts():
    labels = run(
        f"(renderPages({json.dumps({**RESULT, 'pages': PAGES, 'crawl': CRAWL, 'findings': [{}, {}, {}]})}), "
        "[__byId('tab-findings').textContent, __byId('tab-urls').textContent])"
    )
    assert labels == ["Findings (3)", "Scanned URLs (4)"]


def test_a_url_from_the_site_is_a_text_cell_never_markup():
    hostile = "http://t.test/<img src=x onerror=alert(1)>"
    result = {**RESULT, "pages": [{**PAGES[0], "url": hostile}], "crawl": None}
    tree = run(f"(renderPages({json.dumps(result)}), dump(__byId('pages-body')))")
    blob = json.dumps(tree)
    assert hostile in blob
    assert '"tag": "img"' not in blob


def notes(result):
    tree = run(f"(renderPages({json.dumps(result)}), dump(__byId('pages-notes')))")
    return [child["text"] for child in tree["children"]]


def test_without_a_crawl_the_tab_says_only_the_target_page_was_scanned():
    result = {**RESULT, "pages": PAGES[:1], "crawl": None}
    assert notes(result) == [
        "Only the target page was scanned. Tick the crawl box above the Scan button to scan the pages it links to."
    ]


def test_with_a_complete_crawl_there_is_no_such_note():
    assert not any("Only the target page" in n for n in notes({**RESULT, "pages": PAGES, "crawl": CRAWL}))


def test_pages_that_were_fetched_but_not_checked_are_explained():
    text = notes({**RESULT, "pages": PAGES, "crawl": CRAWL})
    assert (
        "Pages that are not HTML, or that answered with an error or a redirect, were fetched but not checked." in text
    )
    only_checked = notes({**RESULT, "pages": PAGES[:2], "crawl": {**CRAWL, "pages_visited": 2}})
    assert not any("fetched but not checked" in n for n in only_checked)


def test_a_list_cut_short_says_how_many_pages_there_were():
    result = {**RESULT, "pages": PAGES[:2], "crawl": {**CRAWL, "pages_visited": 900}}
    assert "Showing the first 2 of 900 pages." in notes(result)
    label = run(f"(renderPages({json.dumps(result)}), __byId('tab-urls').textContent)")
    assert label == "Scanned URLs (900)"


def test_no_pages_means_no_table_and_a_note():
    result = {**RESULT, "pages": [], "crawl": None}
    assert notes(result) == ["No page was fetched, so nothing was checked."]
    assert run(f"(renderPages({json.dumps(result)}), __byId('pages-table').hidden)") is True
    assert (
        run(f"(renderPages({json.dumps({**RESULT, 'pages': PAGES[:1], 'crawl': None})}), __byId('pages-table').hidden)")
        is False
    )


def test_a_result_from_a_server_without_pages_does_not_break_the_page():
    older = {k: v for k, v in RESULT.items() if k != "pages"}
    assert rows(older) == []


def test_a_new_result_brings_the_user_back_to_the_findings_tab():
    expression = (
        f"(selectTab('urls'), renderResult({json.dumps({**RESULT, 'pages': PAGES[:1], 'crawl': None})}), "
        "[__byId('tab-findings').getAttribute('aria-selected'), __byId('panel-urls').hidden])"
    )
    assert run(expression) == ["true", True]


def test_the_tabs_are_wired_to_the_clicks_and_the_keys():
    clicked = run(f"(__byId('tab-urls').listeners.click(), {STATE})")
    assert clicked["urls"] == ["true", 0, False]
    back = run(f"(__byId('tab-urls').listeners.click(), __byId('tab-findings').listeners.click(), {STATE})")
    assert back["findings"] == ["true", 0, False]
    keyed = run(
        "(selectTab('findings'), __byId('tab-findings').listeners.keydown({key: 'ArrowRight', preventDefault() {}}), "
        f"{STATE})"
    )
    assert keyed["urls"][0] == "true"
    keyed_on_the_other = run(
        "(selectTab('urls'), __byId('tab-urls').listeners.keydown({key: 'ArrowLeft', preventDefault() {}}), "
        f"{STATE})"
    )
    assert keyed_on_the_other["findings"][0] == "true"


def test_a_key_the_tabs_use_is_not_left_to_scroll_the_page():
    for key in ("ArrowRight", "ArrowLeft", "Home", "End"):
        expression = (
            "(selectTab('findings'), (() => { let prevented = false; "
            f"tabKeydown({{key: '{key}', preventDefault() {{ prevented = true; }}}}); return prevented; }})())"
        )
        assert run(expression) is True, key


def test_a_finished_scan_fills_the_scanned_urls_tab_through_renderResult():
    result = {**RESULT, "pages": PAGES, "crawl": CRAWL}
    label = run(f"(renderResult({json.dumps(result)}), __byId('tab-urls').textContent)")
    assert label == "Scanned URLs (4)"
    assert run(f"(renderResult({json.dumps(result)}), __byId('pages-body').children.length)") == 4
