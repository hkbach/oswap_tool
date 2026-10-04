# SRS – Non-intrusive Web Security Scanner

| | |
|---|---|
| **Tài liệu** | Software Requirements Specification (SRS) |
| **Sản phẩm** | Non-intrusive Web Security Scanner (CLI + Web UI cục bộ) |
| **Phiên bản tài liệu** | 1.24 |
| **Ngày** | 2026-10-01 (v1.0: 2026-09-22 · v1.1: 2026-09-23 · v1.2–v1.13: 2026-09-30 · v1.14–v1.18: 2026-10-01 · v1.19–v1.24: 2026-10-04) |
| **Chuẩn tham chiếu** | IEEE 830-1998 (rút gọn) |
| **Trạng thái** | Mô tả lại (as-built) mã nguồn `websec_scanner` `v1.24.0` trong repo `hkbach/oswap_tool` (CLI + Web UI cục bộ, sau Sprint 13 và đợt audit chất lượng toàn hệ thống ngày 2026-10-04). Đây là **tài liệu requirement duy nhất**; các bản SRS gửi rời trước đây không còn hiệu lực. |
| **Tài liệu liên quan** | `docs/PRODUCT-BACKLOG.md` (backlog, quyết định, sprint) · `CLAUDE.md` (quy tắc làm việc) · `docs/srs-feedback.md` (review 2026-09-23) |

**Quy ước trong tài liệu này**

- Các mục 1–11 mô tả **hành vi hiện có** của code. Muốn đổi hành vi phải có FR trong backlog và cập nhật tài liệu này cùng lúc.
- Mục 12 ghi các **quyết định đã chốt nhưng code chưa làm**. Khi FR mô tả hành vi mâu thuẫn với một quyết định ở mục 12, code vẫn đang theo FR; ô tương ứng có ghi chú "sẽ đổi theo …".
- Mục 13 ghi các điểm còn chờ xác nhận `[CONFIRM]`.

---

## 0. Lịch sử thay đổi

| Phiên bản | Ngày | Tóm tắt |
|---|---|---|
| 1.0 | 2026-09-22 | Bản as-built đầu tiên (code v1.0.0). |
| 1.1 | 2026-09-23 | Theo code v1.1.0: TLS kiểm tra 2 bước (FR-TLS-01…09); tách robots.txt/sitemap.xml (FR-EXP-08a/b); HSTS chỉ áp dụng cho `https://`; `frame-ancestors` loại trừ cả nhánh "thiếu" X-Frame-Options; `Finding.id` khai báo tường minh cho từng path; thêm AT-15…18. |
| 1.2 | 2026-09-30 | Gộp bản 1.1 ở trên với bản sửa tài liệu ngày 2026-09-30. Chi tiết ở mục 0.1. |
| 1.3 | 2026-09-30 | Theo code v1.2.0 (Sprint 3): mô hình finding có `cwe`/`confidence`/`references`/`instance_key`/`fingerprint` (FR-MODEL-01); JSON `schema_version` 1.1 và `docs/report.schema.json` (FR-MODEL-02); một bộ xử lý đầu ra dùng chung (FR-WEB-01); che secret mặc định (D2, FR-COOKIE-04, NFR-SEC-04); severity CORS theo D3; thứ tự finding cố định (FR-REPORT-02); NFR-PORT-01 đã kiểm chứng Python 3.9; AT-29…AT-33. |
| 1.4 | 2026-09-30 | Theo code v1.3.0 (Sprint 3b): phạm vi redirect D4 (NFR-SEC-05); redirect check luôn chạy và TLS theo redirect `http://` → HTTPS (FIX-09: FR-CLI-03/05, FR-REDIR-01/03); header xét trên response cuối, HSTS ở host gốc (FIX-10: FR-HDR-01/11), JSON `schema_version` 1.2 (`final_url`, `redirect_chain`); User-Agent có version thật, bỏ chữ "passive" (FIX-11: NFR-SEC-03); đính chính nguyên nhân B1 (Avast trên máy dev) và thêm rủi ro TLS bị phần mềm cục bộ chặn; AT-34…AT-37. |
| 1.5 | 2026-09-30 | Theo code v1.4.0 (Sprint 4, độ chính xác): bảng path nhạy cảm chuyển sang `rules/sensitive_paths.json` (FR-EXP-01); đọc body tối đa 8 KiB (NFR-PERF-04); kiểm tra nội dung bằng chữ ký (FR-DET-01: FR-EXP-03/04/06, bảng 4.8.1); soft-404 theo vân tay nội dung và URL redirect (FR-DET-02: FR-EXP-02/07); confidence cho finding đã kiểm tra nội dung (FR-DET-03); cảnh báo TLS bị chặn giữa đường (FR-DET-16: FR-TLS-11); AT-38…AT-41. |
| 1.6 | 2026-09-30 | Theo code v1.5.0 (Sprint 5, dùng trong CI): một kho chứng chỉ cho HTTP và TLS, mặc định là kho OS, `--ca-bundle` (FR-CI-10: FR-CLI-06, FR-TLS-08; B1 đã xử lý); `--fail-on` và exit code `3` (FR-CI-01: FR-CLI-04, mục 7.3, trường `gate`, `schema_version` 1.3; mục 13 không còn điểm chờ); `--sarif` (FR-RPT-02: FR-REPORT-06); `--html` (FR-RPT-09: FR-REPORT-07); template CI trong `examples/ci/` (FR-CI-03); AT-42…AT-46. |
| 1.7 | 2026-09-30 | Theo code v1.5.1 (Sprint 6, chất lượng repo; không đổi hành vi tool): workflow CI của repo (FR-QA-07); golden file JSON/SARIF/HTML (FR-QA-02); mọi finding ID có test (FR-QA-01); NFR-PORT-01 ghi ma trận CI; mục 10 thêm rủi ro Python 3.9 hết hỗ trợ; AT-47…AT-49. |
| 1.8 | 2026-09-30 | Theo code v1.6.0 (Sprint 7): Python ≥ 3.12 (NFR-PORT-01, mục 2; bỏ rủi ro 3.9 ở mục 10); Bước A của TLS chấp nhận TLS 1.0/1.1 và cipher cũ (FR-TLS-01, FR-TLS-04); che userinfo trong URL và gộp redaction theo fingerprint (NFR-SEC-04, AT-32); parse Set-Cookie theo RFC 6265 (FR-COOKIE-01, AT-04); robots/sitemap đọc tối đa 512 KiB, charset lạ không làm dừng check (NFR-PERF-04, AT-38); Web UI trả 500 khi quét lỗi (FR-UI-05, AT-26); `gate_status`/`gate_message` và `output.gate_message()` (FR-UI-09, mục 6.3); AT-50…AT-51. |
| 1.9 | 2026-09-30 | Theo code v1.7.0 (Sprint 8): nhóm mục tiêu kiểm thử `catalog.CHECK_GROUPS` và chọn nhóm khi quét (mục 4.11, FR-GRP-01…03); `--checks`, `--list-checks` (mục 7); JSON `schema_version` 1.4 với `scan_groups` và `check` (mục 6.2); Web UI chọn nhóm và nhóm kết quả theo test target/OWASP Top 10, `GET /api/checks`, `groups`/`owasp_groups` (FR-UI-10, FR-UI-11, mục 6.3); báo cáo HTML theo nhóm (FR-UI-07); AT-52…AT-55. |
| 1.10 | 2026-09-30 | Theo code v1.8.0 (Sprint 9, đóng Phase A): Web UI bind ra ngoài bắt buộc `--allow-remote` + access token (FR-UI-01, mục 6.3, 7); `output.SCOPE_NOTE` dùng chung cho console và HTML (FR-RPT-08, NFR-COMP-01); kiểm kê license `THIRD_PARTY_LICENSES.md` (FR-SEC-10, NFR-LEGAL-01); image Docker chính thức và job CI `docker` (FR-CI-04), sửa Jenkinsfile dùng source archive; rà lại toàn bộ README (FR-DOC-01); AT-56…AT-60. |
| 1.11 | 2026-09-30 | Theo code v1.9.0: **đổi tên package** `owasp_scanner`/`owasp-scanner` → `websec_scanner`/`websec-scanner` theo yêu cầu chủ sản phẩm (tool không còn giới hạn ở riêng OWASP). Đổi: import path, lệnh CLI, tên gói pip, User-Agent (NFR-SEC-03, breaking — WAF/log filter theo chuỗi cũ cần cập nhật), khoá `partialFingerprints` của SARIF (FR-REPORT-06, breaking — mất liên tục fingerprint trên GitHub code scanning), tên file báo cáo tải về, tiêu đề sản phẩm. Không đổi: `schema_version` (1.4), trường `owasp_category`/`owasp_groups`, hành vi CLI/Web UI, exit code. |
| 1.12 | 2026-09-30 | Theo code v1.10.0: JSON thêm `disclaimer` (FR-RPT-08, `schema_version` 1.5, mục 6.2, AT-57); Docker image publish lên `ghcr.io/hkbach/websec-scanner` qua job `docker-publish` chỉ khi push tag `v*` (FR-CI-04, AT-59); tiêu đề trang Web UI (`<title>`/`<h1>`) đổi thành "WebSec Scanner" theo yêu cầu chủ sản phẩm (cosmetic, không có FR riêng, không đổi hành vi). |
| 1.13 | 2026-09-30 | Theo code v1.11.0: bỏ tên công ty khỏi toàn bộ source code theo yêu cầu chủ sản phẩm (NFR-SEC-03: `User-Agent` không còn tiền tố tên công ty, chỉ còn `WebSec-Scanner/<version>`; các mục tài liệu khác nhắc tên công ty được viết lại theo nghĩa trung tính, không đổi ý; `docs/PRODUCT-BACKLOG.md`, `docs/srs-feedback.md`). Không đổi hành vi nào khác. |
| 1.14 | 2026-10-01 | Theo code v1.12.0 (Sprint 10): mỗi finding có `cvss_vector`/`cvss_score` CVSS v3.1 ước tính theo loại (FR-MODEL-03, `websec_scanner/cvss.py`, `catalog._CVSS_VECTORS`, mục 6.1); `schema_version` 1.6 (mục 6.2); console, báo cáo HTML và Web UI (FR-UI-12) hiển thị điểm kèm "(estimated)"; báo cáo HTML thêm mục "Top issues" và dòng "Reproduce" (chạy lại `--checks <group>`) cho mỗi finding — cả hai không đổi JSON schema (FR-RPT-01, cosmetic); sửa lỗi `<title>` báo cáo HTML còn sót "OWASP scan report" từ đợt đổi tên package; AT-61. |
| 1.15 | 2026-10-01 | Theo code v1.13.0 (Sprint 10, sau review bảng vector ngày 2026-10-01): sửa lại vector CVSS theo kịch bản tấn công thật (HSTS thiếu và không redirect HTTPS cùng 6.8; chứng chỉ hết hạn/chưa hiệu lực/không tin cậy 7.4 → 6.8; clickjacking 4.3; cookie thiếu `Secure` 3.1 → 5.3). Thêm `catalog.NO_CVSS`: finding không phải điểm yếu (cảnh báo sớm, gợi ý, mọi finding severity INFO — quyết định C1) **không có** `cvss_vector`/`cvss_score`. Check ghi đè vector theo từng instance, `enrich()` luôn tính lại điểm từ vector thắng (mục 6.1). SARIF `security-severity` lấy từ `cvss_score` (FR-REPORT-06, FR-RPT-10 — **đổi mức cảnh báo trên GitHub code scanning**). CWE-324 cho chứng chỉ hết hạn/sắp hết hạn (C2). `output.CVSS_NOTE` giải thích CVSS và Severity là hai thang khác nhau (console + HTML). **FR-DET-17**: nhận diện cipher yếu viết lại thành bảng khai báo có lý do, bịt chỗ bỏ lọt DES đơn 56-bit và suite ẩn danh `ADH-`/`AECDH-` (FR-TLS-04, AT-62). AT-61 mở rộng, AT-44 cập nhật. |
| 1.16 | 2026-10-01 | Theo code v1.14.0 (Sprint 11, kiểm soát quét an toàn): giới hạn lưu lượng mỗi lần quét `--rate-limit`/`--max-requests`/`--max-duration`, tự giảm tốc khi target trả 429/503 (FR-AUTHZ-05, mục 4.12, `limits.ScanLimiter`), áp ở tầng HTTP adapter nên tính cả redirect hop và retry, và truyền tường minh vào check TLS vốn tự mở socket; JSON thêm khối `limits`, `schema_version` 1.7; `gate.incomplete` nay còn đúng khi một giới hạn dừng lần quét giữa chừng. Phạm vi khai báo nhiều host `--scope-host` (FR-AUTHZ-03). Loại trừ URL `--exclude`/`--exclude-host`/`--no-default-excludes` với bảng mặc định `rules/exclusions.json` (FR-AUTHZ-06), chặn cả redirect dẫn vào path bị loại; `rules_version` thêm phần `exclusions`. Header tùy chọn `X-Scanner-Scan-Id` qua `--scan-id-header` (FR-AUTHZ-09). AT-63…AT-66. |
| 1.17 | 2026-10-01 | Theo code v1.15.0 (Sprint 12, CI với nợ cũ): `--baseline` — gate chỉ tính finding mới, khối `baseline` ghi finding đã sửa và finding chưa được kiểm lại (FR-CI-02, FR-RPT-06, mục 4.13 FR-BASE-01…05); `--suppressions` file TOML có lý do và ngày hết hạn bắt buộc (FR-MODEL-06, FR-SUPP-01…04); `--csv` chặn formula injection, `--junit` có số test fail khớp exit code (FR-RPT-03, FR-OUT-01/02); SARIF dùng `baselineState` và `suppressions` chuẩn (FR-REPORT-06); `schema_version` 1.8, `summary` giữ nguyên nghĩa. **FR-MODEL-07**: `instance_key` của finding CORS và `TLS-NO-HTTPS-REDIRECT` là `site_root()` thay vì URL đầy đủ, để fingerprint không đổi theo trang bắt đầu quét hay token trong query (mục 6.1). Sửa `gate_message` báo sai lý do khi lần quét bị một giới hạn dừng (`gate.incomplete_reason`, lỗi từ v1.14.0). Bổ sung bảng tham số mục 7: các cờ của Sprint 11 và `--allow-remote`/`--token` của Web UI bị thiếu từ v1.8.0. AT-67…AT-71. |
| 1.18 | 2026-10-01 | Theo code v1.16.0 (Sprint 13): file cấu hình `--config` (TOML, nghiêm ngặt, `${ENV}`, cảnh báo credential ghi thẳng; FR-CI-06, mục 4.14 FR-CFG-01…03); nhiều target với `--targets-file`, `--output-dir`/`--formats`, `--baseline-dir`, `--parallel`, exit code theo target tệ nhất, từ chối gửi credential tới nhiều host (FR-CI-05, FR-MULTI-01…05); `--header`, `--cookie` (che ở mọi nơi kể cả khi target phản xạ), `--proxy` `http://` cho cả check TLS qua `CONNECT`, `--user-agent` chỉ ghép trước (NFR-SEC-03), `--quiet`/`--verbose`, `--version` (FR-CI-07, FR-OPT-01…05). Không đổi `schema_version`. AT-72…AT-74. |
| 1.19 | 2026-10-04 | Theo code v1.17.0 (audit chất lượng toàn hệ thống, không thêm tính năng): target không quét được bị từ chối ở argparse thay vì chạy một lần quét rỗng, dùng chung quy tắc với Web UI (FR-CLI-01, FR-CLI-07, AT-75); console vô hiệu hoá ký tự điều khiển lấy từ target, vì site bị quét có thể xoá dòng và giả mạo kết luận (FR-REPORT-08, AT-76); `Location` dị dạng không còn làm sập lần quét (NFR-REL-01, AT-77); sửa AT-47 (trỏ tới test đã đổi tên, và ghi 5 job trong khi CI có 7); bảng tùy chọn Web UI trong README thiếu 3 cờ từ v1.14.0. |
| 1.20 | 2026-10-04 | Theo code v1.18.0 (audit chất lượng, phần 2: rà từng khẳng định của AT-02…AT-77 so với assertion thật của test, đối chiếu từng mục `[x]` của backlog, và mutation test 18 bất biến lõi — cả 18 đều bị suite bắt). Thay đổi hành vi duy nhất: lần GET trang chủ nay cũng tuân thủ exclusion, vì danh sách mặc định đúng là các path mà một GET có thể đăng xuất/xóa/thanh toán (FR-EXCL-02, AT-78). 17 assertion được siết lại (AT-04, 06, 19, 22, 32, 35, 37, 38, 41, 45, 50, 56, 57, 59, 62, 64, 65, 74, 75, AT-79). Sửa AT-30 (`schema_version` ghi 1.1) và AT-61 (ghi 1.6) — giá trị hiện tại là 1.8. |
| 1.21 | 2026-10-04 | Theo code v1.19.0 (gói D8, FR-WEB-07; branch `feat/sprint-16`): Web UI không nhận credential — `POST /api/scan` chỉ nhận `target`/`authorized`/`checks`, từ chối 400 mọi trường credential, trường lạ và target có `user:pass@` (FR-UI-13, AT-80); lỗi mới có `code`/`field` (mục 6.3); `show_secrets` gửi tới Web UI nay bị từ chối thay vì bỏ qua (AT-32). **Thay đổi hành vi:** script gửi trường thừa tới `/api/scan` trước đây được bỏ qua, nay nhận 400. |
| 1.22 | 2026-10-04 | Theo code v1.19.0 (gói D6, FR-QA-03a–d; branch `feat/d6-benchmark`): thêm công cụ benchmark độ chính xác `benchmarks/` (chấm điểm, cổng hồi quy nghiêm theo baseline, `docker-compose.yml` ghim digest chỉ bind loopback, workflow `benchmark.yml`) và AT-81. **Không đổi hành vi sản phẩm và không đổi `websec_scanner/`**, nên không nâng version. FR-QA-03a–d chưa được tick trong backlog: còn chờ CI chạy thật và duyệt ground truth. |
| 1.23 | 2026-10-04 | Theo code v1.20.0 (gói D7, FR-DET-04; branch `feat/d7-d9-tls-openapi`): TLS dò chủ động phiên bản giao thức và nhóm cipher yếu bằng ClientHello tự dựng (FR-TLS-12…16, AT-82), mặc định bật, tắt bằng `--no-tls-probe`; định nghĩa non-intrusive cập nhật (mục 1.2, NFR-SEC-01); `TLS-WEAK-PROTOCOL` và `TLS-WEAK-CIPHER` thành một finding cho mỗi giao thức/nhóm với `instance_key` `host:port:<tên>` (FR-TLS-03, FR-TLS-04). **Thay đổi hành vi:** server bật cả TLS cũ lẫn TLS 1.2 nay bị báo HIGH nên gate `--fail-on high` có thể đổi kết quả; fingerprint của hai finding này đổi một lần; tối đa 13 kết nối TLS thay vì 2. |
| 1.24 | 2026-10-04 | Theo code v1.21.0 (gói D9, FR-API-01a–d; branch `feat/d7-d9-tls-openapi`): `--api-spec FILE` đọc file OpenAPI 3.0/3.1 hoặc Swagger 2.0 và liệt kê server, endpoint, parameter, security scheme (mục 4.15, FR-SPEC-01…06, AT-83): đọc an toàn (safe loader, ngân sách alias, giới hạn độ sâu và kích thước, `$ref` chỉ trong thư mục của spec); `schema_version` 1.9 (khoá `api`, mục 6.2); dependency mới `pyyaml` (MIT). Không đổi hành vi hiện có: tool không gửi request nào tới thứ spec nêu, Web UI không nhận spec. |
| 1.25 | 2026-10-04 | Theo code v1.22.0 (gói crawler HTTP, FR-CRAWL-01/03/04; branch `feat/crawler-http`): `--crawl` đi theo link cùng origin (mặc định tắt) với `--crawl-depth`, `--crawl-max-pages`, `--crawl-max-duration`, `--ignore-robots`; chạy check header và cookie trên từng trang HTML và gộp cùng một lỗi thành một finding có `affected_urls`/`affected_count`. `schema_version` 1.10 (khoá `crawl`, hai trường mới của finding). Thêm mục 4.16 (FR-CRW-01…08), AT-84, bảng 7.2. Không SPA (FR-CRAWL-02 chưa làm). |
| 1.27 | 2026-10-04 | Theo code v1.24.0 (Web UI crawl, FR-UI-14; branch `feat/web-crawl`; chủ sản phẩm duyệt, gồm việc sửa quy tắc Web UI trong `CLAUDE.md`): trang nhập URL có checkbox crawl (mặc định bỏ chọn); `POST /api/scan` nhận thêm đúng một trường `crawl` (boolean); giới hạn crawl do người vận hành đặt lúc khởi động (`--crawl-depth`, `--crawl-max-pages`, `--crawl-max-duration`), Web UI luôn theo robots.txt; `GET /api/checks` thêm khoá `crawl`; trường riêng `crawl_message` (mục 6.3). Sửa FR-UI-13, FR-CRW-08; thêm FR-UI-14, AT-86. JSON báo cáo và `schema_version` 1.10 không đổi. |

### 0.1 Thay đổi trong bản 1.2

| # | Nội dung | Mục bị ảnh hưởng | Backlog |
|---|---|---|---|
| 1 | Sửa tham chiếu chéo: mục 3.2 ghi đúng phạm vi FR-CLI-01 → FR-REPORT-05. | 3.2 | FR-FIX-01 |
| 2 | Cột Severity của FR-COOKIE-01 ghi rõ "xem FR-COOKIE-02". | 4.4 | FR-FIX-02 |
| 3 | Đổi định vị "passive" thành "non-intrusive"; nêu rõ số request tool gửi. | Tên sản phẩm, 1.2, 2.1 | FR-FIX-04 |
| 4 | Thêm Web UI cục bộ (mục 3.3, nhóm FR-UI ở mục 4.10, CLI ở 7.4), đã đối chiếu với `web.py`. | 2.1, 2.3, 2.4, 3.1, 3.3, 4.10, 7.4 | FR-FIX-08 |
| 5 | Đưa vào FR 5 bản sửa đã có trong code sau v1.1.0 (A1–A5 của `docs/srs-feedback.md`). | FR-CLI-01, FR-CLI-03, FR-COOKIE-01, FR-EXP-06, FR-REPORT-05 | — |
| 6 | Thêm AT-19…AT-28 (bản sửa A1–A5 và Web UI); thêm cột "Test tự động" cho mọi AT. | 9 | FR-FIX-03 |
| 7 | Thêm NFR-USA-03 (ngôn ngữ mặc định tiếng Anh); ghi rõ Python 3.9 chưa được kiểm thử thực tế. | 5 | — |
| 8 | Viết lại rủi ro về kho chứng chỉ (B1) theo đúng bản chất; thêm rủi ro evidence chứa cookie trong báo cáo HTML. | 10 | FR-CI-10, FR-AUTH-02 |
| 9 | Thêm mục 12 (quyết định D1–D5, FIX-09, FIX-10) và mục 13 (exit code `3`). Quyết định 2026-09-23 "giữ CRITICAL cho CORS `*` + credentials" được thay bằng D3. | 12, 13, FR-CORS-02 | FR-FIX-07, FR-FIX-09, FR-FIX-10 |

---

## 1. Giới thiệu

### 1.1 Mục đích

Tài liệu này đặc tả yêu cầu chi tiết cho **Non-intrusive Web Security Scanner**: công cụ quét một website và đối chiếu cấu hình HTTP/TLS quan sát được với khuyến nghị của OWASP. Tài liệu dùng để:

- Lập trình và mở rộng tool (giữ đúng hành vi hiện có, hoặc port sang ngôn ngữ/kiến trúc khác).
- Viết acceptance test.
- Làm tài liệu tham chiếu khi bàn giao, đánh giá nội bộ hoặc trao đổi với khách hàng.

### 1.2 Phạm vi sản phẩm

Sản phẩm là một **công cụ Python** có hai lối vào dùng chung một lõi quét:

- **CLI** `python -m websec_scanner <target>`.
- **Web UI cục bộ** `python -m websec_scanner.web`, chạy trên máy người dùng (mục 3.3).

Tool nhận một URL hoặc hostname, gửi các request HTTP **GET thông thường, không chứa payload tấn công**, rồi trả về danh sách finding về cấu hình bảo mật. Mỗi finding có mức độ nghiêm trọng, mã OWASP Top 10:2021, evidence và khuyến nghị khắc phục. Kết quả xuất ra terminal (có màu), file JSON, hoặc trang web và báo cáo HTML.

Đây là **non-intrusive configuration scanner** (scanner cấu hình không xâm lấn), **không phải** DAST toàn diện (xem mục 2.4 và 10). Tool không hoàn toàn thụ động. Với một target `https://`, một lần quét gửi tới target khoảng **29 request GET** và **tối đa 13 kết nối TLS**:

| Nhóm | Request |
|---|---|
| Baseline (trang chủ) | 1 GET |
| TLS (mục 4.5) | Tối đa 13 kết nối TLS: 2 kết nối đọc và xác thực chứng chỉ + 11 probe (mục 4.5, FR-TLS-12), không gửi HTTP |
| Redirect HTTP → HTTPS (mục 4.6) | Nhập `https://`: 1 GET tới `http://<hostname>/` (thêm 1 GET cho mỗi bước redirect HTTP). Nhập `http://`: không gửi thêm, dùng chuỗi redirect của baseline |
| CORS (mục 4.7) | 1 GET có header `Origin` giả lập |
| Path nhạy cảm (mục 4.8) | 2 probe soft-404 (dùng chung với directory listing) + 17 path, mỗi response đọc tối đa 8 KiB |
| Directory listing | 6 thư mục |
| robots.txt, sitemap.xml | 2 GET |

Với target `http://` không chuyển sang HTTPS: không có nhóm TLS, còn 27 GET. Nếu target `http://` chuyển sang HTTPS, nhóm TLS chạy trên URL HTTPS đó (FR-CLI-05). Mỗi redirect trong phạm vi (NFR-SEC-05) cũng là một request, và mỗi lỗi kết nối được thử lại tối đa 1 lần (NFR-PERF-03). Tool không gửi payload khai thác và không thay đổi dữ liệu phía target.

> **Định nghĩa "non-intrusive" (quyết định D7, từ v1.20.0).** Tool không gửi payload khai thác, không gửi request làm thay đổi dữ liệu, không gửi bản tin giao thức dị dạng; chỉ gửi một số lượng **có giới hạn** request HTTP thông thường và **handshake TLS chuẩn**. Handshake TLS chuẩn gồm cả ClientHello cho phiên bản giao thức cũ hoặc nhóm cipher yếu (FR-TLS-12), không bao giờ được hoàn tất. Heartbleed, ROBOT, CCS injection, renegotiation DoS và CRIME thuộc E9 (active) và KHÔNG chạy ở chế độ mặc định.

### 1.3 Đối tượng đọc

Kỹ sư phần mềm và security engineer thực hiện code, mở rộng hoặc review tool; QA viết test case; kỹ sư tích hợp CI/CD.

### 1.4 Định nghĩa, từ viết tắt

| Thuật ngữ | Ý nghĩa |
|---|---|
| SRS | Software Requirements Specification |
| Finding | Một phát hiện đơn lẻ (một vấn đề cấu hình bảo mật) |
| Severity | Mức độ nghiêm trọng: CRITICAL, HIGH, MEDIUM, LOW, INFO |
| Target | URL/hostname được quét |
| Baseline | Request GET đầu tiên tới trang chủ target; các check header và cookie dùng response này |
| Soft-404 | Server trả HTTP 200 cho path không tồn tại (thay vì 404), gây false positive nếu không xử lý |
| Gate | Quy tắc quyết định pass/fail cho CI: fail khi có ít nhất 1 finding CRITICAL hoặc HIGH (FR-CLI-04) |
| ASVS | OWASP Application Security Verification Standard |
| DAST | Dynamic Application Security Testing (kiểm thử động, có gửi payload khai thác) |

### 1.5 Tài liệu tham khảo

- OWASP Secure Headers Project — <https://owasp.org/www-project-secure-headers/>
- OWASP Top 10:2021 — <https://owasp.org/Top10/>
- OWASP ASVS (V9 Communications, V14 Configuration) — <https://owasp.org/www-project-application-security-verification-standard/>
- `README.md` của repo.

---

## 2. Mô tả tổng quan

### 2.1 Bối cảnh sản phẩm

Tool chạy độc lập, không có server hay service riêng (quyết định D1, mục 12). Người dùng chạy `python -m websec_scanner <target>` từ terminal, gọi từ pipeline CI/CD, hoặc mở Web UI cục bộ chạy chung tiến trình với lõi quét (mục 3.3).

### 2.2 Đối tượng người dùng

- Kỹ sư bảo mật / DevSecOps kiểm tra nhanh cấu hình bảo mật trước khi release.
- Delivery/QA lead cần báo cáo nhanh về "vệ sinh" cấu hình HTTP của website nội bộ hoặc website khách hàng **đã được cấp phép**.
- Pipeline CI/CD chạy tự động, chặn build khi có finding CRITICAL/HIGH.

### 2.3 Giả định và ràng buộc

- Người vận hành **có quyền hợp pháp** để quét target (sở hữu hệ thống hoặc có văn bản uỷ quyền). Đây là ràng buộc bắt buộc — xem FR-CONSENT-01 và FR-UI-02.
- Target phản hồi HTTP(S) tiêu chuẩn; tool không hỗ trợ site yêu cầu đăng nhập/OAuth để vào trang chủ.
- Môi trường chạy có Python ≥ 3.12 và cài được các package `requests` ≥ 2.32.3, `urllib3` ≥ 2.0.0, `cryptography` ≥ 42, `pyyaml` ≥ 6.0.1 (mức tối thiểu được CI kiểm tra, job `min-deps`). `cryptography` dùng để đọc ngày hiệu lực của chứng chỉ độc lập với bước xác thực trust chain (mục 4.5).
- Web UI cục bộ là lối vào thứ hai của cùng lõi quét. Tài liệu này không đặc tả chi tiết giao diện màn hình.

### 2.4 Ngoài phạm vi (Out of scope)

Các mục sau **không** thuộc phạm vi bản đặc tả này (có thể nằm trong backlog):

- Gửi payload khai thác chủ động (SQL injection, XSS thật, command injection, brute-force đăng nhập, fuzzing).
- Crawl toàn site hoặc theo link nội bộ nhiều cấp.
- Kiểm tra business logic, broken authentication ở tầng ứng dụng, broken access control ở tầng dữ liệu (cần tài khoản test).
- Quét nhiều target trong một lần chạy.
- Web UI nhiều người dùng hoặc chạy như dịch vụ, lưu lịch sử quét lâu dài, dashboard. Web UI cục bộ một người dùng ở mục 3.3 **không** thuộc mục loại trừ này.

---

## 3. Kiến trúc hệ thống

### 3.1 Thành phần (module) và trách nhiệm

```
websec_scanner/
├── __main__.py        # Cho phép `python -m websec_scanner`
├── cli.py             # Entry point CLI: argparse, consent gate, run_scan() điều phối các check
├── web.py             # Web UI cục bộ: http.server, /api/scan, /api/report/<id>.html
├── static/            # index.html, app.js, app.css của Web UI
├── html_report.py     # render_html(): báo cáo HTML độc lập từ JSON mục 6.2
├── catalog.py         # Bảng cwe/confidence/references theo finding id; enrich() + fingerprint
├── output.py          # build_report() + gate_failed() + gate_message() + exit_code(): một bộ xử lý đầu ra cho CLI và Web UI
├── sarif.py           # to_sarif(): SARIF 2.1.0 từ báo cáo (FR-REPORT-06)
├── redact.py          # redact(): che giá trị cookie và tham số URL nhạy cảm (D2)
├── rule_loader.py     # Nạp + kiểm tra rules/*.json; rules_version
├── rules/             # Bảng khai báo dạng JSON: sensitive_paths.json (bảng 4.8.1), tls_interceptors.json (FR-TLS-11)
├── soft404.py         # Hồ sơ soft-404: 2 probe ngẫu nhiên, so vân tay nội dung/URL cuối
├── http_utils.py      # HTTP session dùng chung: timeout, User-Agent, retry có kiểm soát, phạm vi redirect (ScopedSession)
├── models.py          # Kiểu dữ liệu: Severity, Finding, ScanResult
├── report.py          # In báo cáo CLI (màu ANSI) + ghi file JSON
└── checks/
    ├── headers.py         # Security headers
    ├── cookies.py         # Cờ cookie (Secure/HttpOnly/SameSite)
    ├── tls_check.py       # TLS/chứng chỉ
    ├── redirect_check.py  # Redirect HTTP → HTTPS
    ├── cors_check.py      # Cấu hình CORS
    └── exposure.py        # Path nhạy cảm, directory listing, robots.txt, sitemap.xml
tests/                 # pytest offline: mock HTTP/HTTPS server, chứng chỉ tự sinh
```

Mỗi module trong `checks/` là **hàm gần như thuần**: nhận session/URL/dữ liệu response, trả về `list[Finding]`, không giữ state toàn cục, nên unit test độc lập được.

`run_scan()` trong `cli.py` là **nguồn sự thật duy nhất** cho kết quả quét: CLI và Web UI đều gọi hàm này. Mọi đầu ra (console, `--json`, response của Web UI, báo cáo HTML) được dựng từ **cùng một dict** do `output.build_report()` trả về, và quy tắc gate nằm ở một hàm duy nhất `output.gate_failed()` (FR-WEB-01).

### 3.2 Luồng xử lý chính (FR-CLI-01 → FR-REPORT-05)

1. Người dùng chạy `python -m websec_scanner <target> [options]`.
2. Tool in **consent banner** và hỏi xác nhận quyền quét (bỏ qua nếu có `--yes`). Từ chối → thoát với exit code `2`, không gửi request nào.
3. Chuẩn hoá target (FR-CLI-01).
4. Gửi GET baseline tới trang chủ target. Nếu thất bại, ghi lỗi vào `errors`, rồi:
   - nếu lỗi xảy ra ở tầng TLS (ví dụ chứng chỉ hết hạn hoặc không được tin cậy), vẫn chạy nhóm check TLS (mục 4.5) trên **đúng URL HTTPS bị lỗi** (có thể là bước redirect từ `http://`), rồi dừng; nếu target nhập `http://` và lỗi xảy ra sau khi đã chuyển sang HTTPS thì redirect check coi như đạt (FR-FIX-09);
   - các lỗi khác (DNS, timeout, connection refused) thì dừng ngay, báo cáo có 0 finding.
5. Nếu baseline thành công, chạy lần lượt các check theo thứ tự cố định: security-headers → cookies → tls (nếu chuỗi redirect của baseline có URL HTTPS) → http-to-https-redirect → hsts-start-host (chỉ khi redirect đổi host và kết thúc ở HTTPS, FR-HDR-11) → cors → sensitive-paths → directory-listing → robots-sitemap. Mỗi check trả về `list[Finding]`, gộp vào `ScanResult`. Check nào ném exception thì lỗi được ghi vào `errors` và các check sau vẫn chạy (FR-REPORT-05).
6. In báo cáo ra terminal (sắp xếp theo severity); nếu có `--json PATH`, ghi thêm file JSON.
7. Thoát với exit code theo FR-CLI-04.

### 3.3 Web UI cục bộ (as-built, đã đối chiếu `web.py` ngày 2026-09-30)

- Khởi động bằng `python -m websec_scanner.web` (tham số ở mục 7.4). Module `web.py` dùng `http.server` của Python (`ThreadingHTTPServer`), mặc định nghe ở `127.0.0.1:8765`. Không cần dependency ngoài.
- Trình duyệt tải 3 file tĩnh trong `websec_scanner/static/`: `index.html`, `app.js`, `app.css`. Trang không tải gì từ internet.
- Người dùng nhập URL/hostname, tick ô xác nhận quyền quét rồi bấm **Scan**. `app.js` gửi `POST /api/scan` với body JSON `{"target": "...", "authorized": true}` (kèm `"checks"` khi đã chọn nhóm). **Web UI không nhận credential (D8, FR-UI-13):** body chỉ được có 3 trường đó.
- Server kiểm tra request theo FR-UI-02…04, chuẩn hoá target như CLI, rồi gọi `run_scan(target, timeout, workers)` **ngay trong thread xử lý request** (đồng bộ). Mỗi lúc chỉ chạy một lần quét.
- Kết quả trả về là JSON đúng mục 6.2, kèm các trường riêng của Web UI: `gate_failed`, `gate_status`, `gate_message`, `crawl_message`, `report_id`, `report_url` (mục 6.3).
- Kết quả hiện ngay dưới ô nhập: bảng tổng hợp theo severity, trạng thái gate, lỗi non-fatal, danh sách finding có lọc theo severity. Nút **Download JSON** tải JSON cùng định dạng với `--json` của CLI.
- Link **Download Test result** nằm ngay dưới ô nhập URL, chỉ hiện khi có kết quả, và bị ẩn trong lúc đang quét lần mới. Link trỏ tới `GET /api/report/<id>.html`: server tạo báo cáo HTML bằng `render_html()` từ báo cáo đang giữ trong bộ nhớ và trả về dạng file tải xuống. Server giữ báo cáo của 20 lần quét gần nhất; tắt server là mất.
- Mọi chữ trên UI và trong báo cáo HTML là tiếng Anh (NFR-USA-03).

---

## 4. Yêu cầu chức năng (Functional Requirements)

Quy ước mã: `FR-<NHÓM>-<SỐ>`. Priority: **M**ust / **S**hould / **C**ould (MoSCoW).

### 4.1 Nhóm CLI & vòng đời chạy

| ID | Yêu cầu | Priority |
|---|---|---|
| FR-CLI-01 | Tool PHẢI nhận một tham số bắt buộc `target` (URL hoặc hostname). Nếu chuỗi nhập không chứa `://`, tool PHẢI thêm `https://` (kể cả dạng `host:port`, ví dụ `example.com:8443` → `https://example.com:8443/`). Tool PHẢI thêm `/` vào cuối **phần path** nếu chưa có, giữ nguyên query string (ví dụ `https://a.example/app?q=1` → `https://a.example/app/?q=1`). | M **Từ v1.16.0 (FR-CLI-07):** target không quét được PHẢI bị từ chối ngay ở argparse (exit code 2), trước khi in banner hay gửi request: scheme khác `http`/`https` (kể cả dạng không có `//` như `javascript:alert(1)`, `data:...`, phân biệt với `host:port` bằng việc phần sau dấu hai chấm có phải toàn chữ số không), thiếu hostname (`http://`, `https:///path`), hoặc chuỗi rỗng. Trước đó CLI nhận `ftp://...` rồi chạy một lần quét rỗng và báo lỗi kết nối khó hiểu, trong khi Web UI đã từ chối đúng (FR-UI-04); hai lối vào nay dùng chung `cli._normalize_target()`. |
| FR-CLI-02 | Tool PHẢI hỗ trợ các tham số tuỳ chọn: `--json PATH`, `--timeout N` (giây, mặc định 10), `--workers N` (số luồng cho check path nhạy cảm, mặc định 5), `--no-color`, `--yes`/`--i-have-authorization`. | M |
| FR-CLI-03 | Nếu GET baseline thất bại (lỗi kết nối/DNS/timeout/TLS), tool PHẢI ghi lỗi vào `errors`, KHÔNG được crash, và vẫn in được báo cáo. **Ngoại lệ:** nếu lỗi xảy ra ở tầng TLS (`requests.exceptions.SSLError`), tool PHẢI vẫn chạy nhóm check TLS (mục 4.5) trên **host:cổng của URL HTTPS bị lỗi** (lấy từ request gây lỗi; sau redirect `http://` → `https://` đó là bước HTTPS, không phải URL nhập vào) trước khi dừng. Lỗi kết nối thông thường không chạy nhóm TLS và báo cáo có 0 finding. | M |
| FR-CLI-04 | Exit code (FR-CI-01): `1` nếu có ít nhất 1 finding **bằng hoặc cao hơn ngưỡng `--fail-on`** (mặc định `high` = CRITICAL/HIGH); nếu không, `3` nếu **quét không hoàn tất** (GET baseline tới trang chủ thất bại), trừ khi `--fail-on none`; `2` nếu người dùng không xác nhận quyền quét; còn lại `0`. Finding vượt ngưỡng được ưu tiên hơn "không hoàn tất" (ví dụ chứng chỉ hết hạn làm baseline lỗi nhưng `TLS-CERT-EXPIRED` là CRITICAL → `1`). Báo cáo ghi ngưỡng và kết quả ở trường `gate`. *(Trước v1.5.0: không có `--fail-on`; target không kết nối được trả `0`.)* | M |
| FR-CLI-05 | Nhóm check TLS (mục 4.5) chạy trên **URL HTTPS đầu tiên trong chuỗi redirect của baseline**: chính target nếu nhập `https://`, hoặc URL mà target `http://` chuyển tới. Nếu chuỗi redirect không có URL HTTPS nào, KHÔNG chạy nhóm TLS. *(Trước FIX-09: không bao giờ chạy TLS cho target `http://`.)* | M |
| FR-CLI-06 | **Một kho chứng chỉ cho cả hai đường kết nối (FR-CI-10).** Request HTTP và Bước B của nhóm TLS PHẢI dùng **cùng một** `SSLContext`: nếu có `--ca-bundle PATH` (hoặc biến môi trường `REQUESTS_CA_BUNDLE` / `SSL_CERT_FILE`) thì dùng **đúng file đó thay cho kho mặc định**; nếu không thì dùng **kho chứng chỉ của hệ điều hành**, không dùng `certifi`. File không đọc được hoặc không phải chứng chỉ → lỗi tham số (exit code `2` của argparse). *(Trước v1.5.0: request HTTP tin `certifi`, TLS check tin kho OS — nguyên nhân B1.)* | M |

### 4.2 Nhóm xác nhận quyền quét (Consent Gate)

| ID | Yêu cầu | Priority |
|---|---|---|
| FR-CONSENT-01 | Trước khi gửi bất kỳ request nào tới target, CLI PHẢI hiển thị banner cảnh báo: tool chỉ gửi GET thông thường, không khai thác, nhưng quét không phép có thể vi phạm pháp luật/điều khoản dịch vụ. | M |
| FR-CONSENT-02 | Nếu không truyền `--yes`, CLI PHẢI hỏi xác nhận tương tác trước khi quét. Chỉ `y`/`yes` (không phân biệt hoa/thường, bỏ khoảng trắng hai đầu) được coi là đồng ý. | M |
| FR-CONSENT-03 | Nếu người dùng từ chối (hoặc input rỗng/EOF), tool PHẢI dừng ngay, KHÔNG gửi request nào, và thoát với exit code `2`. | M |
| FR-CONSENT-04 | `--yes` PHẢI cho phép bỏ qua bước hỏi tương tác (dùng trong CI/CD với hệ thống nội bộ đã được phê duyệt). Banner vẫn được in. | M |

Web UI có consent gate tương đương ở FR-UI-02.

### 4.3 Nhóm kiểm tra Security Headers (`checks/headers.py`)

Cơ sở: OWASP Secure Headers Project. Tên header so khớp không phân biệt hoa/thường. Các check dùng header của **response cuối** của baseline, sau khi đã theo các redirect trong phạm vi (NFR-SEC-05); URL của response đó được ghi ở `final_url` (mục 6.2). Cookie thì xét trên toàn chuỗi redirect (FR-COOKIE-01, D5).

| ID | Yêu cầu | Severity | OWASP | Priority |
|---|---|---|---|---|
| FR-HDR-01 | Nếu thiếu `Strict-Transport-Security`, PHẢI tạo finding `HDR-STRICT-TRANSPORT-SECURITY-MISSING`. Chỉ áp dụng khi **response cuối** của baseline (sau các redirect trong phạm vi) đến qua `https://`; nếu response cuối là HTTP thì bỏ qua hoàn toàn yêu cầu HSTS, vì trình duyệt bỏ qua HSTS gửi qua HTTP (FR-FIX-10). | HIGH | A02:2021 | M |
| FR-HDR-02 | Nếu thiếu `Content-Security-Policy`, PHẢI tạo finding `HDR-CONTENT-SECURITY-POLICY-MISSING`. | MEDIUM | A05:2021 | M |
| FR-HDR-03 | Nếu thiếu `X-Content-Type-Options`, PHẢI tạo finding `HDR-X-CONTENT-TYPE-OPTIONS-MISSING`. | LOW | A05:2021 | M |
| FR-HDR-04 | Nếu thiếu `X-Frame-Options`, PHẢI tạo finding `HDR-X-FRAME-OPTIONS-MISSING` — **trừ khi** CSP đã có directive `frame-ancestors` (điều kiện loại trừ chung ở FR-HDR-05). | MEDIUM | A05:2021 | M |
| FR-HDR-05 | Điều kiện loại trừ chung: nếu CSP có `frame-ancestors`, tool KHÔNG tạo finding nào về X-Frame-Options (cả "thiếu" lẫn "giá trị lạ"). Nếu không có `frame-ancestors` và X-Frame-Options khác `DENY`/`SAMEORIGIN` (không phân biệt hoa/thường), PHẢI tạo finding `HDR-XFO-WEAK`. | LOW | A05:2021 | S |
| FR-HDR-06 | Nếu thiếu `Referrer-Policy`, PHẢI tạo finding `HDR-REFERRER-POLICY-MISSING`. | LOW | A05:2021 | M |
| FR-HDR-07 | Nếu thiếu `Permissions-Policy`, PHẢI tạo finding `HDR-PERMISSIONS-POLICY-MISSING`. | INFO | A05:2021 | S |
| FR-HDR-08 | Nếu CSP chứa `unsafe-inline` hoặc `unsafe-eval` (không phân biệt hoa/thường), PHẢI tạo finding `HDR-CSP-UNSAFE`, evidence là giá trị CSP. | MEDIUM | A03:2021 | M |
| FR-HDR-09 | Nếu có `X-XSS-Protection` với giá trị khác `0`, PHẢI tạo finding `HDR-XXP-LEGACY` (khuyến nghị gửi `0` và dùng CSP). | INFO | A05:2021 | C |
| FR-HDR-10 | Với mỗi header rò rỉ thông tin có mặt (`Server`, `X-Powered-By`, `X-AspNet-Version`, `X-AspNetMvc-Version`), PHẢI tạo 1 finding riêng `HDR-INFO-<TÊN-HEADER>`, evidence là giá trị quan sát được. | INFO | A05:2021 | S |
| FR-HDR-11 | Nếu redirect của baseline **đổi host** (ví dụ `example.com` → `www.example.com`, trong phạm vi NFR-SEC-05) và response cuối là HTTPS, tool PHẢI gửi thêm 1 GET tới `https://<host ban đầu>/` (giữ cổng nếu target nhập `https://` có cổng riêng), không theo redirect. Nếu response không có `Strict-Transport-Security`, PHẢI tạo finding `HDR-HSTS-MISSING-ON-START-HOST` (`instance_key` = host ban đầu), vì trình duyệt chỉ áp `includeSubDomains`/`preload` từ host gửi header. Không kết nối được thì ghi lỗi `Check 'hsts-start-host' failed: …`, không tạo finding. | LOW | A02:2021 | S |

### 4.4 Nhóm kiểm tra Cookie (`checks/cookies.py`)

| ID | Yêu cầu | Severity | OWASP | Priority |
|---|---|---|---|---|
| FR-COOKIE-01 | Với mỗi header `Set-Cookie` của response baseline **và của mọi response redirect trung gian** trước nó, tool PHẢI parse tên cookie và kiểm tra 3 thuộc tính `Secure`, `HttpOnly`, `SameSite`. Mỗi cookie thiếu thuộc tính tạo 1 finding `COOKIE-FLAGS-MISSING`. Header được đọc như trình duyệt (RFC 6265, từ v1.6.0): cặp `tên=giá trị` đầu tiên là cookie, phần sau là thuộc tính (tên thuộc tính không phân biệt hoa/thường, thuộc tính lặp lại thì lấy giá trị sau cùng); thuộc tính không kiểm tra (`Priority`, `Partitioned`, …) bị bỏ qua thay vì bị hiểu thành cookie; header không có tên cookie hợp lệ bị bỏ qua. | — (xem FR-COOKIE-02) | A05:2021 | M |
| FR-COOKIE-02 | Thiếu `Secure` hoặc `HttpOnly` → MEDIUM. Chỉ thiếu `SameSite` (đã có Secure + HttpOnly) → LOW. | — | — | M |
| FR-COOKIE-03 | Nếu `SameSite` có giá trị không thuộc {`Lax`,`Strict`,`None`} (không phân biệt hoa/thường), PHẢI coi là thiếu và liệt kê giá trị sai trong finding. | — | — | S |
| FR-COOKIE-04 | Evidence PHẢI chứa header `Set-Cookie` gốc với **giá trị cookie được che**: giữ tên cookie và mọi thuộc tính, giá trị thay bằng `<redacted len=N>` (ví dụ `session=<redacted len=6>; Path=/`). Chỉ CLI với `--show-secrets` mới in nguyên văn (NFR-SEC-04). | — | — | S |

### 4.5 Nhóm kiểm tra TLS/Chứng chỉ (`checks/tls_check.py`)

Chạy theo FR-CLI-05 (URL HTTPS đầu tiên trong chuỗi redirect của baseline), hoặc khi baseline thất bại ở tầng TLS (FR-CLI-03).

Kiểm tra gồm **2 bước kết nối độc lập**, vì một context xác thực mặc định (`ssl.create_default_context()`) ném `SSLCertVerificationError` ngay khi bắt tay nếu chứng chỉ hết hạn, nên không bao giờ đọc được `notAfter`:

- **Bước A (không xác thực):** `verify_mode=ssl.CERT_NONE`, `check_hostname=False`; chỉ để đọc chứng chỉ thô (`getpeercert(binary_form=True)`) và giao thức/cipher đã thương lượng. Luôn thực hiện được bất kể trust.
- **Probe (từ v1.20.0, FR-TLS-12…16):** sau Bước A, một số kết nối ngắn hỏi server chấp nhận phiên bản giao thức nào và nhóm cipher yếu nào. Bước A chỉ cho biết **một** giao thức/cipher được thương lượng, nên server hỗ trợ TLS 1.2 mà vẫn bật TLS 1.0 trước đây không bị phát hiện.
- **Bước B (xác thực):** `ssl.create_default_context()`, chỉ để phát hiện lỗi trust chain/hostname, và **chỉ chạy khi Bước A cho thấy chứng chỉ đang trong thời hạn hiệu lực**, để không báo 2 CRITICAL cho cùng một nguyên nhân.

| ID | Yêu cầu | Severity | OWASP | Priority |
|---|---|---|---|---|
| FR-TLS-01 | Tool PHẢI thực hiện Bước A để lấy bytes chứng chỉ (DER), giao thức và cipher đã thương lượng. Bước này không được thất bại chỉ vì lý do trust/hostname, và PHẢI chấp nhận cả server chỉ hỗ trợ giao thức/cipher cũ: context của Bước A đặt `minimum_version = MINIMUM_SUPPORTED` và cipher `DEFAULT:ALL:@SECLEVEL=0` (từ v1.6.0). Trước v1.6.0, mặc định của Python (TLS 1.2+, SECLEVEL 2) khiến server chỉ có TLS 1.0/1.1 bị báo `TLS-CONN-FAILED` thay vì `TLS-WEAK-PROTOCOL`. `DEFAULT` đứng đầu nên server hiện đại vẫn thương lượng như với client thông thường. Bước B giữ mặc định nghiêm ngặt; với server chỉ có TLS < 1.2, Bước B không kết nối được và không kết luận về trust. | — | — | M |
| FR-TLS-02 | Nếu Bước A thất bại vì lý do kết nối (timeout, DNS, connection refused, lỗi OS/SSL khác), PHẢI tạo finding `TLS-CONN-FAILED` và DỪNG các kiểm tra TLS còn lại. | INFO | A02:2021 | M |
| FR-TLS-03 | PHẢI tạo **một** finding `TLS-WEAK-PROTOCOL` cho **mỗi** giao thức yếu {`SSLv3`,`TLSv1`,`TLSv1.1`} mà server chấp nhận: giao thức được thương lượng ở Bước A, hoặc giao thức mà một probe (FR-TLS-12) nhận được ServerHello. Giao thức Bước A thương lượng là `SSLv2` cũng được báo (không dò). `instance_key` = `host:port:<giao thức>` (**từ v1.20.0**; trước đó `host:port`, nên fingerprint của finding này đổi một lần). Evidence nói rõ thấy qua đường nào (thương lượng và/hoặc probe); một giao thức thấy qua cả hai chỉ là một finding. | HIGH | A02:2021 | M |
| FR-TLS-04 | PHẢI tạo **một** finding `TLS-WEAK-CIPHER` cho **mỗi nhóm** cipher yếu mà server chấp nhận: nhóm của suite Bước A thương lượng (nhận ra từ tên OpenSSL bằng `markers` trong `rules/tls_probe.json`, trước v1.20.0 là `tls_check._WEAK_CIPHER_MARKERS`), hoặc nhóm mà một probe chỉ đề nghị các suite của nó và server chọn một suite trong đó. Các nhóm là `NULL`, `EXPORT`, `ANON`, `RC4`, `RC2`, `3DES`, `DES`, `IDEA`, `MD5` (`RC2`, `IDEA`, `MD5` nhận ra khi thương lượng, không dò). `instance_key` = `host:port:<nhóm>` (**từ v1.20.0**; trước đó `host:port`). Mô tả PHẢI nêu **lý do** nhóm đó yếu ("A cipher suite the server accepts …"). Nhóm xét theo thứ tự mức nghiêm trọng giảm dần, mỗi nhóm một lý do: **không mã hoá** (`NULL`) hoặc **export grade** (`EXP-`, `EXP1024`, `EXPORT` — khoá 40–56 bit); **không xác thực hai bên** (`ADH-`, `AECDH-`); **đã bị phá nhưng vẫn mã hoá** (`RC4`, `RC2`, `3DES` khối 64-bit/SWEET32, `DES` đơn 56-bit — tách khỏi 3DES từ v1.20.0, `IDEA`, `MD5`). Lý do quyết định luôn điểm CVSS: hai nhóm đầu giữ trường hợp xấu nhất của catalog (7.4), nhóm cuối bị hạ xuống 5.9 (FR-MODEL-03). Từ v1.13.0 (FR-DET-17); trước đó danh sách `{RC4,3DES,MD5,NULL,EXPORT}` viết theo kiểu tên IANA nhưng lại so với tên OpenSSL, nên bỏ lọt cả **3DES** (`DES-CBC3-SHA` không chứa chuỗi `3DES`), DES đơn và suite ẩn danh, đồng thời không nhận ra tên export của OpenSSL. *(OpenSSL 3 thường không còn RC4/EXPORT, nên các suite này chỉ phát hiện được khi OpenSSL của máy quét còn hỗ trợ.)* | HIGH | A02:2021 | M |
| FR-TLS-05 | Tool PHẢI giải mã chứng chỉ DER từ Bước A bằng `cryptography` để đọc `not_valid_before`/`not_valid_after`. Nếu hiện tại sớm hơn `not_valid_before`, PHẢI tạo finding `TLS-CERT-NOT-YET-VALID`. | CRITICAL | A02:2021 | S |
| FR-TLS-06 | Nếu hiện tại trễ hơn `not_valid_after`, PHẢI tạo finding `TLS-CERT-EXPIRED`, dựa hoàn toàn vào dữ liệu Bước A. | CRITICAL | A02:2021 | M |
| FR-TLS-07 | Nếu chứng chỉ còn hiệu lực nhưng còn dưới 30 ngày, PHẢI tạo finding `TLS-CERT-EXPIRING-SOON`. Ngưỡng 30 ngày là hằng số `_CERT_EXPIRY_WARN_DAYS` ở đầu module. | MEDIUM | A02:2021 | S |
| FR-TLS-08 | Tool PHẢI thực hiện Bước B (kết nối xác thực bằng kho chứng chỉ của FR-CLI-06, giống hệt request HTTP) **chỉ khi** FR-TLS-05 và FR-TLS-06 không tạo finding. Nếu Bước B ném `SSLCertVerificationError`, PHẢI tạo finding `TLS-CERT-NOT-TRUSTED` với thông điệp lỗi gốc (gộp các nguyên nhân: tự ký, thiếu intermediate, sai hostname, CA không được tin cậy). Lỗi kết nối ở Bước B không tạo finding. | CRITICAL | A02:2021 | M |
| FR-TLS-09 | Nếu FR-TLS-05 hoặc FR-TLS-06 đã tạo finding, tool PHẢI bỏ qua Bước B, không tạo thêm `TLS-CERT-NOT-TRUSTED`. | — | — | M |
| FR-TLS-10 | Nếu không giải mã được chứng chỉ, PHẢI tạo finding `TLS-CERT-PARSE-FAILED` và vẫn chạy Bước B. | INFO | A02:2021 | C |
| FR-TLS-11 | **Phát hiện TLS bị chặn giữa đường (FR-DET-16).** Nếu issuer của chứng chỉ đọc được ở Bước A chứa một từ khoá trong `rules/tls_interceptors.json` (phần mềm diệt virus có web shield, gateway TLS inspection, proxy debug; không bao giờ là tên CA công khai), tool PHẢI ghi **một cảnh báo** vào `errors` (nêu host:port và issuer) và đặt `confidence` của mọi finding TLS của lần kiểm tra đó là `low`. Đây là cảnh báo, không phải finding. | — | — | S |
| FR-TLS-12 | **Dò chủ động (FR-DET-04, quyết định D7, từ v1.20.0).** Sau Bước A thành công, và trừ khi tắt bằng `--no-tls-probe`, tool PHẢI chạy các probe. Mỗi probe là **một kết nối TCP gửi đúng một bản ghi TLS**: ClientHello chuẩn tự dựng bằng `socket` + `struct` (không dùng OpenSSL, vì OpenSSL hiện đại không thể đề nghị SSLv3 hay suite export), đọc phản hồi đầu tiên (ServerHello hoặc alert) rồi đóng. Không hoàn tất bắt tay, không gửi dữ liệu ứng dụng, không gửi bản tin dị dạng. **5 probe phiên bản** (SSLv3, TLS 1.0, 1.1, 1.2, 1.3), mỗi probe chỉ đề nghị đúng một phiên bản; ServerHello mang phiên bản khác (thấp hơn) nghĩa là phiên bản đó **chưa bật**. **6 probe nhóm cipher yếu** (`NULL`, `EXPORT`, `ANON`, `RC4`, `3DES`, `DES`), mỗi probe chỉ đề nghị các suite của nhóm, tới TLS 1.2. Dữ liệu (phiên bản, mã suite và tên theo registry IANA, giới hạn) nằm ở `rules/tls_probe.json` và được ghi vào `rules_version`. SSLv2 không được dò. Probe không chạy khi Bước A thất bại (`TLS-CONN-FAILED`). SNI chỉ gửi cho tên miền, không gửi cho địa chỉ IP. | – | A02:2021 | M |
| FR-TLS-13 | **Giới hạn của probe.** Mỗi probe là một kết nối: PHẢI qua `ScanLimiter` (`--rate-limit` và `--max-requests` áp dụng; `ScanLimitReached` dừng cả lần quét, không bị nuốt), qua `--proxy` bằng `CONNECT`, nghỉ `pause_seconds` (0,2 giây) giữa hai probe, mỗi probe tối đa `probe_timeout_seconds` (5 giây, không vượt `--timeout`), và tổng số kết nối của nhóm TLS (gồm 2 kết nối chứng chỉ) không vượt `max_connections` (30). Hết ngân sách thì các probe còn lại không chạy và được ghi vào `errors` (FR-TLS-14). Nếu không **mở được** kết nối TCP ở một probe thì dừng các probe còn lại ngay, vì mỗi probe sau sẽ chờ hết cùng một timeout. | – | – | M |
| FR-TLS-14 | **Không im lặng.** Probe không chạy được (không kết nối được, hết giờ không phản hồi, phản hồi không phải TLS, hết ngân sách) PHẢI được ghi vào `errors` dạng `Could not test whether host:port accepts <danh sách> (<lý do>)`, **một dòng cho mỗi lý do**, và KHÔNG tạo finding. Server trả alert hoặc đóng/reset kết nối sau ClientHello được coi là **không chấp nhận**, không phải lỗi. | – | – | M |
| FR-TLS-15 | **Tắt được.** `--no-tls-probe` (khoá config `tls_probe = false`; tuỳ chọn khởi động `--no-tls-probe` của Web UI, trình duyệt không đổi được) tắt toàn bộ probe: chỉ còn hai kết nối chứng chỉ, finding từ kết quả thương lượng vẫn dùng khoá mới `host:port:<tên>`. Mặc định **bật**. Banner xác nhận và mô tả nhóm `tls` nêu số kết nối tối đa (13) và việc probe có thể xuất hiện trong log của target. | – | – | M |
| FR-TLS-16 | Finding sinh từ probe chịu cùng quy tắc FR-TLS-11: khi Bước A cho thấy TLS bị chặn giữa đường, mọi finding TLS, kể cả của probe, hạ `confidence` xuống `low`. | – | – | M |

### 4.6 Nhóm kiểm tra Redirect HTTP → HTTPS (`checks/redirect_check.py`)

| ID | Yêu cầu | Severity | OWASP | Priority |
|---|---|---|---|---|
| FR-REDIR-01 | Redirect check **luôn chạy** khi baseline thành công (FR-FIX-09). **Target nhập `https://`:** tool PHẢI probe `http://<hostname>/` (cổng 80) và tự theo từng bước redirect (tối đa 10, trong phạm vi NFR-SEC-05) mà **không tải trang HTTPS nào**: gặp `Location` trỏ tới `https://` là đạt, nên lỗi chứng chỉ không làm redirect check kết luận sai. **Target nhập `http://`:** tool PHẢI kết luận từ chuỗi redirect của chính baseline, không gửi thêm request; nếu baseline dừng ở một redirect bị chặn vì ngoài phạm vi thì không kết luận. | — | — | M |
| FR-REDIR-02 | Nếu request HTTP không có phản hồi (cổng 80 đóng theo thiết kế), KHÔNG coi là finding. | — | — | M |
| FR-REDIR-03 | Nếu chuỗi redirect kết thúc ở một response HTTP (không redirect tiếp) mà chưa gặp URL `https://` nào, PHẢI tạo finding `TLS-NO-HTTPS-REDIRECT`, mô tả nêu URL bắt đầu và URL cuối. Với target nhập `http://`, finding này làm exit code thành `1` (HIGH). | HIGH | A02:2021 | M |

### 4.7 Nhóm kiểm tra CORS (`checks/cors_check.py`)

Chỉ gửi 1 GET với header `Origin` giả lập, rõ ràng là request kiểm thử (không dùng domain thật của bên thứ ba), không gửi credential.

| ID | Yêu cầu | Severity | OWASP | Priority |
|---|---|---|---|---|
| FR-CORS-01 | Tool PHẢI gửi GET tới target kèm `Origin: https://websec-scanner-cors-test.invalid`. | — | — | M |
| FR-CORS-02 | Nếu `Access-Control-Allow-Origin: *` và `Access-Control-Allow-Credentials: true` cùng xuất hiện, PHẢI tạo finding `CORS-WILDCARD-WITH-CREDENTIALS`. Mô tả PHẢI nêu rõ trình duyệt từ chối request có credentials khi origin là `*`, nên tổ hợp này không khai thác trực tiếp được qua trình duyệt; nó cho thấy CORS bị cấu hình sao chép/nhầm và client không phải trình duyệt vẫn có thể làm theo, nên cần rà soát toàn bộ policy. *(Trước D3, ngày 2026-09-30, mức này là CRITICAL.)* | MEDIUM | A05:2021 | M |
| FR-CORS-03 | Nếu `Access-Control-Allow-Origin` phản xạ đúng Origin giả lập, PHẢI tạo finding `CORS-REFLECTS-ARBITRARY-ORIGIN`: HIGH nếu có `Access-Control-Allow-Credentials: true` (mọi website người dùng đã đăng nhập ghé qua đều đọc được response có xác thực), ngược lại MEDIUM (chỉ đọc được response không xác thực). | HIGH/MEDIUM | A05:2021 | M |
| FR-CORS-04 | Nếu `Access-Control-Allow-Origin: *` không kèm credentials, PHẢI tạo finding `CORS-WILDCARD` (chấp nhận được với API công khai, không xác thực). | INFO | A05:2021 | S |

### 4.8 Nhóm kiểm tra lộ file/path nhạy cảm (`checks/exposure.py`)

| ID | Yêu cầu | Priority |
|---|---|---|
| FR-EXP-01 | Tool PHẢI duy trì danh sách path nhạy cảm kèm `Finding.id` và severity (bảng 4.8.1) trong file dữ liệu **`websec_scanner/rules/sensitive_paths.json`**, được kiểm tra khi nạp (thiếu trường, severity lạ, id hoặc path trùng, path tuyệt đối → lỗi rõ ràng). Thêm path chỉ cần sửa file này, không sửa code. Trường `version` của file là `rules_version` trong báo cáo. | M |
| FR-EXP-02 | **Soft-404 theo vân tay nội dung (FR-DET-02).** Mỗi lần quét, tool PHẢI gửi 2 probe tới path ngẫu nhiên chắc chắn không tồn tại (một dạng file `websec-scanner-probe-<hex>.txt`, một dạng thư mục `websec-scanner-probe-<hex>/`; phần hex mới cho mỗi lần quét) và ghi lại các probe trả 200. Một response 200 của path nhạy cảm hoặc thư mục bị coi là "không tồn tại" nếu (a) nó đi qua redirect và dừng ở **cùng URL cuối** với một probe cũng bị redirect (ví dụ mọi path về `/login`), hoặc (b) nội dung giống một probe từ **90%** trở lên (so 4 KiB đầu, sau khi bỏ chuỗi path mà trang in lại và gộp khoảng trắng). Một profile dùng chung cho check path nhạy cảm và directory listing. | M |
| FR-EXP-03 | Tool KHÔNG được tạo finding lộ file chỉ dựa trên mã 200. Trang chung trả 200 cho mọi path (SPA, trang lỗi tuỳ biến, trang chặn của WAF) không tạo finding: phần lớn vì không khớp chữ ký nội dung (FR-EXP-04), phần còn lại vì bị nhận là soft-404 (FR-EXP-02) dù vô tình khớp chữ ký. Một file thật bị lộ trên site như vậy vẫn được phát hiện. | M |
| FR-EXP-04 | Nếu path trả HTTP 200 **và nội dung (tối đa 8 KiB đầu, NFR-PERF-04) khớp chữ ký của path** (cột "Chữ ký nội dung" bảng 4.8.1, khai báo trong `rules/sensitive_paths.json`), PHẢI tạo finding với id và severity đã khai báo, category `A01:2021 - Broken Access Control`. Chữ ký là regex trên text đã giải mã và/hoặc magic bytes ở đầu file; body là trang HTML (`<!doctype html`/`<html`) thì không khớp, trừ path được đánh dấu `allow_html`. Evidence gồm mã trạng thái, URL và mô tả chữ ký đã khớp; **KHÔNG BAO GIỜ chứa nội dung file** (có thể là secret thật). | M |
| FR-EXP-05 | Các request kiểm tra path PHẢI chạy song song có giới hạn (thread pool), số luồng tối đa lấy từ `--workers` (mặc định 5). | M |
| FR-EXP-06 | `.well-known/security.txt` được xử lý riêng: nếu trả 200 và nội dung có trường `Contact:` (RFC 9116), tạo finding INFO `EXPOSURE-SECURITY-TXT` mang tính tích cực, không phải lỗ hổng. | S |
| FR-EXP-07 | Tool PHẢI kiểm tra directory listing tại `images/`, `uploads/`, `backup/`, `files/`, `assets/`, `static/`. Nếu response 200, không bị nhận là soft-404 (FR-EXP-02), và 2000 ký tự đầu chứa `Index of /`, `<title>Index of` hoặc `Directory Listing For`, PHẢI tạo finding `EXPOSURE-DIR-LISTING` mức MEDIUM, category A05:2021. | M |
| FR-EXP-08a | Tool PHẢI tải `robots.txt` (nếu có), trích các dòng `Disallow:`, lọc path chứa từ khoá nhạy cảm (`admin`, `backup`, `config`, `internal`, `private`, `secret`, `staging`, `test`; không phân biệt hoa/thường). Có ít nhất 1 path khớp → finding `EXPOSURE-ROBOTS-HINTS` mức LOW, A01:2021, evidence là tối đa 10 path đầu. | S |
| FR-EXP-08b | Tool PHẢI tải `sitemap.xml` (nếu có), trích nội dung thẻ `<loc>…</loc>`, lấy phần path của từng URL và so với cùng danh sách từ khoá. Có ít nhất 1 URL khớp → finding `EXPOSURE-SITEMAP-HINTS` mức LOW, A01:2021, evidence là tối đa 10 URL đầu. | S |

**Bảng 4.8.1 — Danh sách path nhạy cảm mặc định.** `Finding.id` khai báo tường minh cho từng path, không suy ra từ chuỗi path. Regex đầy đủ nằm trong `websec_scanner/rules/sensitive_paths.json`.

| Path | `Finding.id` | Severity | Chữ ký nội dung |
|---|---|---|---|
| `.git/HEAD` | `EXPOSURE-GIT-HEAD` | CRITICAL | a git HEAD reference |
| `.git/config` | `EXPOSURE-GIT-CONFIG` | CRITICAL | a git config file |
| `.env` | `EXPOSURE-ENV` | CRITICAL | KEY=VALUE environment variables |
| `.env.local` | `EXPOSURE-ENV-LOCAL` | CRITICAL | KEY=VALUE environment variables |
| `.env.production` | `EXPOSURE-ENV-PRODUCTION` | CRITICAL | KEY=VALUE environment variables |
| `wp-config.php.bak` | `EXPOSURE-WP-CONFIG-BAK` | CRITICAL | PHP source code |
| `config.php.bak` | `EXPOSURE-CONFIG-PHP-BAK` | CRITICAL | PHP source code |
| `web.config` | `EXPOSURE-WEB-CONFIG` | MEDIUM | an IIS/ASP.NET configuration file |
| `.svn/entries` | `EXPOSURE-SVN-ENTRIES` | HIGH | a Subversion entries file |
| `.DS_Store` | `EXPOSURE-DS-STORE` | LOW | a macOS .DS_Store file; magic `0000000142756431` |
| `docker-compose.yml` | `EXPOSURE-DOCKER-COMPOSE` | HIGH | a Docker Compose file |
| `backup.zip` | `EXPOSURE-BACKUP-ZIP` | HIGH | a ZIP archive; magic `504b0304` |
| `backup.sql` | `EXPOSURE-BACKUP-SQL` | CRITICAL | an SQL dump |
| `phpinfo.php` | `EXPOSURE-PHPINFO` | MEDIUM | phpinfo() output; chấp nhận HTML |
| `server-status` | `EXPOSURE-SERVER-STATUS` | MEDIUM | an Apache server-status page; chấp nhận HTML |
| `id_rsa` | `EXPOSURE-ID-RSA` | CRITICAL | a private key |
| `.well-known/security.txt` | `EXPOSURE-SECURITY-TXT` | INFO (xử lý riêng, FR-EXP-06) | a security.txt policy (RFC 9116) |

### 4.9 Nhóm báo cáo kết quả (`report.py`)

| ID | Yêu cầu | Priority |
|---|---|---|
| FR-REPORT-01 | CLI PHẢI in: target, thời điểm bắt đầu/kết thúc (UTC, ISO 8601, hậu tố `Z`), danh sách check đã chạy, bảng tổng hợp theo severity, và chi tiết từng finding (severity, title, OWASP category, description, evidence nếu có, recommendation nếu có, URL). | M |
| FR-REPORT-02 | Finding trong output CLI, JSON và HTML PHẢI sắp xếp theo severity giảm dần: CRITICAL → HIGH → MEDIUM → LOW → INFO; cùng severity thì theo `id`, rồi `instance_key`, để hai lần quét cùng một target cho cùng thứ tự. | M |
| FR-REPORT-03 | Với `--no-color`, output CLI KHÔNG được chứa mã ANSI. | M |
| FR-REPORT-04 | Với `--json PATH`, tool PHẢI ghi file JSON hợp lệ theo mục 6.2, UTF-8, `ensure_ascii=False`. | M |
| FR-REPORT-05 | Nếu một check gặp lỗi non-fatal (timeout, lỗi parse, exception bất kỳ), tool PHẢI hoàn tất các check còn lại và ghi lỗi vào `errors` dạng `Check '<tên check>' failed: <mô tả exception>`. Tên check vẫn có trong `checks_run`. | M |
| FR-REPORT-06 | Với `--sarif PATH`, tool PHẢI ghi báo cáo **SARIF 2.1.0** dựng từ cùng dict của `output.build_report()` (secret đã che). Mỗi `Finding.id` là một rule (`shortDescription` = title, `helpUri` = reference đầu tiên, `help` = recommendation, `properties.tags` gồm OWASP và CWE, `properties.precision` = confidence, `properties.security-severity` = `cvss_score` ước tính của finding nặng nhất mang id đó (FR-MODEL-03, từ v1.13.0); finding trong `catalog.NO_CVSS` không có điểm nên quay về bảng theo severity: CRITICAL 9.5, HIGH 8.0, MEDIUM 5.5, LOW 3.0, INFO 0.0); mỗi finding là một result (`level`: CRITICAL/HIGH → `error`, MEDIUM → `warning`, LOW/INFO → `note`; `locations` = URL của finding; `partialFingerprints.websecScannerFingerprint/v1` = `fingerprint`; từ v1.15.0, `baselineState` = `baseline_state` khi có `--baseline`, và `suppressions` = `[{kind: "external", status: "accepted", justification}]` khi finding bị suppress — finding đã sửa **không** được phát thành result `absent` vì một số công cụ code scanning sẽ mở nó thành alert). `errors` thành `toolExecutionNotifications`; `executionSuccessful` là `false` khi quét không hoàn tất. Kết quả trỏ tới URL, không phải file trong repo, nên công cụ code scanning (ví dụ GitHub) sẽ không gắn được vào dòng code. | S |
| FR-REPORT-08 | Mọi văn bản **lấy từ target** khi in ra console (title, description, evidence, recommendation, url, owasp_category, target, `errors`, và title của finding trong khối so sánh baseline) PHẢI đi qua `report.printable_text()`: ký tự điều khiển C0 (trừ tab), DEL và dải C1 (gồm cả CSI 8-bit `\x9b`) được đổi thành dạng nhìn thấy `\xNN`, không bị xoá hẳn (xoá hẳn thì target giấu được một phần giá trị nó kiểm soát). Nếu không, site bị quét có thể đặt chuỗi escape vào header rồi **xoá các dòng finding scanner vừa in và viết kết luận giả** vào chỗ đó — tức đối tượng bị đo điều khiển được kết quả đo. Mã màu của chính scanner không bị ảnh hưởng. Báo cáo JSON/SARIF giữ nguyên byte thật (JSON tự escape), vì đó là định dạng cho máy đọc. (từ v1.16.0) | M |
| FR-REPORT-07 | Với `--html PATH`, tool PHẢI ghi báo cáo HTML bằng **cùng hàm `render_html()`** mà Web UI dùng cho "Download Test result" (FR-UI-06, FR-UI-07), từ cùng dict của `output.build_report()`: cho cùng một báo cáo, file HTML của CLI và của Web UI giống hệt nhau. Có `--show-secrets` thì báo cáo hiện băng cảnh báo (NFR-SEC-04). | S |
| FR-RPT-08 | Console (`print_report()`), báo cáo HTML (`render_html()`) và JSON (`output.build_report()`, trường `disclaimer`, từ v1.10.0) PHẢI mang một đoạn **phạm vi & giới hạn** dùng chung một nguồn văn bản duy nhất (`output.SCOPE_NOTE`, từ v1.8.0): nêu rõ đây là kiểm tra cấu hình không xâm lấn, không phải DAST toàn diện, không phát hiện SQLi/XSS thật, lỗi business logic hay lỗi xác thực ở tầng ứng dụng; và nêu rõ **báo cáo sạch không có nghĩa là target an toàn**, chỉ có nghĩa là các check này không tìm thấy gì. Không định dạng nào (console, JSON, HTML, SARIF) được dùng ngôn ngữ đảm bảo tuyệt đối (ví dụ "100% secure", "guaranteed", "risk-free"). | M |

### 4.10 Nhóm Web UI cục bộ (`web.py`, `static/`, `html_report.py`)

Tiền tố `FR-UI` mô tả hành vi đã có. Các cải tiến dự kiến nằm trong backlog với tiền tố `FR-WEB` (E12a).

| ID | Yêu cầu | Priority |
|---|---|---|
| FR-UI-01 | Server PHẢI mặc định bind `127.0.0.1`. Bind địa chỉ không phải loopback PHẢI qua cờ tường minh `--allow-remote`; thiếu cờ này, tool PHẢI thoát (exit code 2) trước khi mở socket, không bind. Có `--allow-remote`, tool PHẢI in cảnh báo và **bắt buộc access token** trên mọi request (header `X-Scanner-Token`, query `?token=` hoặc cookie do server cấp sau lần đầu xác thực qua query); token ngẫu nhiên (`secrets.token_urlsafe(32)`) trừ khi có `--token`; token PHẢI được che khi ghi log server (từ v1.8.0). | M |
| FR-UI-02 | `POST /api/scan` PHẢI từ chối (HTTP 400, không quét) nếu trường `authorized` không phải đúng giá trị JSON `true`. UI PHẢI có ô xác nhận quyền quét và không gửi request khi chưa tick. | M |
| FR-UI-03 | Khi server bind loopback, mọi request có `Host` không phải loopback PHẢI bị từ chối (403) để chống DNS rebinding. `POST /api/scan` có `Origin` khác `Host` PHẢI bị từ chối (403). | M |
| FR-UI-04 | `POST /api/scan` PHẢI yêu cầu `Content-Type: application/json` (415 nếu khác), body tối đa 4096 byte (413), là JSON object hợp lệ (400), `target` là chuỗi không rỗng và sau chuẩn hoá có scheme `http`/`https` và hostname (400). | M |
| FR-UI-05 | Mỗi lúc chỉ chạy một lần quét; request quét thứ hai trong lúc đang quét PHẢI nhận 429. Nếu lần quét gặp lỗi nội bộ (exception), server PHẢI trả 500 với `{"error": "The scan failed with an internal error; see the server console for details."}`, ghi một dòng đã che secret ra stderr, và giải phóng lượt quét (từ v1.6.0; trước đó kết nối bị đóng không có response). | M |
| FR-UI-06 | Sau mỗi lần quét, server PHẢI lưu báo cáo trong bộ nhớ dưới một id ngẫu nhiên không đoán được (`secrets.token_urlsafe(16)`), giữ tối đa 20 báo cáo gần nhất. `GET /api/report/<id>.html` PHẢI trả báo cáo HTML dạng tệp đính kèm (`Content-Disposition: attachment`, tên `websec-scan-<host>-<thời điểm>.html`); id không tồn tại → 404. | M |
| FR-UI-07 | Báo cáo HTML (`render_html()`) PHẢI là một tệp độc lập: CSS nhúng, không có script, không tải tài nguyên ngoài; mọi giá trị lấy từ target PHẢI được HTML-escape. Nội dung gồm thời gian, nhóm kiểm thử đã chọn và **nhóm không được chọn (not tested)**, check đã chạy, trạng thái gate, bảng tổng hợp, lỗi non-fatal, và (từ v1.7.0) bảng *Summary by test target* (trạng thái và số finding theo severity của từng nhóm mục 4.11, từ `output.group_findings()`), bảng *Summary by OWASP Top 10* (từ `output.owasp_groups()`, link tới từng finding), chi tiết finding **nhóm theo test target** (trong nhóm sắp theo severity), và phần giới hạn phạm vi. Vì không có script, báo cáo trình bày cả hai cách nhóm dạng tĩnh thay cho nút chuyển của Web UI. | M |
| FR-UI-08 | Trang UI PHẢI gửi các header: `Content-Security-Policy: default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`. Dữ liệu quét trên trang chỉ được hiển thị bằng `textContent` (không `innerHTML`). | M |
| FR-UI-09 | Trường `gate_failed` PHẢI bằng `gate.failed` của báo cáo, tính bằng cùng hàm `output.gate_failed()` và cùng ngưỡng `--fail-on` (khai báo khi khởi động server) như CLI. Ngoài các trường của mục 6.3 (`web.WEB_ONLY_FIELDS`) và các trường thay đổi theo lần quét (`scan_id`, thời gian), JSON của Web UI PHẢI giống hệt JSON `--json` của CLI cho cùng target và cùng ngưỡng. Lỗi của cả hai endpoint trả `application/json` dạng `{"error": "..."}`. Câu gate hiển thị trên UI (`gate_message`) và trong báo cáo HTML PHẢI do cùng hàm `output.gate_message()` tạo ra. | M |
| FR-UI-10 | Trang nhập URL PHẢI liệt kê các nhóm kiểm thử (từ `GET /api/checks`) dạng checkbox, mặc định chọn tất cả, có *Select all* / *Clear* và số nhóm đã chọn; PHẢI chặn quét khi không chọn nhóm nào. Nếu không tải được danh sách, UI quét mọi nhóm (không gửi `checks`). (từ v1.7.0) | M |
| FR-UI-11 | Trang kết quả PHẢI nhóm finding theo *Test target* (mặc định, dùng `groups`) hoặc *OWASP Top 10* (dùng `owasp_groups`), chuyển bằng ô *Group by*. Mỗi nhóm là khối thu gọn được, hiện số finding theo severity và trạng thái (*N issues* / *No issues* / *Not run* / *Not selected*); bộ lọc severity áp dụng trong từng nhóm; mỗi finding ghi kèm cách nhóm còn lại (OWASP category hoặc test target). Dòng phạm vi PHẢI liệt kê các nhóm không được chọn là "not tested". (từ v1.7.0) | M |
| FR-UI-13 | **Web UI không nhận credential (D8, FR-WEB-07).** `POST /api/scan` chỉ chấp nhận đúng bốn trường `target`, `authorized`, `checks`, `crawl` (`web.ALLOWED_SCAN_FIELDS`; `crawl` từ v1.24.0, FR-UI-14). Kiểm tra này chạy ngay sau khi parse JSON, **trước** `authorized` và trước khi giữ lượt quét, nên câu trả lời về credential không phụ thuộc phần còn lại của request. (1) Trường thuộc `web.CREDENTIAL_FIELDS` (`auth`, `auth_profile_value`, `password`, `token`, `cookie`, `headers`, `authorization`, `api_key`, `show_secrets`) — so sánh không phân biệt hoa/thường, `_` và `-`, nên `showSecrets`, `x-api-key` cũng khớp — hoặc tên chứa một từ của `redact.SENSITIVE_PARAM_WORDS` (`access_token`, `session_id`, `client_secret`...), kể cả khi giá trị rỗng: HTTP 400, `code` = `credential_not_accepted`, `field` = tên trường. (2) `target` có phần user/password trong URL (`user:pass@host`, có hoặc không có scheme): cùng mã, `field` = `target`. (3) Trường lạ khác: 400, `code` = `unknown_field` (credential được ưu tiên hơn trường lạ). Response chỉ trả **tên** trường (cắt 100 ký tự), không bao giờ trả hay ghi log **giá trị**; thông báo tiếng Anh, chỉ sang CLI/config. Tham số query nhạy cảm kiểu `?token=` trong target vẫn được nhận và che bằng `redact()`. Mọi lỗi khác giữ nguyên dạng `{"error": ...}`. CLI không đổi: vẫn nhận và che `user:pass@host`. Quét có đăng nhập chỉ ở CLI/CI (từ v1.19.0) | M |
| FR-UI-14 | **Checkbox crawl (v1.24.0).** Trang nhập URL PHẢI có một checkbox "Also crawl the site and check the pages it links to", **mặc định bỏ chọn**, kèm dòng chú thích nêu giới hạn đang áp dụng (lấy từ khoá `crawl` của `GET /api/checks`: `max_depth`, `max_pages`, `max_duration`) và rằng robots.txt được theo. Bỏ chọn thì body không có `crawl` và lần quét chỉ chạm trang target như trước. Chọn thì body có đúng một trường `crawl: true`; server chạy `run_scan(crawl=...)` với `CrawlOptions` do **người vận hành** đặt khi khởi động (`--crawl-depth` mặc định 2, `--crawl-max-pages` 50, `--crawl-max-duration` 60), robots.txt luôn được theo, và `--rate-limit`, `--max-requests`, `--max-duration` của server áp dụng cho cả crawl. `crawl` không phải boolean JSON (chuỗi, số, `null`, mảng): 400 "crawl must be true or false", không bắt đầu quét. `crawl_depth`, `crawl_max_pages`, `crawl_max_duration`, `ignore_robots` và mọi trường khác vẫn bị `unknown_field` (FR-UI-13), nên trình duyệt không nâng được giới hạn và không tắt được robots.txt. Checkbox bị vô hiệu (kèm ghi chú) khi không nhóm `headers` hay `cookies` nào được chọn, vì crawl chỉ thêm trang cho hai nhóm đó. Trang kết quả hiện một dòng `Crawl: <crawl_message>` và, với finding thấy ở nhiều trang, mục "Also seen on" liệt kê các trang còn lại (chỉ bằng `textContent`). Báo cáo HTML tải về có thẻ Crawl (FR-CRW-07). Giới hạn body 4096 byte, kiểm tra Host/Origin/Content-Type, bind loopback và việc không nhận credential không đổi. | P1 |
| FR-UI-12 | Mỗi finding trên trang kết quả PHẢI hiện điểm CVSS ước tính kèm chữ "(estimated)" trên dòng phân loại (cùng cách ghi với console và báo cáo HTML, FR-MODEL-03), lấy từ `cvss_score` của JSON; finding không có điểm (`null`, các id trong `catalog.NOT_A_WEAKNESS`) thì không hiện gì. (từ v1.12.0) | M |

### 4.11 Nhóm mục tiêu kiểm thử (`catalog.CHECK_GROUPS`, từ v1.7.0)

Các check được gom thành 8 nhóm mục tiêu kiểm thử, khai báo **một lần** trong `catalog.CHECK_GROUPS` (dữ liệu, không nằm trong logic). CLI, Web UI và báo cáo HTML đều dùng bảng này; thứ tự trong bảng là thứ tự hiển thị.

| id | Tên hiển thị | Check (`checks_run`) |
|---|---|---|
| `headers` | Security headers | `security-headers`, `hsts-start-host` |
| `cookies` | Cookies | `cookies` |
| `tls` | TLS/SSL | `tls` |
| `https-redirect` | HTTP to HTTPS redirect | `http-to-https-redirect` |
| `cors` | CORS | `cors` |
| `exposed-files` | Exposed files | `sensitive-paths` |
| `directory-listing` | Directory listing | `directory-listing` |
| `robots-sitemap` | robots.txt / sitemap.xml | `robots-sitemap` |

| ID | Yêu cầu | Ưu tiên |
|---|---|---|
| FR-GRP-01 | `run_scan(..., groups=None)` PHẢI chạy mọi nhóm khi `groups` là `None`, và chỉ các nhóm được chọn khi có danh sách. GET baseline luôn chạy. Nhóm không được chọn KHÔNG được gửi request nào của riêng nó (2 probe soft-404 chỉ gửi khi chọn `exposed-files` hoặc `directory-listing`). | M |
| FR-GRP-02 | Lựa chọn PHẢI được chuẩn hoá bởi `catalog.normalize_groups()`: không phân biệt hoa/thường, bỏ trùng, trả theo thứ tự bảng; id lạ hoặc danh sách rỗng → `ValueError` nêu các id hợp lệ. | M |
| FR-GRP-03 | Báo cáo PHẢI ghi `scan_groups` (các nhóm đã chọn) và mỗi finding PHẢI có `check` (tên check tạo ra nó). Gate và exit code chỉ tính trên finding của các nhóm đã chạy; nhóm không được chọn phải được hiển thị là "not selected", không phải "no issues". | M |

### 4.12 Kiểm soát lưu lượng và phạm vi quét (từ v1.14.0)

Mỗi lần quét tạo một `limits.ScanLimiter` và một `ScopedSession`; cả hai **mặc định không giới hạn gì**, giữ nguyên hành vi trước v1.14.0.

| ID | Yêu cầu | Ưu tiên |
|---|---|---|
| FR-LIM-01 | `--rate-limit N` PHẢI giới hạn tốc độ ở N request/giây, tính **toàn cục** và **theo từng host**. Giới hạn áp ở `http_utils._TrustAdapter.send()` — tầng duy nhất thấy đúng một lần cho mỗi request thực sự ra khỏi máy: `Session.request()` không thấy các hop redirect do `resolve_redirects()` gửi, và retry của urllib3 nằm bên dưới nó. | M |
| FR-LIM-02 | Kết nối TLS (tối đa 13 socket của nhóm `tls`: 2 kết nối chứng chỉ và 11 probe) KHÔNG đi qua HTTP session, nên `check_tls` PHẢI nhận limiter tường minh và đếm mỗi kết nối như một request. | M |
| FR-LIM-03 | `--max-requests N` và `--max-duration SECONDS` PHẢI **dừng cả lần quét** khi chạm hạn: `limits.ScanLimitReached` (KHÔNG kế thừa `requests.exceptions.RequestException`, vì `safe_get()`/`get_limited()` nuốt loại đó) đi xuyên qua `_run_check` thay vì bị ghi thành "check failed", `errors` có một dòng `Scan stopped early: ...`, và `gate.incomplete` là `true`. Exit code theo mục 7.3 giữ nguyên thứ tự ưu tiên: có finding đạt ngưỡng `--fail-on` → `1`; không có → `3` (quét không kết luận được vì đã dừng giữa chừng). | M |
| FR-LIM-04 | Khi target trả **429 hoặc 503**, scanner PHẢI tự giảm tốc: chờ theo `Retry-After` nếu là số giây hợp lệ, nếu không thì backoff 2s nhân đôi mỗi lần, tối đa 60s. Số lần giảm tốc ghi vào `limits.slowdowns`. | S |
| FR-LIM-05 | Limiter PHẢI an toàn khi dùng nhiều luồng (check `sensitive-paths` chạy trên pool `--workers`), và `--max-requests` PHẢI chính xác tuyệt đối dưới tải đồng thời. | M |
| FR-LIM-06 | Báo cáo JSON PHẢI có khối `limits` = `{rate_limit, max_requests, max_duration, requests_sent, slowdowns, stopped_by}`; `stopped_by` là `null`, `"max-requests"` hoặc `"max-duration"`. | M |
| FR-SCOPE-01 | `--scope-host HOST` (lặp được) PHẢI mở rộng phạm vi D4 sang các host khai báo, áp cho **cả hai** đường kiểm scope: redirect tự động (`ScopedSession.get_redirect_target`) và vòng lặp redirect thủ công của `check_http_to_https_redirect`. Host ngoài phạm vi vẫn bị chặn và ghi vào `errors` như trước. | M |
| FR-EXCL-01 | Tool KHÔNG được gửi request tới URL bị loại trừ: path khớp regex trong `rules/exclusions.json` (mặc định, tắt bằng `--no-default-excludes`), path khớp `--exclude REGEX`, hoặc host trong `--exclude-host`. Áp cả khi URL đến từ một redirect. Các URL bị bỏ qua được ghi một dòng tổng hợp trong `errors`. Regex sai cú pháp PHẢI báo lỗi ở argparse, trước khi gửi bất kỳ request nào. | S |
| FR-EXCL-02 | Lần GET trang chủ (baseline) PHẢI tuân thủ exclusion giống mọi request khác: nếu target rơi vào `--exclude`, `--exclude-host` hoặc danh sách loại trừ mặc định thì **không gửi request nào**, `errors` nói rõ lý do, và lần quét được tính là chưa hoàn tất (exit code 3) chứ không phải sạch. Danh sách mặc định đúng là những path mà một GET có thể đăng xuất, xóa dữ liệu hoặc bắt đầu thanh toán, nên ngoại lệ ở đây phá đúng lời hứa mà exclusion đưa ra. (từ v1.18.0) | M |
| FR-SCANID-01 | `--scan-id-header` PHẢI gửi `X-Scanner-Scan-Id: <scan_id>` trên mọi request HTTP để bên đích lọc log/WAF. Mặc định **tắt** (NFR-SEC-03 vẫn yêu cầu `User-Agent` nhận diện rõ scanner). | S |

### 4.13 So sánh với lần quét trước, chấp nhận finding, xuất CSV/JUnit (từ v1.15.0)

Chỉ có ở CLI. `summary` **giữ nguyên nghĩa** (đếm mọi finding); những gì gate thực sự tính nằm ở `gate.counted`.

| ID | Yêu cầu | Ưu tiên |
|---|---|---|
| FR-BASE-01 | `--baseline FILE` PHẢI đọc một báo cáo `--json` trước đó và đánh dấu mỗi finding `baseline_state` = `new` hoặc `unchanged` theo `fingerprint`; gate chỉ tính finding `new` (`gate.basis` = `"new"`). Không có `--baseline` thì `baseline_state` là `null` và `gate.basis` = `"all"`. | M |
| FR-BASE-02 | File baseline hỏng (không đọc được, không phải JSON, không phải báo cáo, finding thiếu `fingerprint`) PHẢI bị từ chối ở argparse với thông báo rõ ràng, **trước** khi gửi request nào. | M |
| FR-BASE-03 | Khối `baseline` PHẢI liệt kê finding của baseline nay không còn. Một finding chỉ được gọi là **fixed** khi check tạo ra nó đã chạy trong lần quét này **và** lần quét hoàn tất; nếu không (`--checks` bỏ nhóm đó, hoặc một giới hạn đã dừng lần quét), nó vào `not_rechecked`. Không chắc thì không kết luận là đã sửa. | M |
| FR-BASE-04 | Nội dung lấy từ baseline (title, url...) PHẢI qua `redact()` trước khi vào báo cáo mới, vì baseline có thể được ghi bằng `--show-secrets`. | M |
| FR-BASE-05 | Baseline do scanner < 1.15.0 ghi ra PHẢI sinh một cảnh báo trong `errors` khuyên ghi lại baseline, vì FR-MODEL-07 đã đổi fingerprint của finding CORS/redirect với lần quét không bắt đầu từ site root. | S |
| FR-SUPP-01 | `--suppressions FILE` (TOML, thường đặt tên `.scannerignore.toml`) PHẢI chấp nhận các mục `[[suppress]]`, mỗi mục có `reason` không rỗng, `expires` là ngày, và ít nhất một trong `id`, `fingerprint`, `path` (glob trên URL path). Một mục khớp khi **mọi** trường nó nêu đều khớp. | M |
| FR-SUPP-02 | Loader PHẢI nghiêm ngặt: khoá lạ, thiếu `reason`/`expires`, ngày sai, fingerprint sai dạng, hoặc mục không có trường so khớp nào (sẽ khớp mọi finding) → từ chối **cả file** ở argparse. Một lỗi gõ phím không được âm thầm nới rộng việc chấp nhận. | M |
| FR-SUPP-03 | Finding bị suppress PHẢI vẫn có trong `findings` (trường `suppression` = `{reason, expires}`) và trong `summary`, chỉ không tính vào gate. | M |
| FR-SUPP-04 | Mục đã quá `expires` (còn hiệu lực đến hết ngày đó) PHẢI ngừng suppress, và `errors` PHẢI có một dòng báo mục đó đã hết hạn. | M |
| FR-OUT-01 | `--csv PATH` PHẢI ghi một dòng cho mỗi finding, theo thứ tự báo cáo, từ cùng báo cáo đã che secret, có cột `counts_toward_gate`. Ô bắt đầu bằng `=`, `+`, `-`, `@`, tab hoặc CR PHẢI được thêm tiền tố `'` để chặn *formula injection* khi mở bằng bảng tính. | M |
| FR-OUT-02 | `--junit PATH` PHẢI ghi một test case cho mỗi finding và một cho chính lần quét: finding làm gate fail → `<failure>`; các finding khác → `<skipped>` kèm lý do (dưới ngưỡng, không đổi so với baseline, đã suppress); test case của lần quét fail khi quét không hoàn tất và `--fail-on` khác `none`. Vì vậy file có `failures` > 0 **khi và chỉ khi** exit code khác 0. Ký tự XML 1.0 không chứa được PHẢI bị bỏ. | M |

### 4.14 File cấu hình, nhiều target, tham số vận hành (từ v1.16.0)

Chỉ có ở CLI. Không đổi cấu trúc báo cáo JSON (`schema_version` vẫn 1.8).

| ID | Yêu cầu | Ưu tiên |
|---|---|---|
| FR-CFG-01 | `--config FILE` (TOML) PHẢI chấp nhận mọi tùy chọn của CLI dưới tên riêng (`config.CONFIG_KEYS`), **trừ** `--yes`, `--show-secrets`, `--config`, `--list-checks`, `--version`: hai cái đầu là quyết định riêng của từng lần chạy, không được nằm trong file dùng chung. Cờ trên dòng lệnh ghi đè file; tùy chọn lặp được (`headers`, `cookies`, `exclude`, `scope_hosts`, `exclude_hosts`) thì gộp, của file trước. File chỉ được đọc khi chỉ định rõ, không tự tìm. | M |
| FR-CFG-02 | Loader PHẢI nghiêm ngặt: khoá lạ, sai kiểu, `show_secrets`/`yes`, hoặc `quiet` và `verbose` cùng bật → lỗi argparse trước khi gửi request nào. Mỗi giá trị đi qua đúng bộ kiểm tra của cờ CLI tương ứng. | M |
| FR-CFG-03 | `${NAME}` PHẢI được thay từ biến môi trường; biến không tồn tại là lỗi, không phải chuỗi rỗng. Credential ghi thẳng vào file (header nhạy cảm, cookie, mật khẩu proxy) được chấp nhận nhưng PHẢI in cảnh báo. Đường dẫn trong file tính theo thư mục chứa file. | M |
| FR-MULTI-01 | CLI PHẢI nhận nhiều target (đối số vị trí, `--targets-file` — mỗi dòng một target, `#` là comment —, hoặc `targets` trong config), chuẩn hoá và bỏ trùng, giữ thứ tự. Exit code là của target tệ nhất: `1` nếu có target fail gate, nếu không thì `3` nếu có target không quét được, nếu không thì `0`. Có nhiều target thì in bảng tổng hợp cuối cùng. | M |
| FR-MULTI-02 | `--output-dir DIR` PHẢI ghi một bộ file cho mỗi target theo `--formats` (mặc định `json`), tên file `<host>_<port>-<8 hex của SHA-256 URL>`, giống nhau ở mọi lần chạy. Nhiều target kèm tùy chọn ghi một file (`--json`...) → lỗi, gợi ý `--output-dir`. | M |
| FR-MULTI-03 | `--baseline-dir DIR` PHẢI so mỗi target với báo cáo của chính nó trong DIR (cùng tên file). Target chưa có báo cáo trong DIR: không có baseline, mọi finding được tính, `errors` ghi rõ. Nhiều target kèm `--baseline` → lỗi, gợi ý `--baseline-dir`. | M |
| FR-MULTI-04 | `--parallel N` (1–64, mặc định 1) PHẢI giới hạn số target quét đồng thời; báo cáo vẫn in theo thứ tự target đầu vào. Mỗi target có limiter riêng (mục 4.12). | S |
| FR-MULTI-05 | Header nhạy cảm hoặc cookie kèm target thuộc **nhiều host khác nhau** PHẢI bị từ chối: cùng một credential sẽ bị gửi tới mọi target, tức token của site này lọt sang site khác. | M |
| FR-OPT-01 | `--header 'NAME: VALUE'` và `--cookie NAME=VALUE` (lặp được) PHẢI được gửi trên mọi request; tên phải là token HTTP hợp lệ, giá trị không được chứa ký tự điều khiển (CR/LF sẽ chèn thêm header — request splitting). | M |
| FR-OPT-02 | Giá trị của header nhạy cảm (`Authorization`, `Proxy-Authorization`, `Cookie`, hoặc tên chứa token/secret/session/password/api-key/auth/credential/signature), mọi giá trị cookie và mật khẩu proxy PHẢI bị che **ở mọi nơi** trong báo cáo, console và log `--verbose`, kể cả khi target phản xạ lại chúng và kể cả khi có `--show-secrets` (đó là credential của chính người vận hành, báo cáo không bao giờ cần). Header không nhạy cảm thì giữ nguyên, để không cắt nát các hostname tình cờ chứa cùng chuỗi. | M |
| FR-OPT-03 | `--proxy URL` PHẢI là proxy `http://` (có thể kèm `user:pass@`) và áp cho **mọi** request, kể cả mọi kết nối của nhóm `tls` (hai kết nối chứng chỉ và các probe) qua tunnel `CONNECT` (kèm `Proxy-Authorization` khi có credential). Khi có `--proxy`, biến môi trường proxy và `NO_PROXY` không còn áp dụng. Proxy `https://`, SOCKS hoặc không có scheme → lỗi argparse (FR-CI-11). | M |
| FR-OPT-04 | `--user-agent PREFIX` PHẢI được ghép **trước** User-Agent của scanner, không bao giờ thay thế (NFR-SEC-03). | M |
| FR-OPT-05 | `--quiet` PHẢI in đúng một dòng cho mỗi target ra stdout (bỏ banner nếu đã có `--yes`), giữ nguyên exit code, và vẫn in `errors` của từng target ra stderr — exit code `3` mà không kèm lý do thì vô dụng trong log CI; `--verbose` PHẢI in mỗi request thực sự gửi đi ra stderr dạng `[request] METHOD URL -> status`, đã che secret. Hai cờ loại trừ nhau. `--version` in phiên bản rồi thoát. | S |

### 4.15 API inventory từ file spec (`api/`, từ v1.21.0)

Quyết định D9 (2026-10-04). Gói này chỉ **đọc** một mô tả API và liệt kê nó; việc kiểm tra từng endpoint (FR-API-02 trong backlog) chưa có. Chỉ có ở CLI.

| ID | Yêu cầu | Priority |
|---|---|---|
| FR-SPEC-01 | `--api-spec FILE` (khoá config `api_spec`, đường dẫn tính từ file config) PHẢI đọc file OpenAPI 3.0.x/3.1.x hoặc Swagger 2.0 dạng `.json`, `.yaml`, `.yml` (không phân biệt hoa/thường), tối đa 5 MB, UTF-8 (chấp nhận BOM). File được đọc và kiểm tra **ngay khi phân tích tham số**: lỗi → argparse exit 2, thông báo nêu tên file và lý do, **trước khi gửi request nào**. Tool CHỈ đọc file: KHÔNG gửi request tới endpoint hay server nào spec nêu. | M |
| FR-SPEC-02 | **Đọc an toàn.** (1) Không dùng mạng: module không import `socket`. (2) YAML chỉ dùng safe loader (loader C khi có, vì nhanh gấp ~5 lần với file 5 MB), nên tag như `!!python/object` bị từ chối; `yes`/`no`/`on`/`off` là chuỗi (YAML 1.2, đúng với OpenAPI); khoá lặp bị từ chối cả ở JSON lẫn YAML; khoá số (mã response `200`) và ngày tháng thành chuỗi. (3) **Ngân sách mở rộng:** trước khi dựng dữ liệu, đồ thị YAML được duyệt với tối đa 500.000 giá trị, mỗi lần dùng một alias đếm một lần, nên file vài trăm byte "billion laughs" bị từ chối dù nhỏ; giới hạn kích thước một mình không đủ. (4) Lồng tối đa 64 tầng, kể cả alias tự tham chiếu; lồng sâu hơn, kể cả hàng chục nghìn tầng, là lỗi có kiểm soát, không treo hay crash. (5) Tổng dung lượng spec + mọi file include tối đa 10 MB. | M |
| FR-SPEC-03 | **`$ref`.** Chỉ theo `#/json/pointer` trong cùng file, hoặc đường dẫn tương đối tới file `.json`/`.yaml`/`.yml` **nằm trong thư mục của spec** sau khi `..` và symlink đã được giải. PHẢI từ chối, với thông báo "not allowed" và không đọc file đích: URL (`http://`, `https://`, `file://`, `ftp://`, `//host`), đường dẫn tuyệt đối, ổ đĩa, UNC, dấu `\`, ký tự `%`, NUL, `..` thoát khỏi thư mục, symlink trỏ ra ngoài; đuôi file khác `.json`/`.yaml`/`.yml` bị từ chối riêng. Giới hạn: chuỗi `$ref` tối đa 32 bậc, tối đa 10.000 lần theo `$ref`, tối đa 20 file được include; vòng `$ref` (kể cả tự tham chiếu) là lỗi "circular"; `$ref: "#"` (cả tài liệu) bị từ chối. Mỗi file được include chịu đúng các giới hạn của FR-SPEC-02. Chỉ resolve phần inventory cần (path item, parameter, security scheme, server); **schema không bao giờ được resolve**. | M |
| FR-SPEC-04 | **Nội dung inventory** (`api.inventory.ApiInventory`): `source` (chỉ tên file, không bao giờ đường dẫn cục bộ), `format` (`openapi`/`swagger`), `version`, `title`; `servers` (OpenAPI 3: `servers[].url` với biến thay bằng giá trị mặc định, hoặc `/`; Swagger 2: `schemes` × `host` + `basePath`, mặc định `https`); `endpoints` mỗi cái gồm method (chữ hoa; chỉ `get`, `put`, `post`, `delete`, `options`, `head`, `patch`, `trace`; khoá `x-` bị bỏ), path, `operationId`, parameter (gộp mức path và mức operation, mức operation thắng; `name`, `in`, `required`), tên các security scheme áp dụng (mức operation ghi đè mức toàn cục, `[]` nghĩa là không cần), `deprecated`; `security_schemes` (tên, `type`, chi tiết như `header X-API-Key`, `bearer`, các flow OAuth). Sắp xếp theo path rồi method, không phụ thuộc thứ tự trong file. **Chỉ lấy tên và cấu trúc**: không bao giờ example, default, description hay schema. Tối đa 2.000 endpoint và 100 parameter cho một operation; vượt là lỗi, không cắt âm thầm. Spec sai cấu trúc → lỗi nêu chỗ sai và tên file. | M |
| FR-SPEC-05 | **Báo cáo.** JSON có khoá `api` ở cấp gốc (`null` khi không dùng `--api-spec`; `schema_version` 1.9, mục 6.2) gồm `endpoint_count` và đủ mọi endpoint. Mọi chữ lấy từ spec đi qua `redact()` (credential trong URL server bị che; không che khi `--show-secrets`). Console in mục "API inventory" sau các finding, tối đa 100 endpoint rồi "... and N more"; mọi chữ từ spec đi qua `report.printable_text()` (FR-REPORT-08). HTML, SARIF, CSV, JUnit và exit code không đổi. | M |
| FR-SPEC-06 | **Web UI không nhận spec.** `CLAUDE.md` cấm nới giới hạn body 4096 byte, mà spec thường lớn hơn nhiều; trường `api_spec` bị từ chối `unknown_field` (FR-UI-13) và JSON trả về có `api: null`. | M |

---

### 4.16 Crawler HTTP (`crawler/`, từ v1.22.0)

Gói crawler HTTP (backlog FR-CRAWL-01, 03, 04). Mặc định **tắt**: không có `--crawl` thì số request, JSON (trừ hai trường mới của finding) và exit code không đổi. Chỉ có ở CLI và file config.

| ID | Yêu cầu | Priority |
|---|---|---|
| FR-CRW-01 | **Bật và cài đặt.** `--crawl` (khoá config `crawl`) bật crawl. `--crawl-depth N` (mặc định 2; 0 = chỉ trang chủ), `--crawl-max-pages N` (mặc định 50, tính cả trang chủ), `--crawl-max-duration SECONDS` (mặc định 60), `--ignore-robots` (khoá config `crawl_depth`, `crawl_max_pages`, `crawl_max_duration`, `ignore_robots`). Đặt một trong bốn cài đặt mà không có `--crawl` là lỗi, thoát với code `2` trước mọi request. Giá trị sai (âm, 0 với số trang/thời gian, không phải số) cũng thoát `2` trước mọi request. Trước khi hỏi xác nhận quyền, CLI in một khối nói rõ crawl hỏi tối đa bao nhiêu trang, sâu bao nhiêu, và robots.txt được theo hay bỏ qua (không in khi `--quiet` kèm `--yes`). | P0 |
| FR-CRW-02 | **Phạm vi.** Chỉ đi theo `<a href>` và `<area href>` (tôn trọng `<base href>`), chỉ khi cùng origin (scheme, host, port; cổng mặc định coi như không có cổng) với trang mà baseline GET kết thúc. Chỉ dùng GET, qua cùng session của lần quét nên scope guard, `--exclude`, bộ exclusion mặc định, `--rate-limit`, `--max-requests`, `--max-duration`, `--proxy`, `--header`, `--cookie` đều áp dụng. Không bao giờ theo: scheme khác http/https, URL có `user:pass@`, URL dài quá 2000 ký tự. Phần `#fragment` bị bỏ. Một redirect không được session tự theo: crawler coi `Location` là một link như mọi link khác (cùng kiểm tra origin, exclusion, robots), nên không bao giờ gửi request tới origin khác. | P0 |
| FR-CRW-03 | **Giới hạn và lý do dừng.** Duyệt theo chiều rộng, theo thứ tự link xuất hiện. Dừng đúng ở `--crawl-depth`, `--crawl-max-pages`, `--crawl-max-duration`. Thêm: tối đa 5 query khác nhau cho một path, 200 link được đọc mỗi trang, 5000 URL trong hàng đợi, và chỉ đọc 512 KiB đầu của mỗi trang. Link không đi theo được đếm theo lý do: `other-origin`, `not-followable`, `excluded`, `robots-disallowed`, `query-variants`, `beyond-depth`, `queue-full`, `fetch-failed`. `stopped_reason` là một trong `complete`, `max-depth`, `max-pages`, `max-duration`, `scan-limit` (một giới hạn `--max-requests`/`--max-duration` của cả lần quét), `robots-unavailable`. Một trang lỗi mạng bị bỏ và ghi lỗi non-fatal, crawl tiếp tục. | P0 |
| FR-CRW-04 | **robots.txt (FR-CRAWL-04).** Mặc định `/robots.txt` được đọc trước khi lấy trang đầu tiên và các luật của `User-agent: *` và `User-agent: WebSec-Scanner` được theo; URL bị cấm được đếm là `robots-disallowed` và không được yêu cầu. Trả lời 4xx nghĩa là không có luật. Trả lời 5xx hoặc không đọc được thì crawl **dừng** (`robots-unavailable`) và ghi một lỗi non-fatal nêu `--ignore-robots`, không đoán là được phép. `--ignore-robots` không lấy robots.txt và báo cáo ghi `respect_robots: false`. Việc tắt robots hiện là một cờ tường minh vì chưa có xác minh quyền sở hữu domain (FR-AUTHZ-01). | P1 |
| FR-CRW-05 | **Check trên từng trang (FR-CRAWL-03).** Crawl chạy **sau cùng**, để một giới hạn `--max-requests` lấy bớt trang crawl trước khi lấy bớt check thường. Chỉ trang HTML trả 2xx mới chạy check header (nếu nhóm `headers` được chọn) và cookie (nếu nhóm `cookies` được chọn); trang redirect, lỗi, và không phải HTML không bị đánh giá. Nếu cả hai nhóm không được chọn, crawl không chạy và có một lỗi non-fatal nói vậy. Các check mức origin (CORS, TLS, chuyển hướng HTTPS, file lộ, robots/sitemap) vẫn chạy một lần. | P0 |
| FR-CRW-06 | **Gộp finding.** Cùng `id` và `fingerprint` ở nhiều trang là **một** finding, giữ nội dung (severity, evidence) của lần thấy đầu tiên. `affected_urls` liệt kê các trang (tối đa 20, URL của chính finding đứng đầu) và `affected_count` đếm đủ mọi trang, kể cả khi vượt 20. Không có crawl, `affected_urls` là `[url]` và `affected_count` là 1. `fingerprint` không đổi nên `--baseline` và `--suppressions` vẫn khớp; `summary` và gate đếm một finding một lần. Bằng chứng của các trang sau không được giữ. | P0 |
| FR-CRW-07 | **Báo cáo.** JSON có khoá `crawl` (`null` khi không crawl) gồm `max_depth`, `max_pages`, `max_duration`, `respect_robots`, `pages_visited`, `skipped`, `stopped_reason`, **không** chứa URL (mục 6.2, `schema_version` 1.10). Console có mục `Crawl:` và dòng `Seen on N pages`; HTML có thẻ Crawl và mục "Also seen on"; SARIF có một location cho mỗi trang; CSV có cột `affected_count` ngay sau `url`; JUnit nêu các trang khác. Mọi URL trang crawl đi qua `redact()` (tham số nhạy cảm bị che) trừ khi `--show-secrets`; thông báo lỗi của crawler cũng qua `redact()`; credential của người vận hành bị che ở mọi chỗ, kể cả với `--show-secrets`. Văn bản lấy từ site được in qua `printable_text()`. | P0 |
| FR-CRW-08 | **Web UI chỉ bật được crawl bằng một boolean (sửa ở v1.24.0, FR-UI-14).** Từ v1.24.0 `crawl` là trường hợp lệ của `POST /api/scan`; `crawl_depth`, `crawl_max_pages`, `crawl_max_duration`, `ignore_robots` vẫn bị từ chối `unknown_field` (FR-UI-13); giới hạn body 4096 byte không đổi. | P0 |

**Giới hạn đã biết** (không phải lỗi): crawler không chạy JavaScript nên không thấy link do JS tạo ra (SPA là FR-CRAWL-02, chưa làm); chỉ đọc link `<a>`/`<area>`, không đọc form, iframe hay sitemap; một lỗi thấy ở nhiều trang chỉ giữ bằng chứng của trang đầu; crawl dừng vì robots không làm lần quét thành "không hoàn tất" (exit code không đổi, lý do nằm trong `crawl.stopped_reason` và `errors`).

## 5. Yêu cầu phi chức năng (Non-Functional Requirements)

| ID | Nhóm | Yêu cầu |
|---|---|---|
| NFR-SEC-01 | Bảo mật/đạo đức | Tool TUYỆT ĐỐI KHÔNG gửi payload khai thác (SQLi, XSS thật, command injection, path traversal thật, brute-force) và không gửi bản tin giao thức dị dạng. Mọi request tới target là GET tiêu chuẩn, không sửa dữ liệu phía target; kết nối TLS chỉ là handshake chuẩn với số lượng có giới hạn (FR-TLS-13), không bao giờ hoàn tất khi dò (FR-TLS-12). |
| NFR-SEC-02 | Bảo mật/đạo đức | Bước xác nhận quyền quét không tắt được bằng cấu hình mặc định: CLI chỉ bỏ qua bằng cờ `--yes`; Web UI luôn yêu cầu `authorized: true`. |
| NFR-SEC-03 | Bảo mật/đạo đức | Mọi request PHẢI gửi `User-Agent` nhận diện rõ là scanner kèm phiên bản thật: `WebSec-Scanner/<version> (+non-intrusive security configuration check)`, không giả mạo trình duyệt, **không chứa tên công ty hay thông tin thương mại khác** (yêu cầu chủ sản phẩm, đợt rà soát 2026-09-30). *(Chuỗi đã đổi hai lần trong lịch sử, đều không phải bên nào phải hành động lại nếu đã cập nhật sau lần gần nhất: trước v1.3.0 không mang tên sản phẩm; từ v1.3.0 đến trước bản rà soát này, chuỗi có mang tên sản phẩm và tên công ty; từ bản rà soát 2026-09-30, chỉ còn tên sản phẩm. Bên nào lọc log/WAF theo chuỗi cũ cần cập nhật theo giá trị hiện tại ở cột bên trái.)* Từ v1.16.0, `--user-agent PREFIX` chỉ được ghép **trước** chuỗi này (FR-OPT-04), không bao giờ thay thế. |
| NFR-SEC-04 | Bảo mật | Mọi đầu ra (console, `--json`, response Web UI, báo cáo HTML) PHẢI qua `output.build_report()`, nơi che (1) cặp `tên=giá trị` của cookie do check khai báo chính xác, và (2) giá trị của mọi tham số URL có tên chứa `token`, `key`, `session`, `sess`, `password`, `passwd`, `pwd`, `secret`, `sig`, `auth`, `jwt`, và (3) thông tin đăng nhập trong URL (`scheme://user:password@host`: che riêng user và password, từ v1.6.0) — trong `target`, `final_url`, `redirect_chain`, `errors`, và `title`/`description`/`evidence`/`url`/`instance_key` của finding. Dòng `Scanning <target>` của CLI cũng được che. Cờ `--show-secrets` **chỉ có ở CLI**: in cảnh báo ra stderr, JSON có `secrets_redacted: false`, báo cáo HTML có băng cảnh báo. Web UI luôn che, bỏ qua mọi trường yêu cầu tắt che. |
| NFR-SEC-05 | Bảo mật/đạo đức | **Phạm vi khi theo redirect (D4):** mọi request của một lần quét chỉ được theo redirect tới cùng hostname với target, hoặc hostname chỉ khác một tiền tố `www.` (không phân biệt hoa thường; được đổi scheme và cổng; target là IP thì phải khớp chính xác). Redirect ra ngoài phạm vi thì **không gửi request tới host đó**: chuỗi redirect dừng ở response 3xx cuối cùng trong phạm vi, các check chạy tiếp trên response đó, và `errors` có đúng **một dòng** cho mỗi host bị chặn. Tối đa 10 bước redirect cho mỗi request. |
| NFR-PERF-01 | Hiệu năng | Mỗi request PHẢI có timeout cấu hình được (mặc định 10 giây). |
| NFR-PERF-02 | Hiệu năng | Số luồng song song khi kiểm tra path nhạy cảm PHẢI giới hạn qua `--workers` (mặc định 5). |
| NFR-PERF-03 | Hiệu năng | Không retry khi target trả 4xx/5xx; chỉ retry ở tầng kết nối/đọc, tối đa 1 lần. |
| NFR-PERF-04 | Hiệu năng | Mọi request kiểm tra path nhạy cảm, probe soft-404 và directory listing PHẢI đọc **tối đa 8 KiB đầu** của body (`http_utils.MAX_BODY_BYTES`) rồi đóng kết nối, để một file dump hay backup lớn bị lộ không bị tải về (giảm tải cho target và không kéo dữ liệu của target về máy quét). `robots.txt` và `sitemap.xml` được đọc tối đa **512 KiB** (`http_utils.HINT_FILE_MAX_BYTES`, từ v1.6.0; trước đó đọc toàn bộ); mục nằm sau giới hạn này không được xét. Charset không xác định trong `Content-Type` được giải mã như UTF-8 thay vì làm dừng check. |
| NFR-REL-01 | Độ tin cậy | Một check thất bại không được làm crash cả lần quét (FR-REPORT-05). Header do server điều khiển mà thư viện không parse nổi (ví dụ `Location: http://evil[.invalid/` làm `urljoin()` ném `ValueError`) KHÔNG được làm sập lần quét: redirect không parse được thì không đi theo, và được ghi một dòng vào `errors` (từ v1.16.0). |
| NFR-REL-02 | Độ tin cậy | Tool PHẢI xử lý được target không phản hồi ở baseline mà không ném exception ra ngoài. |
| NFR-USA-01 | Khả dụng | Output CLI có phân cách rõ ràng, bảng tổng hợp theo severity ở đầu, rồi mới tới chi tiết. |
| NFR-USA-02 | Khả dụng | Mọi finding PHẢI có khuyến nghị khắc phục khi khả thi. |
| NFR-USA-03 | Khả dụng | Ngôn ngữ mặc định của mọi text sản phẩm (UI, báo cáo HTML, output CLI, thông báo lỗi API, nội dung finding) là **tiếng Anh**. Tài liệu dự án (SRS, backlog, README) có thể viết tiếng Việt. |
| NFR-PORT-01 | Khả chuyển | Tool PHẢI chạy trên Python ≥ 3.12, Linux/macOS/Windows. *Nâng từ ≥ 3.9 lên ≥ 3.12 theo quyết định của chủ sản phẩm ngày 2026-09-30 (3.9 đã hết hỗ trợ, 3.10 hết hỗ trợ 2026-10-31; 3.12 là bản có sẵn trên Ubuntu 24.04). Môi trường dev dùng 3.14. CI của repo (FR-QA-07) chạy trên Ubuntu 24.04 (3.12, 3.14) và Windows (3.14); macOS chưa có trong CI.* |
| NFR-MAINT-01 | Bảo trì | Mỗi nhóm check nằm trong module riêng, unit test được không cần mạng thật (dùng mock server cục bộ hoặc dữ liệu có sẵn). |
| NFR-MAINT-02 | Bảo trì | Danh sách header bắt buộc (4.3) và path nhạy cảm (4.8.1) là cấu trúc dữ liệu khai báo ở đầu file. |
| NFR-COMP-01 | Tuân thủ | README, UI và báo cáo PHẢI nêu rõ giới hạn phạm vi (không phải DAST toàn diện, không thay thế pentest). Không dùng ngôn ngữ đảm bảo tuyệt đối ("website an toàn", "phát hiện 100%"). Từ v1.8.0: `output.SCOPE_NOTE` (FR-RPT-08) là nguồn duy nhất cho console và HTML. |
| NFR-LEGAL-01 | Pháp lý | Mọi dependency (runtime và dev), trực tiếp và bắc cầu, PHẢI có license ghi trong `THIRD_PARTY_LICENSES.md` (FR-SEC-10, từ v1.8.0), không có GPL/AGPL/LGPL; dependency mới PHẢI thêm vào file này cùng lúc với `pyproject.toml`. Không thêm công cụ quét license mới; kiểm kê viết tay, đối chiếu bằng `tests/test_licenses.py`. License có điều khoản cần lưu ý (ví dụ MPL-2.0) PHẢI ghi rõ và đánh dấu `[CONFIRM]` để rà lại trước khi thương mại hóa. |

---

## 6. Đặc tả dữ liệu (Data Model)

### 6.1 Các kiểu dữ liệu lõi (`models.py`)

```python
class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    # rank: CRITICAL=0 ... INFO=4, dùng để sort

@dataclass
class Finding:
    id: str                  # mã ổn định theo loại lỗi, VD "HDR-CSP-UNSAFE"
    title: str
    severity: Severity
    owasp_category: str      # VD "A05:2021 - Security Misconfiguration"
    description: str
    evidence: str = ""
    recommendation: str = ""
    url: str = ""
    instance_key: str = ""  # vị trí: tên header, tên cookie, path, host:port, URL (do check đặt)
    cwe: str = ""           # VD "CWE-693"; rỗng với finding thông tin không phải điểm yếu
    confidence: str = ""    # "high" | "medium" | "low"
    references: list[str] = field(default_factory=list)  # link OWASP/CWE, chỉ https://
    cvss_vector: str = ""    # VD "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"; rỗng nếu không phải điểm yếu
    cvss_score: float | None = None  # tính từ cvss_vector; None nếu cvss_vector rỗng (FR-MODEL-03)
    fingerprint: str = ""   # 32 hex, ổn định giữa các lần quét

@dataclass
class ScanResult:
    target: str
    started_at: str          # ISO 8601 UTC, hậu tố "Z"
    finished_at: str = ""
    final_url: str = ""      # URL của response cuối của baseline; rỗng nếu baseline thất bại
    redirect_chain: list[dict] = []  # các response redirect trước final_url: {"url", "status"}
    findings: list[Finding] = field(default_factory=list)
    checks_run: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    scan_id: str             # UUID4, mới cho mỗi lần quét
    scanner_version: str     # websec_scanner.__version__
    rules_version: str       # "sensitive_paths=<version>;tls_interceptors=<version>" của các file rules
```

**Quy tắc bắt buộc:**

- `Finding.id` là mã ổn định theo **loại** lỗi, không đổi giữa các lần chạy. Hai **vị trí** khác nhau của cùng một loại lỗi (ví dụ hai cookie cùng thiếu cờ) có cùng `id` nhưng khác `instance_key` và `fingerprint` (FR-MODEL-01).
- `fingerprint` = 32 ký tự hex đầu của SHA-256(`id|instance_key|origin`), với `origin` = `scheme://host:port` của target (chữ thường, cổng mặc định 80/443). Không phụ thuộc path, thời gian quét hay giá trị bị che, nên cùng một lỗi ở cùng một chỗ luôn cho cùng fingerprint. **FR-MODEL-07 (từ v1.15.0):** vì vậy `instance_key` của finding mô tả *cả site* PHẢI là `http_utils.site_root()` của URL (`scheme://host[:port]/`, không path, query, fragment hay thông tin đăng nhập) chứ không phải URL đầy đủ — áp cho các finding CORS và `TLS-NO-HTTPS-REDIRECT`. Trước v1.15.0 hai loại này băm cả URL bắt đầu quét, nên cùng một lỗi cho fingerprint khác nhau khi quét từ trang khác hoặc khi query có token xoay vòng. Lần quét bắt đầu từ site root không query thì giữ nguyên fingerprint cũ.
- `cwe`, `confidence`, `references` lấy từ bảng khai báo `catalog.FINDING_CATALOG` (mỗi finding id một dòng). Mọi id tool sinh ra PHẢI có trong bảng. `cwe` để trống cho 3 finding thông tin không phải điểm yếu: `TLS-CONN-FAILED`, `TLS-CERT-PARSE-FAILED`, `EXPOSURE-SECURITY-TXT`. `COOKIE-FLAGS-MISSING` lấy CWE theo thuộc tính quan trọng nhất đang thiếu: Secure → CWE-614, HttpOnly → CWE-1004, SameSite → CWE-1275.
- `cvss_vector`/`cvss_score` (FR-MODEL-03, bảng vector sửa theo review ngày 2026-10-01): vector CVSS v3.1 **ước tính theo loại finding** (`catalog._CVSS_VECTORS`, một dòng mỗi id), không phải đánh giá riêng cho từng target quét. Ba quy tắc:
  1. Vector trong catalog là **trường hợp xấu nhất** của loại finding đó.
  2. Check **ghi đè** `cvss_vector` theo từng instance khi evidence cho thấy trường hợp nhẹ hơn (hằng `catalog.CVSS_*`, không viết chuỗi vector trong check): CORS phản xạ origin không kèm credentials → 4.3; cookie có `Secure` nhưng thiếu `HttpOnly` → 3.1; cookie chỉ thiếu `SameSite` → 3.1; cipher đã bị phá nhưng vẫn mã hoá (RC4/RC2/DES/3DES/IDEA/MD5) → 5.9, trong khi suite không mã hoá, export grade hoặc không xác thực (NULL/EXP-/EXPORT/ADH-/AECDH-) giữ 7.4. `enrich()` **luôn** tính lại `cvss_score` từ vector thắng, nên finding không bao giờ mang điểm của trường hợp xấu nhất khi đã bị ghi đè.
  3. Finding **không phải điểm yếu chấm được điểm** (`catalog.NO_CVSS`) có `cvss_vector = ""` và `cvss_score = None`: 3 id của `NOT_A_WEAKNESS`, cảnh báo sớm (`TLS-CERT-EXPIRING-SOON`), gợi ý (`EXPOSURE-ROBOTS-HINTS`, `EXPOSURE-SITEMAP-HINTS`), và — quyết định **C1** của review — mọi finding có severity mặc định INFO (`HDR-INFO-*`, `HDR-PERMISSIONS-POLICY-MISSING`, `HDR-XXP-LEGACY`, `CORS-WILDCARD`).
  `cvss_score` = `cvss.base_score(cvss_vector)` theo đúng công thức CVSS v3.1 chính thức (`websec_scanner/cvss.py`, có test đối chiếu với các ví dụ điểm đã công bố). `[CONFIRM]` Đây là thang điểm **độc lập** với `Severity` nội bộ của tool (vốn còn tính thêm khả năng khai thác theo ngữ cảnh như quyết định D3 cho CORS), nên hai thang có thể không khớp nhau — mọi nơi hiển thị đều ghi rõ "(estimated)" và kèm `output.CVSS_NOTE`; vẫn cần đội bảo mật rà lại bảng vector trước khi dùng làm số chính thức với khách hàng trả tiền.
- `confidence` (FR-DET-03): `high` = quan sát trực tiếp từ response/bắt tay (header, cookie, TLS, CORS, directory listing có dấu hiệu nội dung) hoặc file nhạy cảm có nội dung khớp chữ ký (FR-EXP-04); `medium` = quan sát gián tiếp (hiện chưa có finding nào); `low` = chỉ là gợi ý (robots.txt, sitemap.xml), hoặc finding TLS khi bắt tay có vẻ bị chặn giữa đường (FR-TLS-11).
- Khi xuất ra (CLI/JSON/HTML), `findings` được sắp theo `severity.rank` tăng dần (CRITICAL trước).

### 6.2 JSON Schema (mô tả phi hình thức)

Định dạng chính thức là JSON Schema draft 2020-12 tại **`docs/report.schema.json`** (bắt buộc mọi khoá, không cho khoá lạ). `schema_version` hiện là **`1.10`**. Lịch sử: bản `1.0` là định dạng chưa đánh version của scanner v1.1.0; `1.1` (scanner 1.2.0) **thêm** `schema_version`, `scanner_version`, `rules_version`, `scan_id` (FR-MODEL-02), `secrets_redacted` (FR-AUTH-02) và 5 trường mới của finding (FR-MODEL-01); `1.2` (scanner 1.3.0) **thêm** `final_url` và `redirect_chain` (FR-FIX-10) và tên check `hsts-start-host`; `1.3` (scanner 1.5.0) **thêm** `gate` = `{fail_on, failed, incomplete}` (FR-CI-01); `1.4` (scanner 1.7.0) **thêm** `scan_groups` và `check` của mỗi finding (FR-GRP-03); `1.5` (scanner 1.10.0) **thêm** `disclaimer` (FR-RPT-08, cùng nội dung với `output.SCOPE_NOTE` hiện trên console và HTML); `1.6` (scanner 1.12.0) **thêm** `cvss_vector`/`cvss_score` của mỗi finding (FR-MODEL-03, ước tính theo loại, xem mục 6.1); `1.7` (scanner 1.14.0) **thêm** khối `limits` (FR-LIM-06, mục 4.12); `1.8` (scanner 1.15.0) **thêm** khối `baseline`, trường `baseline_state` và `suppression` của mỗi finding, và `incomplete_reason`, `basis`, `counted` trong `gate` (mục 4.13). `1.9` (scanner 1.21.0) **thêm** khoá `api` ở cấp gốc: `null` khi không dùng `--api-spec`, hoặc một object `source`, `format`, `version`, `title`, `servers`, `security_schemes`, `endpoint_count`, `endpoints` (mục 4.15). `1.10` (scanner 1.22.0) **thêm** khoá `crawl` ở cấp gốc (`null` khi không dùng `--crawl`, hoặc một object `max_depth`, `max_pages`, `max_duration`, `respect_robots`, `pages_visited`, `skipped`, `stopped_reason`, không chứa URL) và hai trường của mỗi finding: `affected_urls` (các trang đã thấy finding, tối đa 20) và `affected_count` (mục 4.16). `summary` không đổi nghĩa. Không phiên bản nào bỏ hay đổi nghĩa trường. Quy tắc: thêm trường → tăng số phụ; bỏ/đổi tên/đổi nghĩa → tăng số chính; mỗi lần đổi PHẢI ghi changelog.

```json
{
  "schema_version": "1.10",
  "scanner_version": "1.24.0",
  "rules_version": "1.1.0",
  "scan_id": "6f1c2d3e-4b5a-4c6d-8e7f-0a1b2c3d4e5f",
  "secrets_redacted": true,
  "disclaimer": "This is a non-intrusive configuration check, not a full DAST assessment: it does not detect real SQL injection/XSS, business-logic flaws or application-level authentication issues. A clean report does not mean the target is secure: it means these checks found nothing. Only scan systems you own or are explicitly authorized to test.",
  "gate": { "fail_on": "high", "failed": true, "incomplete": false },
  "target": "https://example.com/",
  "final_url": "https://www.example.com/",
  "redirect_chain": [{ "url": "https://example.com/", "status": 301 }],
  "started_at": "2026-09-22T08:26:08.822920Z",
  "finished_at": "2026-09-22T08:26:09.273000Z",
  "scan_groups": ["headers", "cookies", "tls", "https-redirect", "cors", "exposed-files", "directory-listing", "robots-sitemap"],
  "checks_run": ["security-headers", "cookies", "tls", "http-to-https-redirect", "cors", "sensitive-paths", "directory-listing", "robots-sitemap"],
  "limits": { "rate_limit": null, "max_requests": null, "max_duration": null, "requests_sent": 29, "slowdowns": 0, "stopped_by": null },
  "summary": { "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0 },
  "findings": [
    {
      "id": "EXPOSURE-ENV",
      "title": "Exposed .env file (often contains secrets)",
      "severity": "CRITICAL",
      "owasp_category": "A01:2021 - Broken Access Control",
      "cwe": "CWE-538",
      "confidence": "medium",
      "description": "GET .env returned HTTP 200, suggesting the file/path is publicly accessible.",
      "evidence": "HTTP 200 for https://example.com/.env",
      "recommendation": "Remove the file from the web root or block access at the web server/proxy layer.",
      "url": "https://example.com/.env",
      "references": ["https://owasp.org/Top10/A01_2021-Broken_Access_Control/", "https://cwe.mitre.org/data/definitions/538.html"],
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
      "cvss_score": 7.5,
      "instance_key": ".env",
      "fingerprint": "<32 ký tự hex>",
      "check": "sensitive-paths",
      "affected_urls": ["https://example.com/.env"],
      "affected_count": 1
    }
  ],
  "errors": [],
  "api": null,
  "crawl": null
}
```

AT-12 kiểm tra đúng tập khoá ở cấp gốc, trong `summary` và trong mỗi finding; AT-30 kiểm tra output khớp `docs/report.schema.json`.

### 6.3 Trường bổ sung của Web UI

Lỗi bị từ chối theo FR-UI-13 có dạng `{"error": "...", "code": "credential_not_accepted" | "unknown_field", "field": "<tên trường>"}`; hai khóa `code` và `field` chỉ có ở các lỗi này (từ v1.19.0), mọi lỗi khác chỉ có `error`.

`POST /api/scan` trả JSON mục 6.2 cộng thêm các trường sau. Nút **Download JSON** loại bỏ chúng để file tải về giống hệt `--json` của CLI.

| Trường | Kiểu | Ý nghĩa |
|---|---|---|
| `gate_failed` | bool | `true` nếu có ít nhất 1 finding CRITICAL/HIGH (FR-UI-09) |
| `gate_status` | string | `fail`, `warn` (quét không hoàn tất) hoặc `pass`, từ `output.gate_message()` (từ v1.6.0) |
| `gate_message` | string | Câu mô tả gate và exit code của CLI; **cùng câu** với báo cáo HTML (từ v1.6.0) |
| `crawl_message` | string \| null | Một câu nói lần crawl đã duyệt bao nhiêu trang và vì sao dừng, từ `output.crawl_message()` (**cùng câu** với console và báo cáo HTML); `null` khi không crawl (từ v1.24.0) |
| `groups` | array | `output.group_findings()`: mỗi nhóm của mục 4.11 theo thứ tự bảng, gồm `id`, `title`, `description`, `status` (`issues`/`clean`/`not-run`/`not-selected`), `counts` theo severity, `findings` (chỉ số trong `findings`) (từ v1.7.0) |
| `owasp_groups` | array | `output.owasp_groups()`: các OWASP category có finding, sắp theo category, gồm `id` (ví dụ `A05:2021`), `title`, `counts`, `findings` (từ v1.7.0) |
| `report_id` | string | id ngẫu nhiên của báo cáo lưu trong bộ nhớ (FR-UI-06) |
| `report_url` | string | `/api/report/<report_id>.html` |

---

## 7. Giao diện dòng lệnh

### 7.1 Cú pháp

```
python -m websec_scanner <target> [--json PATH] [--sarif PATH] [--html PATH] [--timeout N] [--workers N] [--no-color] [--yes] [--fail-on LEVEL] [--ca-bundle PATH] [--show-secrets]
```

### 7.2 Bảng tham số

| Tham số | Bắt buộc | Mặc định | Mô tả |
|---|---|---|---|
| `target` | Có (trừ khi có `--list-checks`) | — | URL hoặc hostname. Chuẩn hoá theo FR-CLI-01. |
| `--json PATH` | Không | (không xuất) | Ghi báo cáo JSON đầy đủ. Thư mục cha phải tồn tại sẵn. |
| `--timeout N` | Không | `10` | Timeout mỗi request (giây). |
| `--workers N` | Không | `5` | Số luồng song song khi kiểm tra path nhạy cảm. |
| `--no-color` | Không | tắt | Tắt mã màu ANSI. |
| `--yes` / `--i-have-authorization` | Không | tắt | Bỏ qua bước hỏi xác nhận tương tác. |
| `--sarif PATH` | Không | (không xuất) | Ghi báo cáo SARIF 2.1.0 (FR-REPORT-06). |
| `--html PATH` | Không | (không xuất) | Ghi báo cáo HTML độc lập (FR-REPORT-07). |
| `--fail-on LEVEL` | Không | `high` | Mức thấp nhất làm fail gate (exit `1`): `critical`, `high`, `medium`, `low`, hoặc `none` (không bao giờ fail, kể cả khi quét không hoàn tất). |
| `--ca-bundle PATH` | Không | env `REQUESTS_CA_BUNDLE`/`SSL_CERT_FILE`, rồi kho OS | File PEM các CA được tin, thay cho kho mặc định, cho cả request HTTP và TLS check (FR-CLI-06). |
| `--no-tls-probe` | Không | bật probe | Tắt các probe TLS (FR-TLS-15, từ v1.20.0): chỉ còn hai kết nối chứng chỉ. Khoá config `tls_probe = false`. |
| `--api-spec FILE` | Không | không | Hiện API inventory đọc từ file OpenAPI 3.0/3.1 hoặc Swagger 2.0 (`.json`/`.yaml`/`.yml`, tối đa 5 MB); chỉ **đọc** file, không gửi request tới bất kỳ thứ gì nó nêu (FR-SPEC-01…06, từ v1.21.0). File lỗi → exit 2 trước khi gửi request nào. Khoá config `api_spec` (đường dẫn tính từ vị trí file config). |
| `--crawl` | Không | tắt | Đi theo link cùng origin và chạy check header, cookie trên từng trang (mục 4.16, từ v1.22.0). Mỗi request tính vào `--max-requests` và `--rate-limit`. |
| `--crawl-depth N` | Không | 2 | Số cấp link đi từ trang chủ; 0 = chỉ trang chủ. Cần `--crawl`. |
| `--crawl-max-pages N` | Không | 50 | Tổng số trang, tính cả trang chủ. Cần `--crawl`. |
| `--crawl-max-duration SECONDS` | Không | 60 | Dừng crawl sau SECONDS giây. Cần `--crawl`. |
| `--ignore-robots` | Không | theo robots.txt | Crawl mà không đọc robots.txt (FR-CRW-04). Cần `--crawl`. |
| `--checks GROUPS` | Không | tất cả | Danh sách id nhóm cách nhau bằng dấu phẩy (mục 4.11), ví dụ `headers,tls`. Id sai → exit code `2` kèm danh sách id hợp lệ (từ v1.7.0). |
| `--list-checks` | Không | — | In id, tên và mô tả của từng nhóm rồi thoát với code `0`; không cần target, không hỏi xác nhận (từ v1.7.0). |
| `--show-secrets` | Không | tắt | Không che giá trị cookie và tham số URL nhạy cảm (chỉ để debug cục bộ; NFR-SEC-04). |
| `--rate-limit N` | Không | không giới hạn | Tối đa N request/giây, toàn cục và theo host (FR-LIM-01, từ v1.14.0). |
| `--max-requests N` | Không | không giới hạn | Dừng lần quét sau N request (FR-LIM-03, từ v1.14.0). |
| `--max-duration SECONDS` | Không | không giới hạn | Dừng lần quét sau SECONDS giây (FR-LIM-03, từ v1.14.0). |
| `--scope-host HOST` | Không | (chỉ host của target) | Thêm host vào phạm vi; lặp được (FR-SCOPE-01, từ v1.14.0). |
| `--exclude REGEX` | Không | (bảng mặc định) | Không request URL có path khớp REGEX; lặp được (FR-EXCL-01, từ v1.14.0). |
| `--exclude-host HOST` | Không | — | Không request host này; lặp được (FR-EXCL-01, từ v1.14.0). |
| `--no-default-excludes` | Không | tắt | Bỏ bảng loại trừ mặc định `rules/exclusions.json` (FR-EXCL-01, từ v1.14.0). |
| `--scan-id-header` | Không | tắt | Gửi `X-Scanner-Scan-Id` trên mọi request (FR-SCANID-01, từ v1.14.0). |
| `--baseline FILE` | Không | — | Báo cáo `--json` của lần quét trước; gate chỉ tính finding mới (FR-BASE-01, từ v1.15.0). |
| `--suppressions FILE` | Không | — | File TOML các finding được chấp nhận, mỗi mục có lý do và ngày hết hạn (FR-SUPP-01, từ v1.15.0). |
| `--csv PATH` | Không | (không xuất) | Ghi các finding ra CSV (FR-OUT-01, từ v1.15.0). |
| `--junit PATH` | Không | (không xuất) | Ghi báo cáo JUnit XML (FR-OUT-02, từ v1.15.0). |
| `--config FILE` | Không | — | File TOML chứa các tùy chọn; dòng lệnh ghi đè (FR-CFG-01, từ v1.16.0). |
| `--targets-file FILE` | Không | — | Mỗi dòng một target, `#` là comment (FR-MULTI-01, từ v1.16.0). |
| `--output-dir DIR` | Không | — | Một bộ báo cáo cho mỗi target (FR-MULTI-02, từ v1.16.0). |
| `--formats LIST` | Không | `json` | Định dạng ghi vào `--output-dir` (FR-MULTI-02, từ v1.16.0). |
| `--baseline-dir DIR` | Không | — | So mỗi target với báo cáo của nó trong DIR (FR-MULTI-03, từ v1.16.0). |
| `--parallel N` | Không | `1` | Số target quét đồng thời, tối đa 64 (FR-MULTI-04, từ v1.16.0). |
| `--header 'NAME: VALUE'` | Không | — | Header gửi kèm; lặp được (FR-OPT-01, từ v1.16.0). |
| `--cookie NAME=VALUE` | Không | — | Cookie gửi kèm; lặp được (FR-OPT-01, từ v1.16.0). |
| `--proxy URL` | Không | env `HTTP(S)_PROXY` (chỉ HTTP) | Proxy `http://` cho mọi request, kể cả check TLS (FR-OPT-03, từ v1.16.0). |
| `--user-agent PREFIX` | Không | — | Ghép trước User-Agent của scanner (FR-OPT-04, từ v1.16.0). |
| `--quiet` / `--verbose` | Không | tắt | Một dòng mỗi target / log mọi request ra stderr (FR-OPT-05, từ v1.16.0). |
| `--version` | Không | — | In phiên bản rồi thoát (FR-OPT-05, từ v1.16.0). |

### 7.3 Exit code

| Code | Ý nghĩa |
|---|---|
| `0` | Quét xong, không có finding nào bằng hoặc cao hơn ngưỡng `--fail-on`; hoặc `--fail-on none`. |
| `1` | Có ít nhất 1 finding bằng hoặc cao hơn ngưỡng `--fail-on` (mặc định CRITICAL/HIGH). |
| `2` | Người dùng không xác nhận quyền quét — không có request nào được gửi. Cũng là exit code của argparse khi tham số sai. |
| `3` | Quét không hoàn tất: không lấy được trang chủ (DNS, kết nối, TLS…) và không có finding nào vượt ngưỡng. Không dùng khi `--fail-on none`. |

### 7.4 Web UI cục bộ

```
python -m websec_scanner.web [--host 127.0.0.1] [--port 8765] [--timeout N] [--workers N] [--fail-on LEVEL] [--ca-bundle PATH]
```

| Tham số | Mặc định | Mô tả |
|---|---|---|
| `--host` | `127.0.0.1` | Địa chỉ bind. Khác loopback thì in cảnh báo (FR-UI-01). |
| `--port` | `8765` | Cổng lắng nghe. |
| `--timeout` | `10` | Timeout mỗi request khi quét. |
| `--workers` | `5` | Số luồng cho check path nhạy cảm. |
| `--fail-on` | `high` | Ngưỡng cho `gate_failed` và trường `gate` (FR-CI-01). |
| `--ca-bundle` | env, rồi kho OS | Như `--ca-bundle` của CLI (FR-CLI-06). |
| `--no-tls-probe` | bật probe | Như CLI; đặt lúc khởi động và áp cho mọi lần quét (FR-TLS-15). Trình duyệt không bật/tắt được. |
| `--allow-remote` | tắt | Bắt buộc khi `--host` không phải loopback; thiếu thì server từ chối khởi động (FR-UI-01, từ v1.8.0). |
| `--token` | (sinh ngẫu nhiên, in một lần) | Access token bắt buộc trên mọi request khi bind ra ngoài; bỏ qua khi `--host` là loopback (FR-UI-01, từ v1.8.0). |
| `--crawl-depth N`, `--crawl-max-pages N`, `--crawl-max-duration SECONDS` | 2, 50, 60 | Giới hạn của lần crawl khi người dùng chọn checkbox (FR-UI-14); đặt lúc khởi động, trình duyệt không đổi được. Web UI không có `--ignore-robots`: luôn theo robots.txt. |
| `--rate-limit`, `--max-requests`, `--max-duration` | không giới hạn | Như CLI; đặt lúc khởi động và áp cho mọi lần quét, trình duyệt không nâng được (FR-LIM-01, FR-LIM-03, từ v1.14.0). |

Web UI **không** có `--baseline`, `--suppressions`, `--csv`, `--junit` (quyết định chủ sản phẩm 2026-10-01: baseline là tính năng của CI và gắn với từng target). JSON của Web UI vẫn giống CLI vì các trường `baseline`, `baseline_state`, `suppression` luôn có mặt, mang giá trị `null`.

| Endpoint | Mô tả |
|---|---|
| `GET /`, `/app.js`, `/app.css` | Trang UI và file tĩnh. |
| `GET /api/checks` | Danh sách nhóm của mục 4.11: `{"groups": [{"id", "title", "description"}], "crawl": {"max_depth", "max_pages", "max_duration"}}` (`groups` từ v1.7.0, `crawl` từ v1.24.0). |
| `POST /api/scan` | Chạy quét đồng bộ, trả JSON mục 6.2 + 6.3. Body có thể có `checks`: danh sách id nhóm (không có = mọi nhóm); không phải danh sách chuỗi, rỗng hoặc có id lạ → 400. Body có thể có `crawl`: boolean (FR-UI-14); kiểu khác → 400. Mã lỗi: 400, 403, 413, 415, 429, 500 (FR-UI-02…05, FR-UI-10). |

Khi server chạy với `--allow-remote` (FR-UI-01, từ v1.8.0), mọi route ở trên (kể cả `GET /`, `/app.js`, `/app.css`, `GET /api/checks`, `GET /api/report/<id>.html`) PHẢI thêm kiểm tra access token trước khi xử lý: thiếu hoặc sai token → 403. Mặc định (loopback) không cần token.
| `GET /api/report/<id>.html` | Tải báo cáo HTML (FR-UI-06). 404 nếu không còn. |

---

## 8. Ma trận truy vết OWASP

| Nhóm check | FR | OWASP Top 10:2021 | Secure Headers / ASVS |
|---|---|---|---|
| Security headers | FR-HDR-01 … 10 | A02, A03, A05 | Secure Headers Project |
| Cookies | FR-COOKIE-01 … 04 | A05 (liên quan A07) | ASVS V3 (Session Management) |
| TLS/Certificate | FR-TLS-01 … 10 | A02 | ASVS V9 (Communications) |
| HTTP → HTTPS redirect | FR-REDIR-01 … 03 | A02 | ASVS V9 |
| CORS | FR-CORS-01 … 04 | A05 (liên quan A01) | — |
| File/path lộ | FR-EXP-01 … 06 | A01 | — |
| Directory listing | FR-EXP-07 | A05 | ASVS V14 (Configuration) |
| robots.txt | FR-EXP-08a | A01 | — |
| sitemap.xml | FR-EXP-08b | A01 | — |

Các hạng mục A04, A06 (chỉ fingerprint gián tiếp qua header, chưa đối chiếu CVE), A08, A09, A10 **không** được kiểm tra đầy đủ vì cần phân tích chủ động, mã nguồn hoặc log.

---

## 9. Kịch bản kiểm thử chấp nhận (Acceptance Test Scenarios)

Mọi AT chạy **offline**: test tự dựng HTTP/HTTPS server trên `127.0.0.1` (cổng ngẫu nhiên) và tự sinh chứng chỉ bằng `cryptography`. Chạy bằng `python -m pytest`. Cột "Test tự động" là tên hàm pytest trong `tests/`.

| ID | Kịch bản | Input | Kết quả mong đợi | Test tự động |
|---|---|---|---|---|
| AT-01 | Từ chối quét khi chưa xác nhận | Trả lời `no`/rỗng/EOF ở prompt | Không có request nào; exit code `2` | `test_at01_*` |
| AT-02 | Bỏ qua consent bằng `--yes` | `--yes` | Không hỏi; banner vẫn in; quét chạy bình thường | `test_at02_yes_flag_skips_prompt` |
| AT-03 | Thiếu toàn bộ security headers | Response không có header nào (https) | Đủ 6 finding FR-HDR-01…04, 06, 07, đúng severity | `test_at03_all_security_headers_missing` |
| AT-04 | Cookie thiếu cờ | `Set-Cookie: session=abc123; Path=/` | Finding MEDIUM liệt kê thiếu Secure, HttpOnly, SameSite; evidence trong output là `session=<redacted len=6>; Path=/`; `Priority=High`/`Partitioned` không tạo finding cho cookie tên `Priority` và không che mất cookie thật | `test_at04_cookie_missing_flags`, `test_cookie_attributes_are_parsed_like_a_browser`, `test_unchecked_attributes_do_not_hide_missing_flags`, `test_set_cookie_without_a_valid_name_is_skipped` |
| AT-05 | Lộ `.env` và `.git/HEAD` | Mock trả 200 cho 2 path này | Đúng 2 finding CRITICAL, A01:2021 | `test_at05_exposed_env_and_git_head` |
| AT-06 | Soft-404 | Mock trả 200 cho mọi path | Không có finding A01 nào | `test_at06_soft_404_suppresses_exposure_findings` |
| AT-07 | Directory listing | `/images/` chứa `Index of /images/` | Finding MEDIUM `EXPOSURE-DIR-LISTING` | `test_at07_directory_listing` |
| AT-08 | robots.txt | `Disallow: /admin/`, `Disallow: /backup/` | Finding LOW, evidence `/admin/, /backup/` | `test_at08_robots_txt_hints` |
| AT-09 | CORS phản xạ origin + credentials | Server echo `Origin`, `Allow-Credentials: true` | Finding HIGH `CORS-REFLECTS-ARBITRARY-ORIGIN` | `test_at09_*` |
| AT-10 | Chứng chỉ hết hạn, chạy qua CLI | HTTPS với cert tự ký hết hạn năm 2020 | Có `TLS-CERT-EXPIRED`; không có `TLS-CERT-NOT-TRUSTED`; exit code `1` | `test_at10_expired_certificate_end_to_end` |
| AT-11 | Target không phản hồi | Cổng đóng | `errors` có 1 dòng; 0 finding; báo cáo vẫn in; exit code `3` (quét không hoàn tất; `0` trước v1.5.0) | `test_at11_unreachable_target` |
| AT-12 | Xuất JSON hợp lệ | `--json out.json` | Parse được; đúng tập khoá mục 6.2; finding đã sắp xếp | `test_at12_json_report` |
| AT-13 | Exit code | Có ít nhất 1 CRITICAL | Exit code `1` | `test_at13_exit_code_1_on_critical` |
| AT-14 | `--no-color` | `--no-color` | Không có `\x1b[` | `test_at14_no_color_output` |
| AT-15 | Cert tự ký còn hạn, chạy qua CLI | HTTPS với cert tự ký còn hiệu lực | Chỉ có `TLS-CERT-NOT-TRUSTED`; không có finding về thời hạn | `test_at15_untrusted_valid_certificate_end_to_end` |
| AT-16 | HSTS chỉ khi https | Quét `http://` | Không có `HDR-STRICT-TRANSPORT-SECURITY-MISSING`; qua `https://` thì có | `test_at16_hsts_only_required_over_https` |
| AT-17 | `frame-ancestors` | CSP `frame-ancestors 'none'`, không/lạ XFO | Không có finding nào về X-Frame-Options | `test_at17_frame_ancestors_suppresses_x_frame_options` |
| AT-18 | sitemap.xml | `<loc>…/staging/internal-tool</loc>` | Finding LOW `EXPOSURE-SITEMAP-HINTS`, evidence là URL đó | `test_at18_sitemap_loc_hints` |
| AT-19 | Check lỗi không dừng quét | Một check ném exception | `errors` có `Check 'cors' failed: …`; các check sau vẫn chạy | `test_failing_check_is_recorded_and_scan_continues` |
| AT-20 | Cookie ở bước redirect | `/` trả 302 kèm 2 cookie (1 đủ cờ, 1 thiếu), `/home` trả 2 cookie (1 đủ, 1 thiếu) | Đúng 2 finding cho 2 cookie thiếu cờ; evidence là header gốc | `test_cookies_use_real_attributes_across_redirects`, `test_hardened_cookie_on_redirect_hop_is_not_flagged` |
| AT-21 | Chuẩn hoá target | `example.com:8443`, `localhost:8080`, `…/app?q=1` | Đúng theo FR-CLI-01 | `test_normalize_target` |
| AT-22 | Soft-404 và security.txt | Mock trả 200 cho mọi path | Không có `EXPOSURE-SECURITY-TXT` | `test_soft_404_does_not_claim_security_txt` |
| AT-23 | Target https không kết nối được | `https://` tới cổng đóng | 0 finding; 1 lỗi; không chạy nhóm TLS | `test_unreachable_https_target_has_no_findings` |
| AT-24 | Web UI: bắt buộc xác nhận quyền quét | `authorized` thiếu/`false`/`"true"`/`1` | HTTP 400; không quét | `test_scan_requires_explicit_authorization` |
| AT-25 | Web UI: chống request chéo site và DNS rebinding | `Origin` lạ; `Host` không phải loopback | HTTP 403; không quét | `test_scan_rejects_cross_origin`, `test_rejects_dns_rebinding_host`, `test_report_download_blocks_rebinding_host` |
| AT-26 | Web UI: một lần quét mỗi lúc | Gửi lần quét thứ hai khi lần đầu chưa xong | HTTP 429; lỗi nội bộ khi quét → HTTP 500, secret không vào log, lần quét sau vẫn chạy được | `test_only_one_scan_at_a_time`, `test_internal_scan_error_returns_500_and_frees_the_scan_slot` |
| AT-27 | Web UI: tải báo cáo HTML | Quét mock rồi mở `report_url` | 200, `Content-Disposition: attachment`; nội dung từ target được escape | `test_scan_result_links_to_downloadable_html_report`, `test_values_from_target_are_escaped` |
| AT-28 | Web UI: tiếng Anh | File tĩnh của UI | `lang="en"`, không có ký tự tiếng Việt | `test_ui_text_is_english` |
| AT-29 | Mô hình finding | Quét mock có nhiều loại lỗi; quét lại lần 2 | Mọi finding có `instance_key`, `fingerprint` 32 hex, `confidence`, `references`, `cwe` (trừ 3 id thông tin); 2 cookie thiếu cờ có 2 fingerprint khác nhau; fingerprint giống nhau giữa 2 lần quét và không phụ thuộc path | `test_every_finding_of_a_real_scan_is_enriched`, `test_same_type_in_two_places_gets_two_fingerprints`, `test_fingerprints_are_stable_across_scans`, `test_fingerprint_uses_origin_not_path_or_time`, `test_catalog_covers_every_finding_id` |
| AT-30 | JSON có version và khớp schema | `--json`; quét lỗi kết nối; response của Web UI (bỏ 3 trường riêng) | Cả ba khớp `docs/report.schema.json`; `schema_version` = `1.8` (giá trị hiện tại; `test_schema_version_matches_the_schema_file` ghim cả hằng số lẫn file schema); `scan_id` là UUID4 mới mỗi lần quét; schema từ chối khoá lạ | `test_schema_version_matches_the_schema_file`, `test_cli_json_report_matches_schema`, `test_failed_scan_report_matches_schema`, `test_web_response_is_the_report_plus_web_fields`, `test_every_scan_gets_a_new_scan_id`, `test_schema_rejects_unknown_fields` |
| AT-31 | CLI và Web UI cho cùng kết quả | Quét cùng một mock qua CLI `--json` và qua `POST /api/scan` | JSON giống nhau (trừ trường riêng của UI và trường thay đổi theo lần quét); `gate_failed` khớp exit code; mã lỗi và Content-Type của 2 endpoint đúng hợp đồng | `test_cli_and_web_ui_produce_the_same_report`, `test_scan_errors_are_json_with_an_error_message`, `test_report_endpoint_contract` |
| AT-32 | Không lộ secret | Mock đặt cookie `session=<giá trị mẫu>`; target có `?access_token=<giá trị mẫu>` | Console, `--json`, JSON và báo cáo HTML của Web UI không chứa hai giá trị mẫu; `secrets_redacted: true`; `--show-secrets` in cảnh báo stderr và cho `secrets_redacted: false`; Web UI **từ chối** (400 `credential_not_accepted`) khi client gửi `show_secrets`, và lần quét bình thường vẫn được che; cùng một cookie được đặt ở một bước redirect và ở response cuối (hai finding cùng fingerprint) thì cả hai giá trị đều được che; target dạng `http://user:password@host` không để lộ user/password trong console, JSON, SARIF, HTML hay tên file tải về | `test_cli_console_and_json_are_redacted`, `test_show_secrets_is_explicit_and_warns`, `test_web_ui_refuses_show_secrets_and_always_redacts`, `test_html_report_warns_when_secrets_are_shown`, `test_errors_are_redacted`, `test_sensitive_url_parameters_are_masked`, `test_same_cookie_on_a_redirect_and_the_final_response_is_redacted_in_both`, `test_credentials_in_urls_are_masked`, `test_credentials_in_the_target_url_never_reach_the_reports` |
| AT-33 | Severity CORS theo D3 | Server trả 4 tổ hợp: `*` + credentials; phản xạ + credentials; phản xạ không credentials; `*` đơn lẻ | Lần lượt MEDIUM, HIGH, MEDIUM, INFO; mô tả mỗi finding giải thích lý do mức độ; mọi finding có khuyến nghị | `test_cors`, `test_cors_findings_explain_their_severity_and_how_to_fix` |
| AT-34 | Không theo redirect ra ngoài phạm vi | Target redirect trang chủ, hoặc mọi path, sang host khác (`localhost` so với `127.0.0.1`) | Host kia không nhận request nào; `errors` có đúng 1 dòng; quét vẫn chạy; redirect tới cùng host (khác path/cổng) vẫn được theo | `test_baseline_redirect_to_other_host_is_not_followed`, `test_path_redirects_to_other_host_are_blocked_and_reported_once`, `test_in_scope`, `test_in_scope_redirects_are_followed`, `test_redirect_to_another_port_on_the_same_host_is_followed` |
| AT-35 | Redirect check luôn chạy (FIX-09) | `http://` không redirect; `http://` → HTTPS cert tự ký/hết hạn/được tin; `https://` với probe redirect sang `https://` không tồn tại, sang HTTP cùng host, sang host lạ | Lần lượt: `TLS-NO-HTTPS-REDIRECT`; `TLS-CERT-NOT-TRUSTED`/`TLS-CERT-EXPIRED` trên đúng cổng HTTPS và không có finding redirect; TLS chạy trên URL cuối; không finding; có finding; không finding + 1 lỗi phạm vi | `test_http_target_without_redirect_is_reported`, `test_http_target_redirected_to_https_with_bad_cert_reports_the_cert_not_the_redirect`, `test_http_target_redirected_to_expired_https_reports_expiry`, `test_http_target_redirected_to_trusted_https_scans_the_https_page` (skip khi TLS bị chặn), `test_probe_counts_a_redirect_to_https_without_loading_it`, `test_probe_follows_http_hops_in_scope`, `test_probe_stops_at_out_of_scope_redirect` |
| AT-36 | Header xét trên response cuối (FIX-10) | Redirect `/` → `/home`; không redirect; baseline lỗi; `http://` → HTTPS được tin; đổi host với/không có HSTS ở host gốc | `final_url`/`redirect_chain` đúng và được che secret; không đòi HSTS khi response cuối là HTTP, có đòi khi là HTTPS; `HDR-HSTS-MISSING-ON-START-HOST` mức LOW khi host gốc thiếu HSTS; không áp dụng khi cùng host hoặc response cuối là HTTP; host gốc không kết nối được → lỗi, không finding | `test_report_records_final_url_and_redirect_chain`, `test_no_redirect_gives_empty_chain`, `test_failed_baseline_has_no_final_url`, `test_final_url_and_chain_are_redacted`, `test_hsts_is_not_required_when_the_final_response_is_http`, `test_http_target_redirected_to_https_is_held_to_hsts` (skip khi TLS bị chặn), `test_start_host_without_hsts_is_reported`, `test_start_host_with_hsts_is_fine`, `test_start_host_check_does_not_apply`, `test_unreachable_start_host_is_an_error_not_a_finding` |
| AT-37 | Text sản phẩm không còn "passive" (FIX-11) | Banner CLI, `--help` của CLI và Web UI, file tĩnh của UI, báo cáo HTML, User-Agent | Không chứa "passive"; User-Agent đúng mẫu NFR-SEC-03 với `__version__`; footer UI trỏ tới `docs/SRS-websec-scanner.md` | `test_product_text_does_not_say_passive`, `test_cli_help_does_not_say_passive`, `test_user_agent_identifies_the_scanner_and_its_version`, `test_ui_footer_points_at_the_current_srs` |
| AT-38 | Rules dạng dữ liệu và đọc có giới hạn | Bảng path từ `rules/sensitive_paths.json`; file rules sai định dạng; thêm path chỉ bằng file rules; server trả body 20 MB cho mọi path | Bảng khớp 4.8.1; `rules_version` = version của file; lỗi nạp nêu rõ nguyên nhân; path mới được quét; mỗi response chỉ đọc ≤ 8 KiB, check xong trong vài giây; robots.txt/sitemap.xml chỉ đọc ≤ 512 KiB; charset lạ không làm dừng check directory listing | `test_sensitive_paths_come_from_the_rules_file`, `test_report_carries_the_rules_version`, `test_invalid_rules_are_rejected_with_a_clear_message`, `test_a_new_path_needs_only_a_rules_change`, `test_get_limited_reads_at_most_the_cap`, `test_sensitive_path_check_does_not_download_huge_files`, `test_robots_and_sitemap_are_read_up_to_their_cap`, `test_unknown_charset_does_not_stop_the_directory_listing_check` |
| AT-39 | Kiểm tra nội dung file nhạy cảm (FR-DET-01) | Mỗi path: nội dung thật; trang HTML chung, rỗng, text, JSON; site trả 200 cho mọi path có và không có `.env` thật; path 200 sai nội dung | Nội dung thật khớp chữ ký; response chung không khớp; site catch-all không có finding nhưng `.env` thật vẫn được báo; 200 sai nội dung không báo; evidence không chứa nội dung file; rules thiếu/sai chữ ký bị từ chối | `test_signature_matches_real_content`, `test_signature_rejects_generic_responses`, `test_catch_all_html_site_has_no_exposure_findings`, `test_real_file_on_a_catch_all_site_is_still_found`, `test_200_with_the_wrong_content_is_not_reported`, `test_evidence_never_contains_the_file_content`, `test_invalid_signatures_are_rejected` |
| AT-40 | Soft-404 theo vân tay (FR-DET-02) | Site trả cùng một trang (có `Contact:` và `Index of /`) cho mọi path; trang in lại path được hỏi; mọi path redirect về `/login`; `.env` và `/images/` thật trên các site đó; site 404 bình thường | Không có finding từ trang chung; file và listing thật vẫn được báo; site 404 có profile rỗng; path probe ngẫu nhiên mỗi lần; `run_scan` chỉ gửi 2 probe | `test_catch_all_page_that_happens_to_match_a_signature_is_ignored`, `test_catch_all_page_echoing_the_path_is_recognised`, `test_redirect_to_login_is_recognised`, `test_real_files_are_still_found_on_soft_404_sites`, `test_real_file_behind_login_redirects_is_still_found`, `test_normal_404_site_has_an_empty_profile`, `test_probe_paths_are_random_per_scan`, `test_run_scan_builds_the_profile_once` |
| AT-41 | Confidence và TLS bị chặn (FR-DET-03, FR-DET-16) | Finding lộ file có nội dung khớp; robots/sitemap; chứng chỉ có issuer "Avast Web/Mail Shield Root"/"Zscaler …"; chứng chỉ thường; issuer của CA công khai | Lộ file `high`, gợi ý `low`; issuer phần mềm chặn → 1 cảnh báo trong `errors` và finding TLS `low`, kể cả qua `run_scan`; chứng chỉ thường không cảnh báo; tên CA công khai (GlobalSign, Let's Encrypt, DigiCert, Sectigo) không bị nhận nhầm | `test_content_verified_exposure_findings_are_high_confidence`, `test_hint_only_findings_stay_low_confidence`, `test_scanned_exposure_finding_is_high_confidence`, `test_interceptor_issuers_are_recognised`, `test_intercepted_tls_is_flagged_and_findings_are_low_confidence`, `test_run_scan_reports_the_interception_warning`, `test_normal_certificate_gives_no_warning` |
| AT-42 | Một kho chứng chỉ (FR-CI-10) | Mặc định; `--ca-bundle` với CA tự tạo; biến môi trường; một request HTTPS qua session; file bundle thiếu/sai | Mặc định là kho OS (so sánh "khác `certifi`" chỉ chạy trên leg Windows của ma trận CI; trên Linux chỉ kiểm `verify_mode`/`check_hostname`); bundle thay kho mặc định; biến môi trường được dùng; `certifi` không bị nạp thêm vào context dùng chung; không có bundle → baseline lỗi + `TLS-CERT-NOT-TRUSTED`; có bundle → check HTTP chạy đủ, không `NOT-TRUSTED`; bundle hỏng → exit `2` | `test_default_trust_is_the_os_store_not_certifi`, `test_ca_bundle_replaces_the_default_store`, `test_env_variables_are_honoured`, `test_requests_never_adds_certifi_to_the_shared_context`, `test_without_ca_bundle_a_private_ca_is_not_trusted`, `test_ca_bundle_trusts_a_private_ca_for_http_and_tls`, `test_cli_ca_bundle_option`, `test_cli_rejects_a_missing_or_invalid_bundle` |
| AT-43 | Ngưỡng `--fail-on` và exit code `3` (FR-CI-01) | Ma trận ngưỡng × severity; target chỉ có MEDIUM với từng ngưỡng; target có CRITICAL với `none`; target không kết nối được (mặc định và `none`); chứng chỉ hết hạn; Web UI khởi động với `--fail-on medium`; tham số sai | Đúng bảng ngưỡng; exit `1`/`0` theo ngưỡng; `none` → `0`; không kết nối → `3`, với `none` → `0`; chứng chỉ hết hạn → `1` (ưu tiên hơn `3`); JSON `gate` đúng; Web UI `gate_failed` theo ngưỡng của server; báo cáo HTML nêu ngưỡng; tham số sai bị từ chối | `test_threshold`, `test_exit_code_follows_the_threshold`, `test_critical_target_with_fail_on_none_passes`, `test_unreachable_target_exits_3`, `test_unreachable_target_with_fail_on_none_exits_0`, `test_findings_over_the_threshold_win_over_incomplete`, `test_json_records_the_gate`, `test_web_ui_uses_the_server_threshold`, `test_html_report_names_the_threshold`, `test_cli_rejects_an_unknown_threshold` |
| AT-44 | Xuất SARIF (FR-RPT-02) | Quét mock; từng severity; cùng id với 2 severity; quét không kết nối được; target có secret; `--sarif PATH` | `version` 2.1.0 và `$schema`; mỗi result trỏ đúng rule và có `partialFingerprints` = fingerprint; ánh xạ `level` đúng; `security-severity` = `cvss_score` khi finding có điểm, quay về bảng theo severity khi không (từ v1.13.0); rule lấy severity cao nhất; lỗi thành notification và `executionSuccessful: false`; không lộ secret; file được ghi; output ổn định | `test_top_level_structure`, `test_every_result_points_at_its_rule`, `test_severity_mapping`, `test_security_severity_is_the_estimated_cvss_score_when_the_finding_has_one`, `test_rule_severity_is_the_highest_seen_for_that_id`, `test_errors_become_notifications_and_incomplete_scans_are_unsuccessful`, `test_sarif_is_built_from_the_redacted_report`, `test_cli_writes_the_sarif_file`, `test_output_is_deterministic` |
| AT-45 | `--html` dùng chung bộ render (FR-RPT-09) | `--json` + `--html` cùng lần quét; báo cáo Web UI tải về; target có secret; `--show-secrets`; `--json` + `--html` + `--sarif` cùng lúc | HTML của CLI = `render_html(JSON)`; HTML của Web UI = `render_html` của report Web UI trả về; không lộ secret, không có `<script`; có băng cảnh báo khi `--show-secrets`; 3 định dạng thống nhất số finding và gate | `test_cli_html_is_render_html_of_the_json_report`, `test_web_download_uses_the_same_renderer`, `test_cli_html_is_redacted_and_escaped`, `test_cli_html_with_show_secrets_carries_the_warning`, `test_all_outputs_in_one_run_agree` |
| AT-46 | Template CI (FR-CI-03) | 4 file trong `examples/ci/` | Đủ 4 template; lệnh quét chỉ dùng tham số có trong `--help` (gồm `--yes`, `--fail-on`, `--json`, `--sarif`, `--html`); có lưu ý quyền quét và exit code `3`; cài đúng tag của bản phát hành; YAML không có tab. *Không chạy trên CI thật.* | `test_all_four_templates_exist`, `test_template_uses_only_real_cli_options`, `test_template_warns_about_authorization_and_exit_codes`, `test_template_installs_the_current_release`, `test_yaml_templates_have_no_tabs` |
| AT-47 | CI của repo (FR-QA-07) | `.github/workflows/ci.yml`, `.gitleaks.toml` | Có 7 job `lint`/`test`/`min-deps`/`audit`/`docker`/`docker-publish`/`secrets` (`docker`, `docker-publish` từ v1.8.0, xem AT-59; `min-deps` từ v1.6.0: test trên Python thấp nhất với đúng phiên bản dependency thấp nhất khai báo trong `pyproject.toml`); chạy `ruff check`, `ruff format --check`, `pytest`; ma trận có Python thấp nhất theo `requires-python` và một bản mới hơn, có Windows; `pip-audit`; gitleaks quét toàn bộ lịch sử, kiểm checksum; chỉ quyền `contents: read`, không dùng secret; allowlist gitleaks chỉ gồm giá trị giả có trong `tests/test_redact.py`. *Kiểm tra nội dung file; workflow chạy thật trên GitHub sau khi push.* | `test_workflow_has_the_seven_jobs`, `test_min_deps_job_pins_the_floors_declared_in_pyproject`, `test_workflow_runs_lint_and_offline_tests`, `test_workflow_tests_oldest_supported_and_latest_python`, `test_workflow_audits_dependencies_and_scans_for_secrets`, `test_workflow_is_read_only_and_uses_no_repository_secrets`, `test_workflow_has_no_tabs`, `test_gitleaks_allowlist_only_covers_the_fake_redaction_values` |
| AT-48 | Golden file báo cáo (FR-QA-02) | Một lần chạy CLI trên mock server với `--json`, `--sarif`, `--html` | Sau khi thay scan id, thời gian, cổng, version và fingerprint bằng placeholder, cả 3 báo cáo trùng khớp `tests/golden/`; không còn timestamp hay cổng thật; không báo cáo nào chứa giá trị cookie và `.env` giả của mock server | `test_report_matches_the_golden_file`, `test_report_has_no_run_specific_values_left`, `test_report_does_not_leak_the_mock_secrets` |
| AT-49 | Mọi finding ID đều được test tạo ra (FR-QA-01) | 17 rule path nhạy cảm qua HTTP; header `X-AspNetMvc-Version`; chứng chỉ không parse được | Mỗi rule cho đúng 1 finding với id, severity, URL của rule; `HDR-INFO-X-ASPNETMVC-VERSION`; `TLS-CERT-PARSE-FAILED` (INFO) và trust check vẫn chạy. Đo **thủ công** ngày 2026-09-30: cả 47 id trong catalog đều được suite tạo ra (trước đó 33/47). **Chưa có test nào giữ cho con số này đúng** — ba test dưới đây chỉ phủ 17 rule path, 4 header lộ thông tin và `TLS-CERT-PARSE-FAILED`; `test_catalog_covers_every_finding_id` so id *khai báo trong code*, không phải id *được test sinh ra*. Số đo sẽ âm thầm sai khi thêm finding mới; xem FR-QA-08 trong backlog. | `test_every_rule_is_reported_end_to_end`, `test_headers_info_leak_one_finding_per_header`, `test_tls_unparsable_certificate_is_reported_and_trust_is_still_checked` |
| AT-50 | Target IPv6 | Host `::1` cho TLS check và redirect check | URL trong finding và request probe có dấu ngoặc (`https://[::1]:<cổng>`, `http://[::1]/`); `instance_key` giữ nguyên dạng `host:port` để fingerprint không đổi | `test_ipv6_hosts_are_bracketed_in_urls` |
| AT-51 | TLS cũ trên server thật (FR-TLS-01, FR-TLS-03) | Server local chỉ cho TLS 1.0, rồi chỉ TLS 1.1; server thường | Server cũ → đúng 1 `TLS-WEAK-PROTOCOL` (HIGH) ghi đúng phiên bản, không có `TLS-CONN-FAILED`; server thường vẫn thương lượng TLS 1.2/1.3 với cipher không yếu. Test tự skip nếu chính OpenSSL của máy chạy test không bắt tay được TLS 1.0/1.1 | `test_tls_weak_protocol_is_detected_on_a_real_legacy_server`, `test_tls_modern_server_still_negotiates_a_modern_protocol` |
| AT-52 | Chọn nhóm kiểm thử (FR-GRP-01…03) | Bảng nhóm; quét mock mặc định; chỉ `headers`+`cookies`; chỉ `directory-listing`; chỉ `cookies`; lựa chọn rỗng/id lạ/trùng/hoa; target không kết nối được; chỉ `https-redirect` trên target http | Mỗi check thuộc đúng 1 nhóm, id nhóm cố định; mặc định `scan_groups` = cả 8 nhóm và mọi finding có `check`; chọn `headers`+`cookies` thì target chỉ nhận GET `/`; `directory-listing` vẫn gửi probe soft-404 nhưng không gửi path nhạy cảm/robots; gate chỉ tính nhóm đã chạy; lựa chọn sai → `ValueError`; trùng/hoa được chuẩn hoá | `test_every_check_belongs_to_exactly_one_group`, `test_group_ids_are_stable`, `test_default_scan_runs_every_group_and_tags_each_finding`, `test_only_the_selected_groups_run_and_send_requests`, `test_selected_groups_are_reported_in_table_order`, `test_directory_listing_alone_still_uses_the_soft404_probes`, `test_gate_counts_only_the_selected_groups`, `test_invalid_group_selection_is_rejected`, `test_group_selection_ignores_duplicates_and_case`, `test_unreachable_target_still_records_the_selection`, `test_https_redirect_group_alone_on_an_http_target` |
| AT-53 | CLI chọn nhóm (FR-GRP-01, mục 7) | `--list-checks`; `--checks cookies,HEADERS`; quét đủ nhóm; `--checks tls,bogus`; thiếu target | `--list-checks` in đủ 8 nhóm, exit `0`, không hỏi xác nhận; `--checks` chỉ chạy nhóm đã chọn, console in `Check groups:` và `Not selected (not tested):`; quét đủ không in dòng `Not selected`; id sai hoặc thiếu target → exit `2` | `test_list_checks_prints_every_group_without_a_target`, `test_checks_option_selects_groups`, `test_console_does_not_list_unselected_groups_for_a_full_scan`, `test_bad_check_selection_or_missing_target_exits_2` |
| AT-54 | Web UI chọn và nhóm (FR-UI-10, FR-UI-11, mục 6.3) | `GET /api/checks` (và với Host lạ); quét mock với `checks` = `cookies`,`headers`; không có `checks`; `checks` = `[]`/`["bogus"]`/`"headers"`/`[1]`/`null`; bảng nhóm và nhóm OWASP của dữ liệu mẫu và của lần quét thật | Danh sách đúng bảng 4.11; Host lạ → 403; chỉ chạy nhóm đã chọn, `groups`/`owasp_groups` đúng bằng `output.group_findings()`/`owasp_groups()` của báo cáo, nhóm không chọn có `status` `not-selected`; không có `checks` → mọi nhóm; lựa chọn sai → 400, không quét; mỗi finding nằm đúng một nhóm ở cả hai cách nhóm; Download JSON bỏ đúng `web.WEB_ONLY_FIELDS`. *Phần hiển thị (HTML/JS) được kiểm tra bằng ảnh chụp trình duyệt headless, không có test tự động.* | `test_checks_endpoint_lists_the_groups`, `test_checks_endpoint_blocks_rebinding_host`, `test_scan_runs_only_the_selected_groups_and_returns_grouped_views`, `test_scan_without_checks_runs_every_group`, `test_scan_rejects_an_invalid_check_selection`, `test_group_findings_gives_every_group_a_status_in_table_order`, `test_owasp_groups_are_sorted_by_category_and_list_only_categories_found`, `test_grouped_views_of_a_real_scan_cover_every_finding_once`, `test_download_json_in_the_ui_strips_exactly_the_web_only_fields` |
| AT-55 | Báo cáo HTML theo nhóm (FR-UI-07) | Báo cáo mẫu chỉ chọn `headers`,`cookies`,`tls`; báo cáo quét đủ nhóm; quét mock (golden) | Có 3 phần tóm tắt/chi tiết; mọi nhóm có mục riêng (`id="group-<id>"`) và cả ba trạng thái `2 issues` / `No issues` / `Not run` đều xuất hiện trong tài liệu — việc gắn **đúng** trạng thái vào **đúng** nhóm được chứng minh ở mức `output.group_findings()` (`tests/test_groups.py`), không phải trên HTML; dòng *Not selected (not tested)* liệt kê nhóm không chọn và không xuất hiện khi quét đủ; link trong bảng OWASP trỏ tới finding có trong trang; trong nhóm sắp theo severity; khớp golden file | `test_report_groups_findings_by_test_target_and_summarises_owasp`, `test_full_scan_report_has_no_not_selected_row`, `test_report_matches_the_golden_file` |
| AT-56 | Access token khi bind ra ngoài (FR-UI-01) | `--host 0.0.0.0` không có `--allow-remote`; server dựng với `access_token` đặt sẵn (loopback thật, mô phỏng chế độ remote); request thiếu/sai token qua mọi route; token đúng qua header/query; query đúng lần đầu; query sai; nội dung log sau request có `?token=` | Thiếu `--allow-remote` → thoát code 2, không mở socket (không gọi `build_server`); mọi route (kể cả `GET /`, `/app.js`, `/api/checks`, `POST /api/scan`) trả 403 khi thiếu/sai token; header hoặc query đúng → 200; query đúng cấp cookie `HttpOnly`+`SameSite=Strict`, các request sau chỉ cần cookie; query sai không cấp cookie; log server không chứa giá trị token nguyên văn (`token=<redacted...>` thay vào đó); trang UI tự quét bằng chính scanner không có finding header từ MEDIUM trở lên | `test_default_bind_never_requires_a_token`, `test_missing_or_wrong_token_is_rejected_on_every_route`, `test_correct_token_is_accepted_via_header_or_query`, `test_valid_query_token_sets_a_cookie_used_by_later_same_origin_requests`, `test_wrong_query_token_does_not_set_a_cookie`, `test_access_token_never_appears_in_server_logs`, `test_remote_bind_without_allow_remote_refuses_to_start`, `test_web_ui_headers_pass_the_scanners_own_check` |
| AT-57 | Phạm vi & giới hạn trong mọi báo cáo (FR-RPT-08) | Console và HTML của một lần quét mock; JSON/SARIF/console/HTML của cùng lần quét | Console và HTML cùng chứa `output.SCOPE_NOTE` (console được word-wrap, so khớp sau khi chuẩn hoá khoảng trắng); JSON có trường `disclaimer` đúng bằng `output.SCOPE_NOTE` (từ v1.10.0); không định dạng nào chứa cụm từ đảm bảo tuyệt đối (`100% secure`, `fully secure`, `guaranteed secure`, `risk-free`, …) | `test_scope_note_names_its_own_limits`, `test_console_report_includes_the_scope_note`, `test_html_report_footer_includes_the_scope_note`, `test_json_report_has_a_disclaimer_field`, `test_no_absolute_assurance_language_anywhere_in_a_real_scan` |
| AT-58 | Kiểm kê license (FR-SEC-10, NFR-LEGAL-01) | `THIRD_PARTY_LICENSES.md` đối chiếu `pyproject.toml`; nội dung cột License của từng dòng | Tập package trực tiếp trong bảng Runtime/Dev khớp chính xác `dependencies`/`optional-dependencies.dev` của `pyproject.toml`; không dòng nào có license GPL/AGPL/LGPL | `test_third_party_licenses_lists_every_direct_dependency`, `test_third_party_licenses_has_no_copyleft_that_would_force_releasing_source` |
| AT-59 | Image Docker chính thức (FR-CI-04) | `Dockerfile`, `.dockerignore`; job CI `docker` build và quét mock server qua `--network host`; job `docker-publish` (chỉ khi push tag `v*`, sau khi `docker` qua) | 2 giai đoạn (không còn source/pyproject trong stage cuối); có `USER` khác root với `--uid`; entrypoint `python -m websec_scanner`; `.dockerignore` loại `.venv`/`.git`/`tests`/`docs`; có OCI label `image.source`, không tự nhận license chưa công bố. *Không build/chạy được trên máy dev (không có Docker); kiểm tra nội dung file ở đây, build và smoke test thật chạy trên GitHub.* Từ v1.10.0: `docker-publish` đẩy image lên `ghcr.io/hkbach/websec-scanner` (tag phiên bản + `latest`), chỉ chạy khi push tag `v*`, dùng `secrets.GITHUB_TOKEN` của chính lần chạy (không phải secret người dùng tạo), quyền `packages: write` chỉ cấp cho job này; **không** phải required check (không chạy trên PR). Lần publish đầu cần admin tự đặt visibility công khai cho package trên GitHub (README mục Docker). | `test_dockerfile_exists_and_is_two_stage`, `test_dockerfile_runs_as_a_non_root_user`, `test_dockerfile_entrypoint_is_the_cli`, `test_dockerfile_final_stage_does_not_copy_the_source_tree`, `test_dockerfile_has_oci_source_label_but_no_unverified_license_claim`, `test_dockerignore_excludes_the_venv_and_test_suite`, `test_workflow_has_the_seven_jobs`, `test_docker_job_builds_runs_non_root_and_smoke_tests_a_scan`, `test_docker_publish_job_only_runs_on_a_release_tag_after_the_smoke_test`, `test_workflow_is_read_only_and_uses_no_repository_secrets`, `test_jenkinsfile_installs_from_the_source_archive_not_git` |
| AT-60 | README khớp SRS và `ci.yml` (FR-DOC-01) | Câu "AT-01 to AT-NN" trong README so với số AT lớn nhất trong mục 9; danh sách check bắt buộc trong README (khối `text` và JSON của `gh api`) so với job/matrix thật của `ci.yml` | Hai giá trị bằng nhau ở cả hai phép so sánh; test tự fail nếu ai đó thêm AT hoặc đổi job/matrix mà quên sửa README | `test_readme_at_range_matches_the_srs`, `test_readme_required_checks_list_matches_the_workflow` |
| AT-61 | CVSS v3.1 ước tính theo loại finding (FR-MODEL-03) | Công thức `cvss.base_score()` với các vector mẫu đã công bố (vd `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = 9.8); mọi id trong `catalog.FINDING_CATALOG` trừ `NOT_A_WEAKNESS`; quét mock thật | Điểm khớp các ví dụ CVSS v3.1 đã công bố; mọi id có vector hợp lệ parse được và điểm trong [0, 10]; id thuộc `NOT_A_WEAKNESS` không có vector/điểm; finding của một lần quét thật có `cvss_vector`/`cvss_score` nhất quán với `catalog`; JSON đúng `docs/report.schema.json`; console, báo cáo HTML và `app.js` của Web UI đều hiện điểm kèm "(estimated)" (FR-UI-12); finding thuộc `catalog.NO_CVSS` không hiện điểm; từ v1.13.0: bảng vector khớp từng dòng với review ngày 2026-10-01, mọi id INFO nằm trong `NO_CVSS`, vector ghi đè theo instance (CORS/cookie/cipher) cho đúng điểm và `enrich()` tính lại điểm từ vector ghi đè | `test_base_score_matches_published_examples`, `test_invalid_vectors_are_rejected`, `test_catalog_entries_are_complete`, `test_every_finding_of_a_real_scan_is_enriched`, `test_cli_json_report_matches_schema`, `test_console_report_shows_the_score_as_estimated`, `test_html_report_shows_the_score_and_vector_as_estimated`, `test_web_ui_shows_the_score_as_estimated`, `test_findings_that_are_not_a_weakness_carry_no_score`, `tests/test_catalog_cvss.py` (toàn bộ) |
| AT-62 | Nhận diện cipher yếu cho đủ (FR-DET-17, FR-TLS-04) | Tên suite OpenSSL theo từng nhóm: `NULL-SHA256`, `EXP-RC4-MD5`, `EXP1024-DES-CBC-SHA`, `TLS_RSA_EXPORT_WITH_RC4_40_MD5`, `ADH-AES256-SHA`, `AECDH-AES128-SHA`, `RC4-MD5`, `EXP-RC2-CBC-MD5`, `DES-CBC-SHA`, `DES-CBC3-SHA`, `IDEA-CBC-SHA`; và suite hiện đại `ECDHE-RSA-AES256-GCM-SHA384`, `ECDHE-RSA-CHACHA20-POLY1305`, `TLS_AES_128_GCM_SHA256` | Mỗi suite yếu trả đúng lý do (`no-encryption`/`unauthenticated`/`broken`), suite export được xếp theo export chứ không theo RC2/RC4; suite hiện đại không sinh finding nào; điểm CVSS 7.4 cho nhóm không mã hoá/không xác thực và 5.9 cho nhóm còn lại; finding ghi rõ lý do trong mô tả và tên suite trong evidence | `tests/test_weak_ciphers.py` (toàn bộ) |
| AT-63 | Giới hạn tốc độ (FR-LIM-01, FR-LIM-02, FR-LIM-05, FR-QA-05) | Đồng hồ giả: 4 req/s, nhiều host, caller chậm hơn khoảng cách; mock server thật: nhóm tuần tự và nhóm chạy trên pool 5 worker; nhóm `tls` so với nhóm chỉ có baseline | Với đồng hồ giả, khoảng cách đúng 1/N và không chờ khi caller đã đủ chậm; đo trên mock server, tốc độ trung bình không vượt mức đặt và không cửa sổ 1 giây nào vượt quá, kể cả khi chạy 5 luồng; nhóm `tls` đếm nhiều request hơn nhóm không bắt tay TLS | `tests/test_limits.py`, `test_the_scanner_keeps_to_the_rate_it_was_given`, `test_the_rate_holds_even_when_checks_run_on_the_worker_pool`, `test_tls_handshakes_are_counted_even_though_they_bypass_the_session` |
| AT-64 | Dừng khi chạm hạn (FR-LIM-03, FR-LIM-06) | `--max-requests 3`; `--max-duration 0.001`; chuỗi 3 redirect với `--max-requests 2`; pool 5 worker với `--max-requests 6` | `limits.stopped_by` đúng loại hạn, `requests_sent` đúng bằng hạn (kể cả khi 5 luồng cùng chạy), `errors` có đúng một dòng `Scan stopped early` và **không** có dòng `failed:`, `gate.incomplete` là `true`; mỗi hop redirect được tính một request | `test_max_requests_stops_the_scan_and_says_so`, `test_max_duration_stops_the_scan`, `test_a_stopped_scan_is_reported_as_incomplete`, `test_every_redirect_hop_is_counted`, `test_the_limiter_is_shared_by_the_worker_pool`, `test_a_reached_limit_is_not_reported_as_a_broken_check` |
| AT-65 | Tự giảm tốc khi bị đẩy lùi (FR-LIM-04) | Response 429 và 503; `Retry-After: 2`; `Retry-After` không phải số; response 200 | 429/503 làm lần chờ kế tiếp dài hơn khoảng cách thường và tăng `slowdowns`; `Retry-After` hợp lệ được tôn trọng đúng số giây; giá trị rác quay về backoff mặc định; response bình thường không gây chờ | `test_the_scanner_slows_down_when_the_target_pushes_back`, `test_retry_after_is_honoured`, `test_a_nonsense_retry_after_falls_back_to_the_default_backoff`, `test_an_ordinary_response_does_not_slow_anything_down` |
| AT-66 | Phạm vi khai báo, loại trừ và header scan id (FR-SCOPE-01, FR-EXCL-01, FR-SCANID-01) | 10 path mẫu so với bảng mặc định; `--exclude`, `--exclude-host`, `--no-default-excludes`; regex sai cú pháp; redirect dẫn vào `/logout`; redirect sang host ngoài phạm vi; quét có và không có `--scan-id-header` | Path đổi trạng thái bị loại (kể cả chữ hoa), `/blog/how-we-delete-data` thì không; URL bị loại không hề được gửi và được ghi trong `errors`; regex sai làm CLI thoát trước khi quét; redirect vào path bị loại không được đi theo; host ngoài phạm vi vẫn bị chặn và báo; header chỉ xuất hiện khi bật cờ và bằng đúng `scan_id` | `tests/test_scope_and_exclusions.py` (toàn bộ) |
| AT-67 | Fingerprint ổn định theo site (FR-MODEL-07) | `site_root()` với path, query, fragment, cổng mặc định, thông tin đăng nhập, IPv6; finding CORS quét từ `/` và `/app/?q=1`; query có token xoay vòng; finding redirect của target `http://`; hai lần quét một site từ hai trang khác nhau | Chỉ còn scheme, host, cổng không mặc định; fingerprint CORS và redirect như nhau bất kể trang bắt đầu và token; lần quét từ site root giữ nguyên `instance_key` cũ; hai lần quét có cùng tập fingerprint | `tests/test_fingerprint_stability.py` (toàn bộ) |
| AT-68 | Baseline và so sánh (FR-BASE-01…05) | Báo cáo trước đó làm baseline; file hỏng các kiểu; finding cũ, mới, đã biến mất; `--checks` bỏ nhóm; lần quét bị `--max-requests` dừng; baseline ghi bằng `--show-secrets`; baseline của 1.13.0 | Finding cũ không làm fail gate, finding mới thì có; `summary` vẫn đếm mọi finding còn `gate.counted` thì không; finding biến mất là `fixed` chỉ khi check đã chạy và lần quét hoàn tất, nếu không là `not_rechecked`; file hỏng báo lỗi rõ; secret trong baseline không lọt sang báo cáo mới; baseline cũ sinh cảnh báo | `tests/test_baseline.py` (toàn bộ) |
| AT-69 | Suppression (FR-SUPP-01…04) | Khớp theo `id`, `fingerprint`, `path`, kết hợp nhiều trường; mục hết hạn, mục hết hạn đúng hôm nay; ngày dạng chuỗi; 7 kiểu mục sai; file không phải TOML, file không tồn tại, file rỗng; suppression kết hợp baseline | Finding bị suppress vẫn liệt kê, vẫn trong `summary`, không làm fail gate; mọi trường đã nêu phải khớp; mục hết hạn ngừng suppress và được báo trong `errors`, còn hiệu lực đến hết ngày `expires`; mọi mục sai làm hỏng cả file | `tests/test_suppressions.py` (toàn bộ) |
| AT-70 | CSV và JUnit (FR-OUT-01/02) | Hai finding khác mức; 6 kiểu payload công thức trong title/description; quét sạch; 6 tổ hợp finding × `--fail-on` × quét hoàn tất/không; markup và ký tự điều khiển từ target; xuất qua CLI | CSV mỗi finding một dòng, công thức bị vô hiệu bằng `'`, giá trị thường giữ nguyên, quét sạch vẫn có dòng tiêu đề; JUnit đúng cấu trúc, tổng số khớp, `failures` > 0 khi và chỉ khi exit code khác 0, quét sạch vẫn có 1 test, markup được escape, ký tự cấm bị bỏ; file từ CLI không lộ secret | `tests/test_exports.py` (toàn bộ) |
| AT-71 | Baseline và suppression trong mọi định dạng (FR-CI-02, FR-RPT-06, FR-REPORT-06) | Một báo cáo có finding không đổi, mới, mới-và-bị-suppress, và một finding đã sửa; báo cáo không có baseline | Console có nhãn `[NEW]`/`[UNCHANGED]`/`[SUPPRESSED ...]`, dòng *Counted toward the gate* và mục *Compared with baseline*; HTML có pill trạng thái và mục so sánh, lý do suppress được escape; SARIF có `baselineState` và `suppressions` chuẩn; không có baseline thì không thêm gì | `tests/test_baseline_views.py` (toàn bộ), `test_baseline_state_and_suppressions_use_the_native_sarif_fields`, `test_without_a_baseline_results_carry_no_baseline_state` |
| AT-72 | File cấu hình (FR-CFG-01…03) | File đầy đủ; 9 kiểu file sai (khoá gõ nhầm, sai kiểu, `show_secrets`, `yes`, `quiet`+`verbose`, không phải TOML); `${ENV}` có và thiếu biến; credential ghi thẳng; đường dẫn tương đối; quét qua `--config`; cờ CLI ghi đè; header từ file và CLI | Giá trị đúng kiểu; mọi file sai bị từ chối kèm lý do và **trước** request đầu tiên; biến thiếu là lỗi; credential ghi thẳng sinh cảnh báo, header thường thì không; đường dẫn tính theo thư mục file; CLI thắng file; header được gộp; mọi tùy chọn CLI (trừ 5 tùy chọn theo từng lần chạy) đều có khoá trong file | `tests/test_config.py` (toàn bộ) |
| AT-73 | Nhiều target (FR-MULTI-01…05) | Hai target vị trí; target sạch + target không kết nối được; `--targets-file` có comment/dòng trống; hai lần chạy cùng target; `--formats` đủ 5 loại; `--json` với nhiều target; `--baseline-dir` từ lần chạy trước; `--baseline` với nhiều target; `Authorization` với 2 host; header thường với nhiều target; `--parallel 3` với 4 target; `--quiet`; `--parallel` 0/-1/65 | Exit code theo target tệ nhất (1 > 3 > 0); tên file giống nhau giữa các lần chạy; đủ 5 loại file; tổ hợp sai bị từ chối kèm gợi ý; mỗi target so với báo cáo của chính nó; credential tới nhiều host bị từ chối, header thường thì không; quét song song đủ target và in đúng thứ tự; bảng tổng hợp liệt kê mọi target; `--quiet` một dòng mỗi target | `tests/test_multi_target.py` (toàn bộ) |
| AT-74 | Tham số vận hành (FR-OPT-01…05) | Phân tích header/cookie hợp lệ và có CR/LF/NUL; 10 tên header nhạy cảm/không; target phản xạ `Authorization` và cookie vào evidence, xuất 5 định dạng; header thường bị phản xạ; `--user-agent` thường và có CR/LF; proxy cục bộ cho target `http://` và cho check TLS qua `CONNECT`; proxy có credential; proxy `https://`/`socks5://`/không scheme; `--version`; `--quiet`; `--verbose` với `Authorization` | Header/cookie tới được target; credential **không** xuất hiện trong bất kỳ định dạng nào, console hay stderr; giá trị header thường giữ nguyên; header injection bị chặn trước request đầu tiên; User-Agent = tiền tố + chuỗi của scanner; request HTTP và cả hai lần bắt tay TLS đi qua proxy, check TLS vẫn đo được cert thật; `Proxy-Authorization` được gửi, mật khẩu không bị in; proxy không phải `http://` bị từ chối; `--quiet` một dòng và giữ exit code, lý do quét không hoàn tất vẫn có trên stderr; `--verbose` log mỗi request đã che secret | `tests/test_operating_options.py` (toàn bộ) |
| AT-75 | Target không quét được bị từ chối (FR-CLI-01, FR-CLI-07, FR-UI-04) | Target hợp lệ (hostname trần, `host:port`, IPv6, có path/query, scheme viết hoa); target không quét được (`ftp://`, `gopher://`, `file://`, `javascript:alert(1)`, `data:`, `http://` thiếu host, `https:///path`, chuỗi rỗng); một dòng hỏng trong `--targets-file`; cùng tập target qua Web UI | Target hợp lệ được chuẩn hoá đúng; target không quét được làm CLI thoát với exit code 2 và **không in gì ra stdout** (chưa có banner, chưa có request); lỗi trong `--targets-file` nêu rõ tên file và dòng sai; Web UI từ chối đúng cùng tập target đó với 400, không phải 500 | `tests/test_target_validation.py` (toàn bộ), `test_scan_rejects_invalid_targets` |
| AT-76 | Console không bị target điều khiển (FR-REPORT-08) | Target đặt chuỗi escape vào `Server`, `X-Powered-By`, `Set-Cookie`, `robots.txt` và vào `Location`; chuỗi xoá dòng kiểu `\x1b[2K\x1b[1A`; chạy có và không có `--no-color`; `--quiet`; báo cáo JSON | Không ký tự điều khiển nào của target ra tới terminal ở mọi chế độ; escape hiện dưới dạng `\xNN` nhìn thấy được chứ không bị xoá; mã màu của scanner vẫn hoạt động; JSON vẫn giữ byte thật | `tests/test_terminal_safety.py` (toàn bộ) |
| AT-77 | Server hỏng không làm sập scanner (NFR-REL-01) | 6 header `Location` dị dạng: IPv6 thiếu đóng ngoặc, port không phải số, port quá lớn, scheme-relative hỏng, có ký tự NUL | Lần quét vẫn hoàn tất và trả về kết quả; redirect không parse được thì không đi theo và được ghi vào `errors`; không có traceback | `tests/test_malformed_responses.py` (toàn bộ) |
| AT-78 | Exclusion áp dụng cho cả target (FR-EXCL-02) | Target là `/checkout/` và `/logout` trên mock server ghi lại mọi request; `--exclude-host` chính host của target | Không request nào tới server; `baseline_fetched` là False; `errors` nói target bị chính cấu hình loại trừ; exit code 3, không phải 0 | `test_a_target_on_an_excluded_path_is_not_fetched_either`, `test_an_excluded_target_is_reported_as_incomplete_not_clean`, `test_an_excluded_host_is_never_requested_during_a_scan` |
| AT-79 | Cờ phạm vi đi từ argparse tới session (FR-EXCL-01) | `--exclude-host cdn.example` và `--no-default-excludes` qua `cli.main()` | `build_session()` nhận đúng `excluded_hosts` và `exclusions` rỗng; cả hai lần bắt tay TLS đều đi qua CONNECT của proxy | `test_the_scope_flags_reach_the_session`, `test_both_tls_handshakes_are_tunnelled_not_just_one` |
| AT-80 | Web UI không nhận credential (FR-UI-13, D8) | `POST /api/scan` với từng trường trong `CREDENTIAL_FIELDS` cùng cách viết camelCase/kebab-case/hoa; tên kiểu `access_token`, `session_id`, `x-api-key`; giá trị rỗng; `authorized: false` kèm credential; trường lạ `chekcs`; target có `user:pass@`, có và không có scheme; `?token=` trong target; payload thật của `app.js` | Credential và trường lạ: 400 với `code` và `field` đúng, **không bao giờ** có lần quét nào chạy, giá trị không xuất hiện trong response hay stderr của server; credential thắng trường lạ và thắng lỗi `authorized`; `?token=` vẫn quét được và bị che; lỗi khác giữ dạng `{error}`; mọi trường `app.js` gửi nằm trong `ALLOWED_SCAN_FIELDS` | `tests/test_web_credentials.py` (toàn bộ), `test_web_ui_refuses_show_secrets_and_always_redacts` |
| AT-81 | Khung benchmark độ chính xác (FR-QA-03, D6) | File ground truth hợp lệ và các kiểu file sai (thiếu khóa, image theo tag hoặc digest ngắn, target ngoài loopback, khóa lạ, thiếu lý do, nhóm sai, trùng, vừa expect vừa forbid); chấm điểm TP/FP/FN/chưa phân loại; gate với baseline (mất finding đúng, finding sai mới, cải thiện, ground truth đổi, image khác); `python -m benchmarks.run` với scanner thật trên mock cục bộ ở ba chế độ (capture, update-baseline, chấm điểm) có dàn dựng hồi quy; compose, workflow và file expected trong repo | precision/recall theo nhóm, `None` (không phải 0 hay 1) khi mẫu số bằng 0; finding chưa phân loại, digest lệch, file chưa duyệt, thiếu baseline hoặc app không chạy đều exit 2; mất finding đúng hoặc có finding sai mới là hồi quy (exit 1), cải thiện vẫn exit 0; target ngoài loopback bị từ chối trước khi gửi request nào; evidence trong artifact đã che; mọi image ghim digest, mọi cổng chỉ bind `127.0.0.1`; workflow có lịch + chạy tay, quyền chỉ đọc, luôn dừng app và giữ kết quả | `tests/test_benchmark_scoring.py`, `tests/test_benchmark_run.py`, `tests/test_benchmark_guards.py` (toàn bộ) |
| AT-82 | Dò chủ động giao thức và nhóm cipher TLS (FR-TLS-03, FR-TLS-04, FR-TLS-12…16) | Server TLS giả ở mức giao thức (SSLv3, TLS 1.0 …1.3, RC4, 3DES, NULL; trả alert, đóng, reset, im lặng, trả HTTP, trả từng mảnh); server OpenSSL thật hiện đại và chỉ TLS 1.0; qua proxy; có limiter; ngân sách thấp; host không kết nối được; chặn giữa đường; `--no-tls-probe` ở CLI, config và Web UI | Mỗi probe là một kết nối gửi đúng một bản ghi, strict parser đọc được mọi ClientHello, ClientHello tự dựng khiến OpenSSL thật trả ServerHello đúng phiên bản; đúng phiên bản và nhóm được báo, mỗi cái một finding `host:port:<tên>`, thương lượng và probe trùng chỉ là một; server hiện đại thật không bị báo yếu; tối đa 13 kết nối, qua proxy, qua limiter, `ScanLimitReached` không bị nuốt; probe không chạy được vào `errors` một dòng cho mỗi lý do và không tạo finding; không kết nối được thì dừng sau một lần thử; chặn giữa đường hạ confidence; Web UI từ chối trường `tls_probe` từ trình duyệt | `tests/test_tls_probe_rules.py`, `tests/test_tls_probe.py`, `tests/test_tls_probe_check.py` (toàn bộ) |
| AT-83 | API inventory từ file spec (FR-SPEC-01…06, D9) | Spec JSON/YAML OpenAPI 3.0, 3.1 và Swagger 2.0; spec thật của VAmPI (thử thủ công, không commit); tag YAML nguy hiểm, billion laughs, alias tự tham chiếu, lồng 100.000 tầng, khoá lặp, file > 5 MB; 19 dạng `$ref` bị cấm (URL, `file://`, tuyệt đối, UNC, `..`, `%2e%2e`, NUL, symlink…), vòng, chuỗi > 32, quá nhiều ref/file/dung lượng, tham chiếu tới thư mục; `--api-spec` ở CLI, config, nhiều target; spec lỗi; chữ điều khiển terminal và credential trong spec; Web UI | Spec hợp lệ cho đúng servers/endpoint/parameter/security đã hợp nhất và sắp xếp ổn định, không có example/default/description; mọi spec độc hại là `SpecError` có tên file, không treo, không crash, không mạng, không đọc file ngoài thư mục (nội dung file bí mật không xuất hiện trong lỗi); spec lỗi exit 2 trước request đầu tiên; JSON có `api` (null khi không dùng), khớp schema 1.9 và schema nghiêm với khoá lạ; không request nào tới endpoint hay server trong spec; console cắt ở 100 dòng và vô hiệu hoá ký tự điều khiển; credential bị che; Web UI trả `api: null` và từ chối trường `api_spec` | `tests/test_api_spec_loader.py`, `tests/test_api_inventory.py`, `tests/test_api_cli.py` (toàn bộ) |
| AT-84 | Crawler HTTP (FR-CRW-01…08, FR-CRAWL-01/03/04) | Site cục bộ nhiều trang, có vòng lặp link, link ra origin khác, redirect ra ngoài, trang không phải HTML, robots.txt, trang lỗi mạng: crawler chỉ yêu cầu đúng các trang trong phạm vi và nhật ký request của site chứng minh điều đó; dừng đúng `--crawl-depth`, `--crawl-max-pages`, `--crawl-max-duration` và `--max-requests`; cùng một lỗi header/cookie ở nhiều trang là một finding có `affected_urls` và `affected_count`, `fingerprint` không đổi so với lần quét không crawl; không có `--crawl` thì không có request nào thêm và `crawl` là `null`; `--crawl-depth` không kèm `--crawl` thoát code `2` trước mọi request; Web UI từ chối `crawl`. | `python -m pytest tests/test_crawler_links.py tests/test_crawler_engine.py tests/test_crawler_scan.py tests/test_crawler_cli.py` |
| AT-86 | Checkbox crawl của Web UI (FR-UI-14, FR-CRW-08) | `crawl: true` làm quét thêm các trang được link tới và `crawl: false` hoặc vắng mặt thì chỉ quét trang target (nhật ký request của site giả chứng minh); `crawl` là chuỗi, số, `null`, mảng hay object: 400 và không bắt đầu quét; `crawl_depth`, `crawl_max_pages`, `crawl_max_duration`, `ignore_robots`: 400 `unknown_field`; giới hạn của server áp dụng và trình duyệt không nâng được; robots.txt luôn được theo; `--max-requests` của server cắt cả crawl; `GET /api/checks` nêu đúng giới hạn của server; JS thật của trang (chạy bằng Node trên DOM giả): payload chỉ có `crawl` khi chọn và khi có nhóm `headers`/`cookies`, hint nêu đúng giới hạn, "Also seen on" và dòng Crawl chỉ là văn bản, tải JSON bỏ `crawl_message` và giữ `crawl`. | `python -m pytest tests/test_web_crawl.py tests/test_web_ui_js.py` |

---

## 10. Rủi ro và hạn chế đã biết

- **Không phải DAST toàn diện:** không phát hiện injection thật, broken authentication ở tầng logic, IDOR, SSRF, lỗi business logic.
- **Chỉ quét trang chủ** cho phần lớn check; không crawl, có thể bỏ sót cấu hình khác nhau giữa các route.
- **False positive:** robots.txt/sitemap.xml (path "nghe nhạy cảm" chưa chắc tồn tại hay lộ). Path nhạy cảm đã kiểm tra nội dung (FR-EXP-04), nhưng chữ ký là heuristic: một file khác vô tình khớp mẫu (ví dụ file text bắt đầu bằng số cho `.svn/entries`) vẫn có thể bị báo, và một file thật có định dạng lạ có thể bị bỏ sót.
- **False negative:** target dùng CDN/WAF có thể chặn hoặc trả response khác cho User-Agent của scanner. TLS chỉ xét giao thức/cipher **được thương lượng**, không dò các phiên bản cũ server còn bật (FR-DET-04).
- **Kho chứng chỉ (B1, đã xử lý ở v1.5.0):** trước v1.5.0, request HTTP tin `certifi` còn TLS check tin kho hệ điều hành, nên sau một thành phần chặn TLS mà CA chỉ có trong kho OS (trên máy dev là Avast Web/Mail Shield), mọi site HTTPS bị báo "Could not fetch" với 0 finding và exit code `0`. Từ v1.5.0 cả hai dùng cùng một kho (FR-CLI-06): mặc định là kho OS, hoặc `--ca-bundle`. Hạn chế còn lại: nếu kho OS thiếu một CA mà `certifi` có, site đó sẽ bị coi là không tin cậy; khi đó dùng `--ca-bundle`.
- **TLS bị phần mềm cục bộ chặn giữa đường:** trên máy có phần mềm ký lại TLS (ví dụ Avast Web/Mail Shield, kể cả với `127.0.0.1`), nhóm TLS đo **kết nối tới phần mềm đó** chứ không phải tới server: giao thức và cipher là do phần mềm chọn (có thể bỏ sót `TLS-WEAK-PROTOCOL`/`TLS-WEAK-CIPHER`), chứng chỉ là bản do nó ký lại. Kết quả TLS trên các máy như vậy không đáng tin; nên quét từ máy hoặc CI không có TLS inspection. Tool tự cảnh báo khi issuer thuộc danh sách phần mềm/proxy chặn TLS đã biết (FR-TLS-11); phần mềm không có trong danh sách sẽ không được nhận ra. Test cần bắt tay TLS được tin cậy sẽ tự skip khi phát hiện việc chặn này.
- **Che secret dựa trên quy tắc:** chỉ che giá trị cookie và tham số URL có tên thuộc danh sách ở NFR-SEC-04. Secret nằm ở chỗ khác (ví dụ trong nội dung CSP hay header `Server`) sẽ không bị che. Báo cáo vẫn chứa URL, header và cấu hình của target nên chỉ chia sẻ trong phạm vi được phép.
- **TLS mở tối đa 13 kết nối** (Bước A, Bước B và 11 probe, từ v1.20.0); chấp nhận được vì chỉ là bắt tay chuẩn, không bao giờ hoàn tất khi dò, có giới hạn và có thể tắt (`--no-tls-probe`). Probe cho phiên bản cũ có thể xuất hiện trong log IDS/WAF của target.
- **`TLS-CERT-NOT-TRUSTED` gộp nhiều nguyên nhân** (tự ký, thiếu intermediate, sai hostname, CA lạ) vào một mã (FR-DET-05).
- **Web UI quét đồng bộ:** trình duyệt chờ tới khi quét xong, không có tiến độ hay nút huỷ (FR-WEB-03). Báo cáo chỉ nằm trong bộ nhớ.
- **Trên Windows có Application Control**, lần đầu nạp DLL native của `cryptography` có thể bị chặn; cần IT allowlist nếu gặp trên máy CI.

---

## 11. Lộ trình mở rộng

Lộ trình chi tiết, độ ưu tiên và thứ tự sprint nằm ở `docs/PRODUCT-BACKLOG.md` (mục 5 và 9). Tài liệu này không lặp lại để tránh hai nơi lệch nhau.

---

## 12. Quyết định đã chốt, chưa triển khai

Các quyết định dưới đây đã được chủ sản phẩm chốt ngày 2026-09-30. Code hiện chưa làm, trừ D1 (mục 3.3), D2 (Sprint 3: FR-COOKIE-04, NFR-SEC-04), D3 (Sprint 3: FR-CORS-02…04) D4 (Sprint 3b: NFR-SEC-05), D5 và FIX-10 (Sprint 3b: FR-HDR-01, FR-HDR-11, mục 6.2) và FIX-09 (Sprint 3b: FR-CLI-05, FR-REDIR-01, FR-REDIR-03). Khi code xong: cập nhật các FR tương ứng ở mục 4, thêm AT ở mục 9, rồi xoá dòng khỏi bảng.

| ID | Quyết định | FR sẽ thay đổi | Phụ thuộc | Backlog |
|---|---|---|---|---|
| D1 | Web UI là công cụ cục bộ chạy chung tiến trình, gọi thẳng `run_scan()`; không có server/service riêng. **Đã triển khai** (mục 3.3, 4.10). | — | — | 1.4 |

---

## 13. Điểm chờ xác nhận

Hiện không có điểm nào. Exit code `3` (Q1 cũ) đã được xác nhận và triển khai ở v1.5.0 (FR-CLI-04).

---

*Tài liệu này mô tả hành vi của mã nguồn `websec_scanner` `v1.11.0` trong repo (CLI + Web UI cục bộ), đã đối chiếu với code và với các test tự động của v1.11.0 ngày 2026-09-30 (các test cần bắt tay TLS được tin cậy tự skip trên máy có phần mềm chặn TLS). Khi code thay đổi, cập nhật FR/NFR/AT tương ứng trong cùng thay đổi để tài liệu và mã nguồn không lệch nhau.*
