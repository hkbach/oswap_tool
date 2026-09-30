# SRS – OWASP-Aligned Non-intrusive Web Security Scanner

| | |
|---|---|
| **Tài liệu** | Software Requirements Specification (SRS) |
| **Sản phẩm** | OWASP-Aligned Non-intrusive Web Security Scanner (CLI + Web UI cục bộ) |
| **Phiên bản tài liệu** | 1.8 |
| **Ngày** | 2026-09-30 (v1.0: 2026-09-22 · v1.1: 2026-09-23 · v1.2–v1.7: 2026-09-30) |
| **Chuẩn tham chiếu** | IEEE 830-1998 (rút gọn) |
| **Trạng thái** | Mô tả lại (as-built) mã nguồn `owasp_scanner` `v1.6.0` trong repo `hkbach/oswap_tool` (CLI + Web UI cục bộ, sau Sprint 7). Đây là **tài liệu requirement duy nhất**; các bản SRS gửi rời trước đây không còn hiệu lực. |
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

Tài liệu này đặc tả yêu cầu chi tiết cho **OWASP-Aligned Non-intrusive Web Security Scanner**: công cụ quét một website và đối chiếu cấu hình HTTP/TLS quan sát được với khuyến nghị của OWASP. Tài liệu dùng để:

- Lập trình và mở rộng tool (giữ đúng hành vi hiện có, hoặc port sang ngôn ngữ/kiến trúc khác).
- Viết acceptance test.
- Làm tài liệu tham chiếu khi bàn giao, đánh giá nội bộ hoặc trao đổi với khách hàng.

### 1.2 Phạm vi sản phẩm

Sản phẩm là một **công cụ Python** có hai lối vào dùng chung một lõi quét:

- **CLI** `python -m owasp_scanner <target>`.
- **Web UI cục bộ** `python -m owasp_scanner.web`, chạy trên máy người dùng (mục 3.3).

Tool nhận một URL hoặc hostname, gửi các request HTTP **GET thông thường, không chứa payload tấn công**, rồi trả về danh sách finding về cấu hình bảo mật. Mỗi finding có mức độ nghiêm trọng, mã OWASP Top 10:2021, evidence và khuyến nghị khắc phục. Kết quả xuất ra terminal (có màu), file JSON, hoặc trang web và báo cáo HTML.

Đây là **non-intrusive configuration scanner** (scanner cấu hình không xâm lấn), **không phải** DAST toàn diện (xem mục 2.4 và 10). Tool không hoàn toàn thụ động. Với một target `https://`, một lần quét gửi tới target khoảng **29 request GET** và **2 lần bắt tay TLS**:

| Nhóm | Request |
|---|---|
| Baseline (trang chủ) | 1 GET |
| TLS (mục 4.5) | 2 lần bắt tay TLS, không gửi HTTP |
| Redirect HTTP → HTTPS (mục 4.6) | Nhập `https://`: 1 GET tới `http://<hostname>/` (thêm 1 GET cho mỗi bước redirect HTTP). Nhập `http://`: không gửi thêm, dùng chuỗi redirect của baseline |
| CORS (mục 4.7) | 1 GET có header `Origin` giả lập |
| Path nhạy cảm (mục 4.8) | 2 probe soft-404 (dùng chung với directory listing) + 17 path, mỗi response đọc tối đa 8 KiB |
| Directory listing | 6 thư mục |
| robots.txt, sitemap.xml | 2 GET |

Với target `http://` không chuyển sang HTTPS: không có nhóm TLS, còn 27 GET. Nếu target `http://` chuyển sang HTTPS, nhóm TLS chạy trên URL HTTPS đó (FR-CLI-05). Mỗi redirect trong phạm vi (NFR-SEC-05) cũng là một request, và mỗi lỗi kết nối được thử lại tối đa 1 lần (NFR-PERF-03). Tool không gửi payload khai thác và không thay đổi dữ liệu phía target.

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

Tool chạy độc lập, không có server hay service riêng (quyết định D1, mục 12). Người dùng chạy `python -m owasp_scanner <target>` từ terminal, gọi từ pipeline CI/CD, hoặc mở Web UI cục bộ chạy chung tiến trình với lõi quét (mục 3.3).

### 2.2 Đối tượng người dùng

- Kỹ sư bảo mật / DevSecOps kiểm tra nhanh cấu hình bảo mật trước khi release.
- Delivery/QA lead cần báo cáo nhanh về "vệ sinh" cấu hình HTTP của website nội bộ hoặc website khách hàng **đã được cấp phép**.
- Pipeline CI/CD chạy tự động, chặn build khi có finding CRITICAL/HIGH.

### 2.3 Giả định và ràng buộc

- Người vận hành **có quyền hợp pháp** để quét target (sở hữu hệ thống hoặc có văn bản uỷ quyền). Đây là ràng buộc bắt buộc — xem FR-CONSENT-01 và FR-UI-02.
- Target phản hồi HTTP(S) tiêu chuẩn; tool không hỗ trợ site yêu cầu đăng nhập/OAuth để vào trang chủ.
- Môi trường chạy có Python ≥ 3.12 và cài được các package `requests` ≥ 2.32.3, `urllib3` ≥ 2.0.0, `cryptography` ≥ 42 (mức tối thiểu được CI kiểm tra, job `min-deps`). `cryptography` dùng để đọc ngày hiệu lực của chứng chỉ độc lập với bước xác thực trust chain (mục 4.5).
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
owasp_scanner/
├── __main__.py        # Cho phép `python -m owasp_scanner`
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

1. Người dùng chạy `python -m owasp_scanner <target> [options]`.
2. Tool in **consent banner** và hỏi xác nhận quyền quét (bỏ qua nếu có `--yes`). Từ chối → thoát với exit code `2`, không gửi request nào.
3. Chuẩn hoá target (FR-CLI-01).
4. Gửi GET baseline tới trang chủ target. Nếu thất bại, ghi lỗi vào `errors`, rồi:
   - nếu lỗi xảy ra ở tầng TLS (ví dụ chứng chỉ hết hạn hoặc không được tin cậy), vẫn chạy nhóm check TLS (mục 4.5) trên **đúng URL HTTPS bị lỗi** (có thể là bước redirect từ `http://`), rồi dừng; nếu target nhập `http://` và lỗi xảy ra sau khi đã chuyển sang HTTPS thì redirect check coi như đạt (FR-FIX-09);
   - các lỗi khác (DNS, timeout, connection refused) thì dừng ngay, báo cáo có 0 finding.
5. Nếu baseline thành công, chạy lần lượt các check theo thứ tự cố định: security-headers → cookies → tls (nếu chuỗi redirect của baseline có URL HTTPS) → http-to-https-redirect → hsts-start-host (chỉ khi redirect đổi host và kết thúc ở HTTPS, FR-HDR-11) → cors → sensitive-paths → directory-listing → robots-sitemap. Mỗi check trả về `list[Finding]`, gộp vào `ScanResult`. Check nào ném exception thì lỗi được ghi vào `errors` và các check sau vẫn chạy (FR-REPORT-05).
6. In báo cáo ra terminal (sắp xếp theo severity); nếu có `--json PATH`, ghi thêm file JSON.
7. Thoát với exit code theo FR-CLI-04.

### 3.3 Web UI cục bộ (as-built, đã đối chiếu `web.py` ngày 2026-09-30)

- Khởi động bằng `python -m owasp_scanner.web` (tham số ở mục 7.4). Module `web.py` dùng `http.server` của Python (`ThreadingHTTPServer`), mặc định nghe ở `127.0.0.1:8765`. Không cần dependency ngoài.
- Trình duyệt tải 3 file tĩnh trong `owasp_scanner/static/`: `index.html`, `app.js`, `app.css`. Trang không tải gì từ internet.
- Người dùng nhập URL/hostname, tick ô xác nhận quyền quét rồi bấm **Scan**. `app.js` gửi `POST /api/scan` với body JSON `{"target": "...", "authorized": true}`.
- Server kiểm tra request theo FR-UI-02…04, chuẩn hoá target như CLI, rồi gọi `run_scan(target, timeout, workers)` **ngay trong thread xử lý request** (đồng bộ). Mỗi lúc chỉ chạy một lần quét.
- Kết quả trả về là JSON đúng mục 6.2, kèm các trường riêng của Web UI: `gate_failed`, `gate_status`, `gate_message`, `report_id`, `report_url` (mục 6.3).
- Kết quả hiện ngay dưới ô nhập: bảng tổng hợp theo severity, trạng thái gate, lỗi non-fatal, danh sách finding có lọc theo severity. Nút **Download JSON** tải JSON cùng định dạng với `--json` của CLI.
- Link **Download Test result** nằm ngay dưới ô nhập URL, chỉ hiện khi có kết quả, và bị ẩn trong lúc đang quét lần mới. Link trỏ tới `GET /api/report/<id>.html`: server tạo báo cáo HTML bằng `render_html()` từ báo cáo đang giữ trong bộ nhớ và trả về dạng file tải xuống. Server giữ báo cáo của 20 lần quét gần nhất; tắt server là mất.
- Mọi chữ trên UI và trong báo cáo HTML là tiếng Anh (NFR-USA-03).

---

## 4. Yêu cầu chức năng (Functional Requirements)

Quy ước mã: `FR-<NHÓM>-<SỐ>`. Priority: **M**ust / **S**hould / **C**ould (MoSCoW).

### 4.1 Nhóm CLI & vòng đời chạy

| ID | Yêu cầu | Priority |
|---|---|---|
| FR-CLI-01 | Tool PHẢI nhận một tham số bắt buộc `target` (URL hoặc hostname). Nếu chuỗi nhập không chứa `://`, tool PHẢI thêm `https://` (kể cả dạng `host:port`, ví dụ `example.com:8443` → `https://example.com:8443/`). Tool PHẢI thêm `/` vào cuối **phần path** nếu chưa có, giữ nguyên query string (ví dụ `https://a.example/app?q=1` → `https://a.example/app/?q=1`). | M |
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
- **Bước B (xác thực):** `ssl.create_default_context()`, chỉ để phát hiện lỗi trust chain/hostname, và **chỉ chạy khi Bước A cho thấy chứng chỉ đang trong thời hạn hiệu lực**, để không báo 2 CRITICAL cho cùng một nguyên nhân.

| ID | Yêu cầu | Severity | OWASP | Priority |
|---|---|---|---|---|
| FR-TLS-01 | Tool PHẢI thực hiện Bước A để lấy bytes chứng chỉ (DER), giao thức và cipher đã thương lượng. Bước này không được thất bại chỉ vì lý do trust/hostname, và PHẢI chấp nhận cả server chỉ hỗ trợ giao thức/cipher cũ: context của Bước A đặt `minimum_version = MINIMUM_SUPPORTED` và cipher `DEFAULT:ALL:@SECLEVEL=0` (từ v1.6.0). Trước v1.6.0, mặc định của Python (TLS 1.2+, SECLEVEL 2) khiến server chỉ có TLS 1.0/1.1 bị báo `TLS-CONN-FAILED` thay vì `TLS-WEAK-PROTOCOL`. `DEFAULT` đứng đầu nên server hiện đại vẫn thương lượng như với client thông thường. Bước B giữ mặc định nghiêm ngặt; với server chỉ có TLS < 1.2, Bước B không kết nối được và không kết luận về trust. | — | — | M |
| FR-TLS-02 | Nếu Bước A thất bại vì lý do kết nối (timeout, DNS, connection refused, lỗi OS/SSL khác), PHẢI tạo finding `TLS-CONN-FAILED` và DỪNG các kiểm tra TLS còn lại. | INFO | A02:2021 | M |
| FR-TLS-03 | Nếu giao thức ở Bước A thuộc {`SSLv2`,`SSLv3`,`TLSv1`,`TLSv1.1`}, PHẢI tạo finding `TLS-WEAK-PROTOCOL`. *(Chỉ xét giao thức được thương lượng; dò chủ động là FR-DET-04 trong backlog.)* | HIGH | A02:2021 | M |
| FR-TLS-04 | Nếu tên cipher ở Bước A chứa một trong {`RC4`,`3DES`,`MD5`,`NULL`,`EXPORT`}, PHẢI tạo finding `TLS-WEAK-CIPHER`. *(OpenSSL 3 thường không còn RC4/EXPORT, nên các suite này chỉ phát hiện được khi OpenSSL của máy quét còn hỗ trợ.)* | HIGH | A02:2021 | M |
| FR-TLS-05 | Tool PHẢI giải mã chứng chỉ DER từ Bước A bằng `cryptography` để đọc `not_valid_before`/`not_valid_after`. Nếu hiện tại sớm hơn `not_valid_before`, PHẢI tạo finding `TLS-CERT-NOT-YET-VALID`. | CRITICAL | A02:2021 | S |
| FR-TLS-06 | Nếu hiện tại trễ hơn `not_valid_after`, PHẢI tạo finding `TLS-CERT-EXPIRED`, dựa hoàn toàn vào dữ liệu Bước A. | CRITICAL | A02:2021 | M |
| FR-TLS-07 | Nếu chứng chỉ còn hiệu lực nhưng còn dưới 30 ngày, PHẢI tạo finding `TLS-CERT-EXPIRING-SOON`. Ngưỡng 30 ngày là hằng số `_CERT_EXPIRY_WARN_DAYS` ở đầu module. | MEDIUM | A02:2021 | S |
| FR-TLS-08 | Tool PHẢI thực hiện Bước B (kết nối xác thực bằng kho chứng chỉ của FR-CLI-06, giống hệt request HTTP) **chỉ khi** FR-TLS-05 và FR-TLS-06 không tạo finding. Nếu Bước B ném `SSLCertVerificationError`, PHẢI tạo finding `TLS-CERT-NOT-TRUSTED` với thông điệp lỗi gốc (gộp các nguyên nhân: tự ký, thiếu intermediate, sai hostname, CA không được tin cậy). Lỗi kết nối ở Bước B không tạo finding. | CRITICAL | A02:2021 | M |
| FR-TLS-09 | Nếu FR-TLS-05 hoặc FR-TLS-06 đã tạo finding, tool PHẢI bỏ qua Bước B, không tạo thêm `TLS-CERT-NOT-TRUSTED`. | — | — | M |
| FR-TLS-10 | Nếu không giải mã được chứng chỉ, PHẢI tạo finding `TLS-CERT-PARSE-FAILED` và vẫn chạy Bước B. | INFO | A02:2021 | C |
| FR-TLS-11 | **Phát hiện TLS bị chặn giữa đường (FR-DET-16).** Nếu issuer của chứng chỉ đọc được ở Bước A chứa một từ khoá trong `rules/tls_interceptors.json` (phần mềm diệt virus có web shield, gateway TLS inspection, proxy debug; không bao giờ là tên CA công khai), tool PHẢI ghi **một cảnh báo** vào `errors` (nêu host:port và issuer) và đặt `confidence` của mọi finding TLS của lần kiểm tra đó là `low`. Đây là cảnh báo, không phải finding. | — | — | S |

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
| FR-CORS-01 | Tool PHẢI gửi GET tới target kèm `Origin: https://owasp-scanner-cors-test.invalid`. | — | — | M |
| FR-CORS-02 | Nếu `Access-Control-Allow-Origin: *` và `Access-Control-Allow-Credentials: true` cùng xuất hiện, PHẢI tạo finding `CORS-WILDCARD-WITH-CREDENTIALS`. Mô tả PHẢI nêu rõ trình duyệt từ chối request có credentials khi origin là `*`, nên tổ hợp này không khai thác trực tiếp được qua trình duyệt; nó cho thấy CORS bị cấu hình sao chép/nhầm và client không phải trình duyệt vẫn có thể làm theo, nên cần rà soát toàn bộ policy. *(Trước D3, ngày 2026-09-30, mức này là CRITICAL.)* | MEDIUM | A05:2021 | M |
| FR-CORS-03 | Nếu `Access-Control-Allow-Origin` phản xạ đúng Origin giả lập, PHẢI tạo finding `CORS-REFLECTS-ARBITRARY-ORIGIN`: HIGH nếu có `Access-Control-Allow-Credentials: true` (mọi website người dùng đã đăng nhập ghé qua đều đọc được response có xác thực), ngược lại MEDIUM (chỉ đọc được response không xác thực). | HIGH/MEDIUM | A05:2021 | M |
| FR-CORS-04 | Nếu `Access-Control-Allow-Origin: *` không kèm credentials, PHẢI tạo finding `CORS-WILDCARD` (chấp nhận được với API công khai, không xác thực). | INFO | A05:2021 | S |

### 4.8 Nhóm kiểm tra lộ file/path nhạy cảm (`checks/exposure.py`)

| ID | Yêu cầu | Priority |
|---|---|---|
| FR-EXP-01 | Tool PHẢI duy trì danh sách path nhạy cảm kèm `Finding.id` và severity (bảng 4.8.1) trong file dữ liệu **`owasp_scanner/rules/sensitive_paths.json`**, được kiểm tra khi nạp (thiếu trường, severity lạ, id hoặc path trùng, path tuyệt đối → lỗi rõ ràng). Thêm path chỉ cần sửa file này, không sửa code. Trường `version` của file là `rules_version` trong báo cáo. | M |
| FR-EXP-02 | **Soft-404 theo vân tay nội dung (FR-DET-02).** Mỗi lần quét, tool PHẢI gửi 2 probe tới path ngẫu nhiên chắc chắn không tồn tại (một dạng file `owasp-scanner-probe-<hex>.txt`, một dạng thư mục `owasp-scanner-probe-<hex>/`; phần hex mới cho mỗi lần quét) và ghi lại các probe trả 200. Một response 200 của path nhạy cảm hoặc thư mục bị coi là "không tồn tại" nếu (a) nó đi qua redirect và dừng ở **cùng URL cuối** với một probe cũng bị redirect (ví dụ mọi path về `/login`), hoặc (b) nội dung giống một probe từ **90%** trở lên (so 4 KiB đầu, sau khi bỏ chuỗi path mà trang in lại và gộp khoảng trắng). Một profile dùng chung cho check path nhạy cảm và directory listing. | M |
| FR-EXP-03 | Tool KHÔNG được tạo finding lộ file chỉ dựa trên mã 200. Trang chung trả 200 cho mọi path (SPA, trang lỗi tuỳ biến, trang chặn của WAF) không tạo finding: phần lớn vì không khớp chữ ký nội dung (FR-EXP-04), phần còn lại vì bị nhận là soft-404 (FR-EXP-02) dù vô tình khớp chữ ký. Một file thật bị lộ trên site như vậy vẫn được phát hiện. | M |
| FR-EXP-04 | Nếu path trả HTTP 200 **và nội dung (tối đa 8 KiB đầu, NFR-PERF-04) khớp chữ ký của path** (cột "Chữ ký nội dung" bảng 4.8.1, khai báo trong `rules/sensitive_paths.json`), PHẢI tạo finding với id và severity đã khai báo, category `A01:2021 - Broken Access Control`. Chữ ký là regex trên text đã giải mã và/hoặc magic bytes ở đầu file; body là trang HTML (`<!doctype html`/`<html`) thì không khớp, trừ path được đánh dấu `allow_html`. Evidence gồm mã trạng thái, URL và mô tả chữ ký đã khớp; **KHÔNG BAO GIỜ chứa nội dung file** (có thể là secret thật). | M |
| FR-EXP-05 | Các request kiểm tra path PHẢI chạy song song có giới hạn (thread pool), số luồng tối đa lấy từ `--workers` (mặc định 5). | M |
| FR-EXP-06 | `.well-known/security.txt` được xử lý riêng: nếu trả 200 và nội dung có trường `Contact:` (RFC 9116), tạo finding INFO `EXPOSURE-SECURITY-TXT` mang tính tích cực, không phải lỗ hổng. | S |
| FR-EXP-07 | Tool PHẢI kiểm tra directory listing tại `images/`, `uploads/`, `backup/`, `files/`, `assets/`, `static/`. Nếu response 200, không bị nhận là soft-404 (FR-EXP-02), và 2000 ký tự đầu chứa `Index of /`, `<title>Index of` hoặc `Directory Listing For`, PHẢI tạo finding `EXPOSURE-DIR-LISTING` mức MEDIUM, category A05:2021. | M |
| FR-EXP-08a | Tool PHẢI tải `robots.txt` (nếu có), trích các dòng `Disallow:`, lọc path chứa từ khoá nhạy cảm (`admin`, `backup`, `config`, `internal`, `private`, `secret`, `staging`, `test`; không phân biệt hoa/thường). Có ít nhất 1 path khớp → finding `EXPOSURE-ROBOTS-HINTS` mức LOW, A01:2021, evidence là tối đa 10 path đầu. | S |
| FR-EXP-08b | Tool PHẢI tải `sitemap.xml` (nếu có), trích nội dung thẻ `<loc>…</loc>`, lấy phần path của từng URL và so với cùng danh sách từ khoá. Có ít nhất 1 URL khớp → finding `EXPOSURE-SITEMAP-HINTS` mức LOW, A01:2021, evidence là tối đa 10 URL đầu. | S |

**Bảng 4.8.1 — Danh sách path nhạy cảm mặc định.** `Finding.id` khai báo tường minh cho từng path, không suy ra từ chuỗi path. Regex đầy đủ nằm trong `owasp_scanner/rules/sensitive_paths.json`.

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
| FR-REPORT-06 | Với `--sarif PATH`, tool PHẢI ghi báo cáo **SARIF 2.1.0** dựng từ cùng dict của `output.build_report()` (secret đã che). Mỗi `Finding.id` là một rule (`shortDescription` = title, `helpUri` = reference đầu tiên, `help` = recommendation, `properties.tags` gồm OWASP và CWE, `properties.precision` = confidence, `properties.security-severity` theo severity cao nhất của id đó: CRITICAL 9.5, HIGH 8.0, MEDIUM 5.5, LOW 3.0, INFO 0.0); mỗi finding là một result (`level`: CRITICAL/HIGH → `error`, MEDIUM → `warning`, LOW/INFO → `note`; `locations` = URL của finding; `partialFingerprints.owaspScannerFingerprint/v1` = `fingerprint`). `errors` thành `toolExecutionNotifications`; `executionSuccessful` là `false` khi quét không hoàn tất. Kết quả trỏ tới URL, không phải file trong repo, nên công cụ code scanning (ví dụ GitHub) sẽ không gắn được vào dòng code. | S |
| FR-REPORT-07 | Với `--html PATH`, tool PHẢI ghi báo cáo HTML bằng **cùng hàm `render_html()`** mà Web UI dùng cho "Download Test result" (FR-UI-06, FR-UI-07), từ cùng dict của `output.build_report()`: cho cùng một báo cáo, file HTML của CLI và của Web UI giống hệt nhau. Có `--show-secrets` thì báo cáo hiện băng cảnh báo (NFR-SEC-04). | S |

### 4.10 Nhóm Web UI cục bộ (`web.py`, `static/`, `html_report.py`)

Tiền tố `FR-UI` mô tả hành vi đã có. Các cải tiến dự kiến nằm trong backlog với tiền tố `FR-WEB` (E12a).

| ID | Yêu cầu | Priority |
|---|---|---|
| FR-UI-01 | Server PHẢI mặc định bind `127.0.0.1`. Nếu bind địa chỉ không phải loopback, PHẢI in cảnh báo rằng bất kỳ ai truy cập được cổng đều có thể ra lệnh quét. | M |
| FR-UI-02 | `POST /api/scan` PHẢI từ chối (HTTP 400, không quét) nếu trường `authorized` không phải đúng giá trị JSON `true`. UI PHẢI có ô xác nhận quyền quét và không gửi request khi chưa tick. | M |
| FR-UI-03 | Khi server bind loopback, mọi request có `Host` không phải loopback PHẢI bị từ chối (403) để chống DNS rebinding. `POST /api/scan` có `Origin` khác `Host` PHẢI bị từ chối (403). | M |
| FR-UI-04 | `POST /api/scan` PHẢI yêu cầu `Content-Type: application/json` (415 nếu khác), body tối đa 4096 byte (413), là JSON object hợp lệ (400), `target` là chuỗi không rỗng và sau chuẩn hoá có scheme `http`/`https` và hostname (400). | M |
| FR-UI-05 | Mỗi lúc chỉ chạy một lần quét; request quét thứ hai trong lúc đang quét PHẢI nhận 429. Nếu lần quét gặp lỗi nội bộ (exception), server PHẢI trả 500 với `{"error": "The scan failed with an internal error; see the server console for details."}`, ghi một dòng đã che secret ra stderr, và giải phóng lượt quét (từ v1.6.0; trước đó kết nối bị đóng không có response). | M |
| FR-UI-06 | Sau mỗi lần quét, server PHẢI lưu báo cáo trong bộ nhớ dưới một id ngẫu nhiên không đoán được (`secrets.token_urlsafe(16)`), giữ tối đa 20 báo cáo gần nhất. `GET /api/report/<id>.html` PHẢI trả báo cáo HTML dạng tệp đính kèm (`Content-Disposition: attachment`, tên `owasp-scan-<host>-<thời điểm>.html`); id không tồn tại → 404. | M |
| FR-UI-07 | Báo cáo HTML (`render_html()`) PHẢI là một tệp độc lập: CSS nhúng, không có script, không tải tài nguyên ngoài; mọi giá trị lấy từ target PHẢI được HTML-escape. Nội dung gồm thời gian, check đã chạy, trạng thái gate, bảng tổng hợp, lỗi non-fatal, danh sách finding, và phần giới hạn phạm vi. | M |
| FR-UI-08 | Trang UI PHẢI gửi các header: `Content-Security-Policy: default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`. Dữ liệu quét trên trang chỉ được hiển thị bằng `textContent` (không `innerHTML`). | M |
| FR-UI-09 | Trường `gate_failed` PHẢI bằng `gate.failed` của báo cáo, tính bằng cùng hàm `output.gate_failed()` và cùng ngưỡng `--fail-on` (khai báo khi khởi động server) như CLI. Ngoài các trường của mục 6.3 (`web.WEB_ONLY_FIELDS`) và các trường thay đổi theo lần quét (`scan_id`, thời gian), JSON của Web UI PHẢI giống hệt JSON `--json` của CLI cho cùng target và cùng ngưỡng. Lỗi của cả hai endpoint trả `application/json` dạng `{"error": "..."}`. Câu gate hiển thị trên UI (`gate_message`) và trong báo cáo HTML PHẢI do cùng hàm `output.gate_message()` tạo ra. | M |

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

---

## 5. Yêu cầu phi chức năng (Non-Functional Requirements)

| ID | Nhóm | Yêu cầu |
|---|---|---|
| NFR-SEC-01 | Bảo mật/đạo đức | Tool TUYỆT ĐỐI KHÔNG gửi payload khai thác (SQLi, XSS thật, command injection, path traversal thật, brute-force). Mọi request tới target là GET tiêu chuẩn, không sửa dữ liệu phía target. |
| NFR-SEC-02 | Bảo mật/đạo đức | Bước xác nhận quyền quét không tắt được bằng cấu hình mặc định: CLI chỉ bỏ qua bằng cờ `--yes`; Web UI luôn yêu cầu `authorized: true`. |
| NFR-SEC-03 | Bảo mật/đạo đức | Mọi request PHẢI gửi `User-Agent` nhận diện rõ là scanner kèm phiên bản thật: `TECHVIFY-OWASP-Scanner/<version> (+non-intrusive security configuration check)`, không giả mạo trình duyệt. *(Trước v1.3.0 chuỗi là `TECHVIFY-OWASP-Scanner/1.0 (+passive security header/config check)`; bên nào lọc log/WAF theo chuỗi cũ cần cập nhật.)* |
| NFR-SEC-04 | Bảo mật | Mọi đầu ra (console, `--json`, response Web UI, báo cáo HTML) PHẢI qua `output.build_report()`, nơi che (1) cặp `tên=giá trị` của cookie do check khai báo chính xác, và (2) giá trị của mọi tham số URL có tên chứa `token`, `key`, `session`, `sess`, `password`, `passwd`, `pwd`, `secret`, `sig`, `auth`, `jwt`, và (3) thông tin đăng nhập trong URL (`scheme://user:password@host`: che riêng user và password, từ v1.6.0) — trong `target`, `final_url`, `redirect_chain`, `errors`, và `title`/`description`/`evidence`/`url`/`instance_key` của finding. Dòng `Scanning <target>` của CLI cũng được che. Cờ `--show-secrets` **chỉ có ở CLI**: in cảnh báo ra stderr, JSON có `secrets_redacted: false`, báo cáo HTML có băng cảnh báo. Web UI luôn che, bỏ qua mọi trường yêu cầu tắt che. |
| NFR-SEC-05 | Bảo mật/đạo đức | **Phạm vi khi theo redirect (D4):** mọi request của một lần quét chỉ được theo redirect tới cùng hostname với target, hoặc hostname chỉ khác một tiền tố `www.` (không phân biệt hoa thường; được đổi scheme và cổng; target là IP thì phải khớp chính xác). Redirect ra ngoài phạm vi thì **không gửi request tới host đó**: chuỗi redirect dừng ở response 3xx cuối cùng trong phạm vi, các check chạy tiếp trên response đó, và `errors` có đúng **một dòng** cho mỗi host bị chặn. Tối đa 10 bước redirect cho mỗi request. |
| NFR-PERF-01 | Hiệu năng | Mỗi request PHẢI có timeout cấu hình được (mặc định 10 giây). |
| NFR-PERF-02 | Hiệu năng | Số luồng song song khi kiểm tra path nhạy cảm PHẢI giới hạn qua `--workers` (mặc định 5). |
| NFR-PERF-03 | Hiệu năng | Không retry khi target trả 4xx/5xx; chỉ retry ở tầng kết nối/đọc, tối đa 1 lần. |
| NFR-PERF-04 | Hiệu năng | Mọi request kiểm tra path nhạy cảm, probe soft-404 và directory listing PHẢI đọc **tối đa 8 KiB đầu** của body (`http_utils.MAX_BODY_BYTES`) rồi đóng kết nối, để một file dump hay backup lớn bị lộ không bị tải về (giảm tải cho target và không kéo dữ liệu của target về máy quét). `robots.txt` và `sitemap.xml` được đọc tối đa **512 KiB** (`http_utils.HINT_FILE_MAX_BYTES`, từ v1.6.0; trước đó đọc toàn bộ); mục nằm sau giới hạn này không được xét. Charset không xác định trong `Content-Type` được giải mã như UTF-8 thay vì làm dừng check. |
| NFR-REL-01 | Độ tin cậy | Một check thất bại không được làm crash cả lần quét (FR-REPORT-05). |
| NFR-REL-02 | Độ tin cậy | Tool PHẢI xử lý được target không phản hồi ở baseline mà không ném exception ra ngoài. |
| NFR-USA-01 | Khả dụng | Output CLI có phân cách rõ ràng, bảng tổng hợp theo severity ở đầu, rồi mới tới chi tiết. |
| NFR-USA-02 | Khả dụng | Mọi finding PHẢI có khuyến nghị khắc phục khi khả thi. |
| NFR-USA-03 | Khả dụng | Ngôn ngữ mặc định của mọi text sản phẩm (UI, báo cáo HTML, output CLI, thông báo lỗi API, nội dung finding) là **tiếng Anh**. Tài liệu dự án (SRS, backlog, README) có thể viết tiếng Việt. |
| NFR-PORT-01 | Khả chuyển | Tool PHẢI chạy trên Python ≥ 3.12, Linux/macOS/Windows. *Nâng từ ≥ 3.9 lên ≥ 3.12 theo quyết định của chủ sản phẩm ngày 2026-09-30 (3.9 đã hết hỗ trợ, 3.10 hết hỗ trợ 2026-10-31; 3.12 là bản có sẵn trên Ubuntu 24.04). Môi trường dev dùng 3.14. CI của repo (FR-QA-07) chạy trên Ubuntu 24.04 (3.12, 3.14) và Windows (3.14); macOS chưa có trong CI.* |
| NFR-MAINT-01 | Bảo trì | Mỗi nhóm check nằm trong module riêng, unit test được không cần mạng thật (dùng mock server cục bộ hoặc dữ liệu có sẵn). |
| NFR-MAINT-02 | Bảo trì | Danh sách header bắt buộc (4.3) và path nhạy cảm (4.8.1) là cấu trúc dữ liệu khai báo ở đầu file. |
| NFR-COMP-01 | Tuân thủ | README, UI và báo cáo PHẢI nêu rõ giới hạn phạm vi (không phải DAST toàn diện, không thay thế pentest). Không dùng ngôn ngữ đảm bảo tuyệt đối ("website an toàn", "phát hiện 100%"). |

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
    scanner_version: str     # owasp_scanner.__version__
    rules_version: str       # "sensitive_paths=<version>;tls_interceptors=<version>" của các file rules
```

**Quy tắc bắt buộc:**

- `Finding.id` là mã ổn định theo **loại** lỗi, không đổi giữa các lần chạy. Hai **vị trí** khác nhau của cùng một loại lỗi (ví dụ hai cookie cùng thiếu cờ) có cùng `id` nhưng khác `instance_key` và `fingerprint` (FR-MODEL-01).
- `fingerprint` = 32 ký tự hex đầu của SHA-256(`id|instance_key|origin`), với `origin` = `scheme://host:port` của target (chữ thường, cổng mặc định 80/443). Không phụ thuộc path, thời gian quét hay giá trị bị che, nên cùng một lỗi ở cùng một chỗ luôn cho cùng fingerprint.
- `cwe`, `confidence`, `references` lấy từ bảng khai báo `catalog.FINDING_CATALOG` (mỗi finding id một dòng). Mọi id tool sinh ra PHẢI có trong bảng. `cwe` để trống cho 3 finding thông tin không phải điểm yếu: `TLS-CONN-FAILED`, `TLS-CERT-PARSE-FAILED`, `EXPOSURE-SECURITY-TXT`. `COOKIE-FLAGS-MISSING` lấy CWE theo thuộc tính quan trọng nhất đang thiếu: Secure → CWE-614, HttpOnly → CWE-1004, SameSite → CWE-1275.
- `confidence` (FR-DET-03): `high` = quan sát trực tiếp từ response/bắt tay (header, cookie, TLS, CORS, directory listing có dấu hiệu nội dung) hoặc file nhạy cảm có nội dung khớp chữ ký (FR-EXP-04); `medium` = quan sát gián tiếp (hiện chưa có finding nào); `low` = chỉ là gợi ý (robots.txt, sitemap.xml), hoặc finding TLS khi bắt tay có vẻ bị chặn giữa đường (FR-TLS-11).
- Khi xuất ra (CLI/JSON/HTML), `findings` được sắp theo `severity.rank` tăng dần (CRITICAL trước).

### 6.2 JSON Schema (mô tả phi hình thức)

Định dạng chính thức là JSON Schema draft 2020-12 tại **`docs/report.schema.json`** (bắt buộc mọi khoá, không cho khoá lạ). `schema_version` hiện là **`1.4`**. Lịch sử: bản `1.0` là định dạng chưa đánh version của scanner v1.1.0; `1.1` (scanner 1.2.0) **thêm** `schema_version`, `scanner_version`, `rules_version`, `scan_id` (FR-MODEL-02), `secrets_redacted` (FR-AUTH-02) và 5 trường mới của finding (FR-MODEL-01); `1.2` (scanner 1.3.0) **thêm** `final_url` và `redirect_chain` (FR-FIX-10) và tên check `hsts-start-host`; `1.3` (scanner 1.5.0) **thêm** `gate` = `{fail_on, failed, incomplete}` (FR-CI-01); `1.4` (scanner 1.7.0) **thêm** `scan_groups` và `check` của mỗi finding (FR-GRP-03). Không phiên bản nào bỏ hay đổi nghĩa trường. Quy tắc: thêm trường → tăng số phụ; bỏ/đổi tên/đổi nghĩa → tăng số chính; mỗi lần đổi PHẢI ghi changelog.

```json
{
  "schema_version": "1.4",
  "scanner_version": "1.7.0",
  "rules_version": "1.1.0",
  "scan_id": "6f1c2d3e-4b5a-4c6d-8e7f-0a1b2c3d4e5f",
  "secrets_redacted": true,
  "gate": { "fail_on": "high", "failed": true, "incomplete": false },
  "target": "https://example.com/",
  "final_url": "https://www.example.com/",
  "redirect_chain": [{ "url": "https://example.com/", "status": 301 }],
  "started_at": "2026-09-22T08:26:08.822920Z",
  "finished_at": "2026-09-22T08:26:09.273000Z",
  "scan_groups": ["headers", "cookies", "tls", "https-redirect", "cors", "exposed-files", "directory-listing", "robots-sitemap"],
  "checks_run": ["security-headers", "cookies", "tls", "http-to-https-redirect", "cors", "sensitive-paths", "directory-listing", "robots-sitemap"],
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
      "instance_key": ".env",
      "fingerprint": "<32 ký tự hex>",
      "check": "sensitive-paths"
    }
  ],
  "errors": []
}
```

AT-12 kiểm tra đúng tập khoá ở cấp gốc, trong `summary` và trong mỗi finding; AT-30 kiểm tra output khớp `docs/report.schema.json`.

### 6.3 Trường bổ sung của Web UI

`POST /api/scan` trả JSON mục 6.2 cộng thêm các trường sau. Nút **Download JSON** loại bỏ chúng để file tải về giống hệt `--json` của CLI.

| Trường | Kiểu | Ý nghĩa |
|---|---|---|
| `gate_failed` | bool | `true` nếu có ít nhất 1 finding CRITICAL/HIGH (FR-UI-09) |
| `gate_status` | string | `fail`, `warn` (quét không hoàn tất) hoặc `pass`, từ `output.gate_message()` (từ v1.6.0) |
| `gate_message` | string | Câu mô tả gate và exit code của CLI; **cùng câu** với báo cáo HTML (từ v1.6.0) |
| `report_id` | string | id ngẫu nhiên của báo cáo lưu trong bộ nhớ (FR-UI-06) |
| `report_url` | string | `/api/report/<report_id>.html` |

---

## 7. Giao diện dòng lệnh

### 7.1 Cú pháp

```
python -m owasp_scanner <target> [--json PATH] [--sarif PATH] [--html PATH] [--timeout N] [--workers N] [--no-color] [--yes] [--fail-on LEVEL] [--ca-bundle PATH] [--show-secrets]
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
| `--checks GROUPS` | Không | tất cả | Danh sách id nhóm cách nhau bằng dấu phẩy (mục 4.11), ví dụ `headers,tls`. Id sai → exit code `2` kèm danh sách id hợp lệ (từ v1.7.0). |
| `--list-checks` | Không | — | In id, tên và mô tả của từng nhóm rồi thoát với code `0`; không cần target, không hỏi xác nhận (từ v1.7.0). |
| `--show-secrets` | Không | tắt | Không che giá trị cookie và tham số URL nhạy cảm (chỉ để debug cục bộ; NFR-SEC-04). |

### 7.3 Exit code

| Code | Ý nghĩa |
|---|---|
| `0` | Quét xong, không có finding nào bằng hoặc cao hơn ngưỡng `--fail-on`; hoặc `--fail-on none`. |
| `1` | Có ít nhất 1 finding bằng hoặc cao hơn ngưỡng `--fail-on` (mặc định CRITICAL/HIGH). |
| `2` | Người dùng không xác nhận quyền quét — không có request nào được gửi. Cũng là exit code của argparse khi tham số sai. |
| `3` | Quét không hoàn tất: không lấy được trang chủ (DNS, kết nối, TLS…) và không có finding nào vượt ngưỡng. Không dùng khi `--fail-on none`. |

### 7.4 Web UI cục bộ

```
python -m owasp_scanner.web [--host 127.0.0.1] [--port 8765] [--timeout N] [--workers N] [--fail-on LEVEL] [--ca-bundle PATH]
```

| Tham số | Mặc định | Mô tả |
|---|---|---|
| `--host` | `127.0.0.1` | Địa chỉ bind. Khác loopback thì in cảnh báo (FR-UI-01). |
| `--port` | `8765` | Cổng lắng nghe. |
| `--timeout` | `10` | Timeout mỗi request khi quét. |
| `--workers` | `5` | Số luồng cho check path nhạy cảm. |
| `--fail-on` | `high` | Ngưỡng cho `gate_failed` và trường `gate` (FR-CI-01). |
| `--ca-bundle` | env, rồi kho OS | Như `--ca-bundle` của CLI (FR-CLI-06). |

| Endpoint | Mô tả |
|---|---|
| `GET /`, `/app.js`, `/app.css` | Trang UI và file tĩnh. |
| `POST /api/scan` | Chạy quét đồng bộ, trả JSON mục 6.2 + 6.3. Mã lỗi: 400, 403, 413, 415, 429, 500 (FR-UI-02…05). |
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
| AT-30 | JSON có version và khớp schema | `--json`; quét lỗi kết nối; response của Web UI (bỏ 3 trường riêng) | Cả ba khớp `docs/report.schema.json`; `schema_version` = `1.1`; `scan_id` là UUID4 mới mỗi lần quét; schema từ chối khoá lạ | `test_cli_json_report_matches_schema`, `test_failed_scan_report_matches_schema`, `test_web_response_is_the_report_plus_web_fields`, `test_every_scan_gets_a_new_scan_id`, `test_schema_rejects_unknown_fields` |
| AT-31 | CLI và Web UI cho cùng kết quả | Quét cùng một mock qua CLI `--json` và qua `POST /api/scan` | JSON giống nhau (trừ trường riêng của UI và trường thay đổi theo lần quét); `gate_failed` khớp exit code; mã lỗi và Content-Type của 2 endpoint đúng hợp đồng | `test_cli_and_web_ui_produce_the_same_report`, `test_scan_errors_are_json_with_an_error_message`, `test_report_endpoint_contract` |
| AT-32 | Không lộ secret | Mock đặt cookie `session=<giá trị mẫu>`; target có `?access_token=<giá trị mẫu>` | Console, `--json`, JSON và báo cáo HTML của Web UI không chứa hai giá trị mẫu; `secrets_redacted: true`; `--show-secrets` in cảnh báo stderr và cho `secrets_redacted: false`; Web UI vẫn che khi client gửi `show_secrets`; cùng một cookie được đặt ở một bước redirect và ở response cuối (hai finding cùng fingerprint) thì cả hai giá trị đều được che; target dạng `http://user:password@host` không để lộ user/password trong console, JSON, SARIF, HTML hay tên file tải về | `test_cli_console_and_json_are_redacted`, `test_show_secrets_is_explicit_and_warns`, `test_web_ui_always_redacts_even_if_asked_not_to`, `test_html_report_warns_when_secrets_are_shown`, `test_errors_are_redacted`, `test_sensitive_url_parameters_are_masked`, `test_same_cookie_on_a_redirect_and_the_final_response_is_redacted_in_both`, `test_credentials_in_urls_are_masked`, `test_credentials_in_the_target_url_never_reach_the_reports` |
| AT-33 | Severity CORS theo D3 | Server trả 4 tổ hợp: `*` + credentials; phản xạ + credentials; phản xạ không credentials; `*` đơn lẻ | Lần lượt MEDIUM, HIGH, MEDIUM, INFO; mô tả mỗi finding giải thích lý do mức độ; mọi finding có khuyến nghị | `test_cors`, `test_cors_findings_explain_their_severity_and_how_to_fix` |
| AT-34 | Không theo redirect ra ngoài phạm vi | Target redirect trang chủ, hoặc mọi path, sang host khác (`localhost` so với `127.0.0.1`) | Host kia không nhận request nào; `errors` có đúng 1 dòng; quét vẫn chạy; redirect tới cùng host (khác path/cổng) vẫn được theo | `test_baseline_redirect_to_other_host_is_not_followed`, `test_path_redirects_to_other_host_are_blocked_and_reported_once`, `test_in_scope`, `test_in_scope_redirects_are_followed`, `test_redirect_to_another_port_on_the_same_host_is_followed` |
| AT-35 | Redirect check luôn chạy (FIX-09) | `http://` không redirect; `http://` → HTTPS cert tự ký/hết hạn/được tin; `https://` với probe redirect sang `https://` không tồn tại, sang HTTP cùng host, sang host lạ | Lần lượt: `TLS-NO-HTTPS-REDIRECT`; `TLS-CERT-NOT-TRUSTED`/`TLS-CERT-EXPIRED` trên đúng cổng HTTPS và không có finding redirect; TLS chạy trên URL cuối; không finding; có finding; không finding + 1 lỗi phạm vi | `test_http_target_without_redirect_is_reported`, `test_http_target_redirected_to_https_with_bad_cert_reports_the_cert_not_the_redirect`, `test_http_target_redirected_to_expired_https_reports_expiry`, `test_http_target_redirected_to_trusted_https_scans_the_https_page` (skip khi TLS bị chặn), `test_probe_counts_a_redirect_to_https_without_loading_it`, `test_probe_follows_http_hops_in_scope`, `test_probe_stops_at_out_of_scope_redirect` |
| AT-36 | Header xét trên response cuối (FIX-10) | Redirect `/` → `/home`; không redirect; baseline lỗi; `http://` → HTTPS được tin; đổi host với/không có HSTS ở host gốc | `final_url`/`redirect_chain` đúng và được che secret; không đòi HSTS khi response cuối là HTTP, có đòi khi là HTTPS; `HDR-HSTS-MISSING-ON-START-HOST` mức LOW khi host gốc thiếu HSTS; không áp dụng khi cùng host hoặc response cuối là HTTP; host gốc không kết nối được → lỗi, không finding | `test_report_records_final_url_and_redirect_chain`, `test_no_redirect_gives_empty_chain`, `test_failed_baseline_has_no_final_url`, `test_final_url_and_chain_are_redacted`, `test_hsts_is_not_required_when_the_final_response_is_http`, `test_http_target_redirected_to_https_is_held_to_hsts` (skip khi TLS bị chặn), `test_start_host_without_hsts_is_reported`, `test_start_host_with_hsts_is_fine`, `test_start_host_check_does_not_apply`, `test_unreachable_start_host_is_an_error_not_a_finding` |
| AT-37 | Text sản phẩm không còn "passive" (FIX-11) | Banner CLI, `--help` của CLI và Web UI, file tĩnh của UI, báo cáo HTML, User-Agent | Không chứa "passive"; User-Agent đúng mẫu NFR-SEC-03 với `__version__`; footer UI trỏ tới `docs/SRS-owasp-scanner.md` | `test_product_text_does_not_say_passive`, `test_cli_help_does_not_say_passive`, `test_user_agent_identifies_the_scanner_and_its_version`, `test_ui_footer_points_at_the_current_srs` |
| AT-38 | Rules dạng dữ liệu và đọc có giới hạn | Bảng path từ `rules/sensitive_paths.json`; file rules sai định dạng; thêm path chỉ bằng file rules; server trả body 20 MB cho mọi path | Bảng khớp 4.8.1; `rules_version` = version của file; lỗi nạp nêu rõ nguyên nhân; path mới được quét; mỗi response chỉ đọc ≤ 8 KiB, check xong trong vài giây; robots.txt/sitemap.xml chỉ đọc ≤ 512 KiB; charset lạ không làm dừng check directory listing | `test_sensitive_paths_come_from_the_rules_file`, `test_report_carries_the_rules_version`, `test_invalid_rules_are_rejected_with_a_clear_message`, `test_a_new_path_needs_only_a_rules_change`, `test_get_limited_reads_at_most_the_cap`, `test_sensitive_path_check_does_not_download_huge_files`, `test_robots_and_sitemap_are_read_up_to_their_cap`, `test_unknown_charset_does_not_stop_the_directory_listing_check` |
| AT-39 | Kiểm tra nội dung file nhạy cảm (FR-DET-01) | Mỗi path: nội dung thật; trang HTML chung, rỗng, text, JSON; site trả 200 cho mọi path có và không có `.env` thật; path 200 sai nội dung | Nội dung thật khớp chữ ký; response chung không khớp; site catch-all không có finding nhưng `.env` thật vẫn được báo; 200 sai nội dung không báo; evidence không chứa nội dung file; rules thiếu/sai chữ ký bị từ chối | `test_signature_matches_real_content`, `test_signature_rejects_generic_responses`, `test_catch_all_html_site_has_no_exposure_findings`, `test_real_file_on_a_catch_all_site_is_still_found`, `test_200_with_the_wrong_content_is_not_reported`, `test_evidence_never_contains_the_file_content`, `test_invalid_signatures_are_rejected` |
| AT-40 | Soft-404 theo vân tay (FR-DET-02) | Site trả cùng một trang (có `Contact:` và `Index of /`) cho mọi path; trang in lại path được hỏi; mọi path redirect về `/login`; `.env` và `/images/` thật trên các site đó; site 404 bình thường | Không có finding từ trang chung; file và listing thật vẫn được báo; site 404 có profile rỗng; path probe ngẫu nhiên mỗi lần; `run_scan` chỉ gửi 2 probe | `test_catch_all_page_that_happens_to_match_a_signature_is_ignored`, `test_catch_all_page_echoing_the_path_is_recognised`, `test_redirect_to_login_is_recognised`, `test_real_files_are_still_found_on_soft_404_sites`, `test_real_file_behind_login_redirects_is_still_found`, `test_normal_404_site_has_an_empty_profile`, `test_probe_paths_are_random_per_scan`, `test_run_scan_builds_the_profile_once` |
| AT-41 | Confidence và TLS bị chặn (FR-DET-03, FR-DET-16) | Finding lộ file có nội dung khớp; robots/sitemap; chứng chỉ có issuer "Avast Web/Mail Shield Root"/"Zscaler …"; chứng chỉ thường; issuer của CA công khai | Lộ file `high`, gợi ý `low`; issuer phần mềm chặn → 1 cảnh báo trong `errors` và finding TLS `low`, kể cả qua `run_scan`; chứng chỉ thường không cảnh báo; tên CA công khai (GlobalSign, Let's Encrypt, DigiCert, Sectigo) không bị nhận nhầm | `test_content_verified_exposure_findings_are_high_confidence`, `test_hint_only_findings_stay_low_confidence`, `test_scanned_exposure_finding_is_high_confidence`, `test_interceptor_issuers_are_recognised`, `test_intercepted_tls_is_flagged_and_findings_are_low_confidence`, `test_run_scan_reports_the_interception_warning`, `test_normal_certificate_gives_no_warning` |
| AT-42 | Một kho chứng chỉ (FR-CI-10) | Mặc định; `--ca-bundle` với CA tự tạo; biến môi trường; một request HTTPS qua session; file bundle thiếu/sai | Mặc định là kho OS (khác `certifi`); bundle thay kho mặc định; biến môi trường được dùng; `certifi` không bị nạp thêm vào context dùng chung; không có bundle → baseline lỗi + `TLS-CERT-NOT-TRUSTED`; có bundle → check HTTP chạy đủ, không `NOT-TRUSTED`; bundle hỏng → exit `2` | `test_default_trust_is_the_os_store_not_certifi`, `test_ca_bundle_replaces_the_default_store`, `test_env_variables_are_honoured`, `test_requests_never_adds_certifi_to_the_shared_context`, `test_without_ca_bundle_a_private_ca_is_not_trusted`, `test_ca_bundle_trusts_a_private_ca_for_http_and_tls`, `test_cli_ca_bundle_option`, `test_cli_rejects_a_missing_or_invalid_bundle` |
| AT-43 | Ngưỡng `--fail-on` và exit code `3` (FR-CI-01) | Ma trận ngưỡng × severity; target chỉ có MEDIUM với từng ngưỡng; target có CRITICAL với `none`; target không kết nối được (mặc định và `none`); chứng chỉ hết hạn; Web UI khởi động với `--fail-on medium`; tham số sai | Đúng bảng ngưỡng; exit `1`/`0` theo ngưỡng; `none` → `0`; không kết nối → `3`, với `none` → `0`; chứng chỉ hết hạn → `1` (ưu tiên hơn `3`); JSON `gate` đúng; Web UI `gate_failed` theo ngưỡng của server; báo cáo HTML nêu ngưỡng; tham số sai bị từ chối | `test_threshold`, `test_exit_code_follows_the_threshold`, `test_critical_target_with_fail_on_none_passes`, `test_unreachable_target_exits_3`, `test_unreachable_target_with_fail_on_none_exits_0`, `test_findings_over_the_threshold_win_over_incomplete`, `test_json_records_the_gate`, `test_web_ui_uses_the_server_threshold`, `test_html_report_names_the_threshold`, `test_cli_rejects_an_unknown_threshold` |
| AT-44 | Xuất SARIF (FR-RPT-02) | Quét mock; từng severity; cùng id với 2 severity; quét không kết nối được; target có secret; `--sarif PATH` | `version` 2.1.0 và `$schema`; mỗi result trỏ đúng rule và có `partialFingerprints` = fingerprint; ánh xạ `level`/`security-severity` đúng; rule lấy severity cao nhất; lỗi thành notification và `executionSuccessful: false`; không lộ secret; file được ghi; output ổn định | `test_top_level_structure`, `test_every_result_points_at_its_rule`, `test_severity_mapping`, `test_rule_severity_is_the_highest_seen_for_that_id`, `test_errors_become_notifications_and_incomplete_scans_are_unsuccessful`, `test_sarif_is_built_from_the_redacted_report`, `test_cli_writes_the_sarif_file`, `test_output_is_deterministic` |
| AT-45 | `--html` dùng chung bộ render (FR-RPT-09) | `--json` + `--html` cùng lần quét; báo cáo Web UI tải về; target có secret; `--show-secrets`; `--json` + `--html` + `--sarif` cùng lúc | HTML của CLI = `render_html(JSON)`; HTML của Web UI = `render_html` của report Web UI trả về; không lộ secret, không có `<script`; có băng cảnh báo khi `--show-secrets`; 3 định dạng thống nhất số finding và gate | `test_cli_html_is_render_html_of_the_json_report`, `test_web_download_uses_the_same_renderer`, `test_cli_html_is_redacted_and_escaped`, `test_cli_html_with_show_secrets_carries_the_warning`, `test_all_outputs_in_one_run_agree` |
| AT-46 | Template CI (FR-CI-03) | 4 file trong `examples/ci/` | Đủ 4 template; lệnh quét chỉ dùng tham số có trong `--help` (gồm `--yes`, `--fail-on`, `--json`, `--sarif`, `--html`); có lưu ý quyền quét và exit code `3`; cài đúng tag của bản phát hành; YAML không có tab. *Không chạy trên CI thật.* | `test_all_four_templates_exist`, `test_template_uses_only_real_cli_options`, `test_template_warns_about_authorization_and_exit_codes`, `test_template_installs_the_current_release`, `test_yaml_templates_have_no_tabs` |
| AT-47 | CI của repo (FR-QA-07) | `.github/workflows/ci.yml`, `.gitleaks.toml` | Có 5 job `lint`/`test`/`min-deps`/`audit`/`secrets` (`min-deps` từ v1.6.0: test trên Python thấp nhất với đúng phiên bản dependency thấp nhất khai báo trong `pyproject.toml`); chạy `ruff check`, `ruff format --check`, `pytest`; ma trận có Python thấp nhất theo `requires-python` và một bản mới hơn, có Windows; `pip-audit`; gitleaks quét toàn bộ lịch sử, kiểm checksum; chỉ quyền `contents: read`, không dùng secret; allowlist gitleaks chỉ gồm giá trị giả có trong `tests/test_redact.py`. *Kiểm tra nội dung file; workflow chạy thật trên GitHub sau khi push.* | `test_workflow_has_the_five_jobs`, `test_min_deps_job_pins_the_floors_declared_in_pyproject`, `test_workflow_runs_lint_and_offline_tests`, `test_workflow_tests_oldest_supported_and_latest_python`, `test_workflow_audits_dependencies_and_scans_for_secrets`, `test_workflow_is_read_only_and_uses_no_repository_secrets`, `test_workflow_has_no_tabs`, `test_gitleaks_allowlist_only_covers_the_fake_redaction_values` |
| AT-48 | Golden file báo cáo (FR-QA-02) | Một lần chạy CLI trên mock server với `--json`, `--sarif`, `--html` | Sau khi thay scan id, thời gian, cổng, version và fingerprint bằng placeholder, cả 3 báo cáo trùng khớp `tests/golden/`; không còn timestamp hay cổng thật; không báo cáo nào chứa giá trị cookie và `.env` giả của mock server | `test_report_matches_the_golden_file`, `test_report_has_no_run_specific_values_left`, `test_report_does_not_leak_the_mock_secrets` |
| AT-49 | Mọi finding ID đều được test tạo ra (FR-QA-01) | 17 rule path nhạy cảm qua HTTP; header `X-AspNetMvc-Version`; chứng chỉ không parse được | Mỗi rule cho đúng 1 finding với id, severity, URL của rule; `HDR-INFO-X-ASPNETMVC-VERSION`; `TLS-CERT-PARSE-FAILED` (INFO) và trust check vẫn chạy. Đo ngày 2026-09-30: cả 47 id trong catalog đều được suite tạo ra (trước đó 33/47). | `test_every_rule_is_reported_end_to_end`, `test_headers_info_leak_one_finding_per_header`, `test_tls_unparsable_certificate_is_reported_and_trust_is_still_checked` |
| AT-50 | Target IPv6 | Host `::1` cho TLS check và redirect check | URL trong finding và request probe có dấu ngoặc (`https://[::1]:<cổng>`, `http://[::1]/`); `instance_key` giữ nguyên dạng `host:port` để fingerprint không đổi | `test_ipv6_hosts_are_bracketed_in_urls` |
| AT-51 | TLS cũ trên server thật (FR-TLS-01, FR-TLS-03) | Server local chỉ cho TLS 1.0, rồi chỉ TLS 1.1; server thường | Server cũ → đúng 1 `TLS-WEAK-PROTOCOL` (HIGH) ghi đúng phiên bản, không có `TLS-CONN-FAILED`; server thường vẫn thương lượng TLS 1.2/1.3 với cipher không yếu. Test tự skip nếu chính OpenSSL của máy chạy test không bắt tay được TLS 1.0/1.1 | `test_tls_weak_protocol_is_detected_on_a_real_legacy_server`, `test_tls_modern_server_still_negotiates_a_modern_protocol` |
| AT-52 | Chọn nhóm kiểm thử (FR-GRP-01…03) | Bảng nhóm; quét mock mặc định; chỉ `headers`+`cookies`; chỉ `directory-listing`; chỉ `cookies`; lựa chọn rỗng/id lạ/trùng/hoa; target không kết nối được; chỉ `https-redirect` trên target http | Mỗi check thuộc đúng 1 nhóm, id nhóm cố định; mặc định `scan_groups` = cả 8 nhóm và mọi finding có `check`; chọn `headers`+`cookies` thì target chỉ nhận GET `/`; `directory-listing` vẫn gửi probe soft-404 nhưng không gửi path nhạy cảm/robots; gate chỉ tính nhóm đã chạy; lựa chọn sai → `ValueError`; trùng/hoa được chuẩn hoá | `test_every_check_belongs_to_exactly_one_group`, `test_group_ids_are_stable`, `test_default_scan_runs_every_group_and_tags_each_finding`, `test_only_the_selected_groups_run_and_send_requests`, `test_selected_groups_are_reported_in_table_order`, `test_directory_listing_alone_still_uses_the_soft404_probes`, `test_gate_counts_only_the_selected_groups`, `test_invalid_group_selection_is_rejected`, `test_group_selection_ignores_duplicates_and_case`, `test_unreachable_target_still_records_the_selection`, `test_https_redirect_group_alone_on_an_http_target` |
| AT-53 | CLI chọn nhóm (FR-GRP-01, mục 7) | `--list-checks`; `--checks cookies,HEADERS`; quét đủ nhóm; `--checks tls,bogus`; thiếu target | `--list-checks` in đủ 8 nhóm, exit `0`, không hỏi xác nhận; `--checks` chỉ chạy nhóm đã chọn, console in `Check groups:` và `Not selected (not tested):`; quét đủ không in dòng `Not selected`; id sai hoặc thiếu target → exit `2` | `test_list_checks_prints_every_group_without_a_target`, `test_checks_option_selects_groups`, `test_console_does_not_list_unselected_groups_for_a_full_scan`, `test_bad_check_selection_or_missing_target_exits_2` |

---

## 10. Rủi ro và hạn chế đã biết

- **Không phải DAST toàn diện:** không phát hiện injection thật, broken authentication ở tầng logic, IDOR, SSRF, lỗi business logic.
- **Chỉ quét trang chủ** cho phần lớn check; không crawl, có thể bỏ sót cấu hình khác nhau giữa các route.
- **False positive:** robots.txt/sitemap.xml (path "nghe nhạy cảm" chưa chắc tồn tại hay lộ). Path nhạy cảm đã kiểm tra nội dung (FR-EXP-04), nhưng chữ ký là heuristic: một file khác vô tình khớp mẫu (ví dụ file text bắt đầu bằng số cho `.svn/entries`) vẫn có thể bị báo, và một file thật có định dạng lạ có thể bị bỏ sót.
- **False negative:** target dùng CDN/WAF có thể chặn hoặc trả response khác cho User-Agent của scanner. TLS chỉ xét giao thức/cipher **được thương lượng**, không dò các phiên bản cũ server còn bật (FR-DET-04).
- **Kho chứng chỉ (B1, đã xử lý ở v1.5.0):** trước v1.5.0, request HTTP tin `certifi` còn TLS check tin kho hệ điều hành, nên sau một thành phần chặn TLS mà CA chỉ có trong kho OS (trên máy dev là Avast Web/Mail Shield), mọi site HTTPS bị báo "Could not fetch" với 0 finding và exit code `0`. Từ v1.5.0 cả hai dùng cùng một kho (FR-CLI-06): mặc định là kho OS, hoặc `--ca-bundle`. Hạn chế còn lại: nếu kho OS thiếu một CA mà `certifi` có, site đó sẽ bị coi là không tin cậy; khi đó dùng `--ca-bundle`.
- **TLS bị phần mềm cục bộ chặn giữa đường:** trên máy có phần mềm ký lại TLS (ví dụ Avast Web/Mail Shield, kể cả với `127.0.0.1`), nhóm TLS đo **kết nối tới phần mềm đó** chứ không phải tới server: giao thức và cipher là do phần mềm chọn (có thể bỏ sót `TLS-WEAK-PROTOCOL`/`TLS-WEAK-CIPHER`), chứng chỉ là bản do nó ký lại. Kết quả TLS trên các máy như vậy không đáng tin; nên quét từ máy hoặc CI không có TLS inspection. Tool tự cảnh báo khi issuer thuộc danh sách phần mềm/proxy chặn TLS đã biết (FR-TLS-11); phần mềm không có trong danh sách sẽ không được nhận ra. Test cần bắt tay TLS được tin cậy sẽ tự skip khi phát hiện việc chặn này.
- **Che secret dựa trên quy tắc:** chỉ che giá trị cookie và tham số URL có tên thuộc danh sách ở NFR-SEC-04. Secret nằm ở chỗ khác (ví dụ trong nội dung CSP hay header `Server`) sẽ không bị che. Báo cáo vẫn chứa URL, header và cấu hình của target nên chỉ chia sẻ trong phạm vi được phép.
- **TLS mở 2 kết nối** (Bước A và B); chấp nhận được vì chỉ là bắt tay, không lặp.
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

*Tài liệu này mô tả hành vi của mã nguồn `owasp_scanner` `v1.6.0` trong repo (CLI + Web UI cục bộ), đã đối chiếu với code và với các test tự động của v1.6.0 ngày 2026-09-30 (các test cần bắt tay TLS được tin cậy tự skip trên máy có phần mềm chặn TLS). Khi code thay đổi, cập nhật FR/NFR/AT tương ứng trong cùng thay đổi để tài liệu và mã nguồn không lệch nhau.*
