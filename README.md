# OWASP-Aligned Non-intrusive Web Security Scanner

Công cụ Python (CLI + Web UI cục bộ) quét cấu hình bảo mật của một website và
đối chiếu với các khuyến nghị của OWASP: [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/),
[OWASP Top 10:2021](https://owasp.org/Top10/) và một phần [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/).

**Tài liệu:**

- [`docs/SRS-owasp-scanner.md`](./docs/SRS-owasp-scanner.md) — đặc tả yêu cầu
  (v1.2), tài liệu requirement duy nhất, đã đối chiếu với mã nguồn và test.
- [`docs/PRODUCT-BACKLOG.md`](./docs/PRODUCT-BACKLOG.md) — backlog, quyết định
  đã chốt, thứ tự sprint.
- [`CLAUDE.md`](./CLAUDE.md) — quy tắc làm việc trong repo.
- [`docs/report.schema.json`](./docs/report.schema.json) — JSON Schema của báo cáo `--json`
  (`schema_version` 1.1).

## Changelog

- **v1.4.0** (Sprint 4, độ chính xác) — thay đổi hành vi cần lưu ý:
  - **Finding lộ file chỉ được báo khi nội dung khớp loại file (FR-DET-01).**
    HTTP 200 thôi là không đủ: `.git/HEAD` phải có `ref:`, `.env` phải có
    `KEY=VALUE`, `backup.zip` phải bắt đầu bằng `PK`… Trang chung của SPA, trang
    lỗi tuỳ biến hay trang chặn của WAF không còn tạo false positive; file thật
    trên các site như vậy vẫn được phát hiện. **Sẽ có ít finding lộ file hơn.**
  - **Soft-404 theo vân tay nội dung (FR-DET-02):** 2 probe ngẫu nhiên mỗi lần
    quét, nhận ra cả trường hợp mọi path redirect về `/login`.
  - **Không tải cả file:** mỗi response của path/thư mục chỉ đọc tối đa 8 KiB.
  - **Confidence (FR-DET-03):** finding lộ file có nội dung khớp là `high`.
  - **Cảnh báo TLS bị chặn giữa đường (FR-DET-16):** nếu chứng chỉ do phần mềm
    diệt virus hoặc proxy TLS inspection ký lại (ví dụ Avast Web/Mail Shield),
    `errors` có cảnh báo và finding TLS mang `confidence: low`.
  - Bảng path nhạy cảm và danh sách phần mềm chặn TLS nằm trong
    `owasp_scanner/rules/*.json`; `rules_version` giờ có dạng
    `sensitive_paths=<v>;tls_interceptors=<v>`.
- **v1.3.0** (Sprint 3b) — thay đổi hành vi cần lưu ý:
  - **Quét `http://` giờ luôn kiểm tra redirect sang HTTPS (FIX-09).** Site HTTP
    không chuyển sang HTTPS có finding `TLS-NO-HTTPS-REDIRECT` (HIGH), nên
    **exit code thành `1`**. Nếu `http://` chuyển sang HTTPS, nhóm TLS chạy trên
    URL HTTPS đó.
  - **Không theo redirect ra ngoài phạm vi (D4):** chỉ theo tới cùng host hoặc
    host chỉ khác `www.`; host khác không nhận request nào, `errors` có 1 dòng
    cho mỗi host bị chặn. Tối đa 10 bước redirect.
  - **Header xét trên response cuối (FIX-10):** HSTS chỉ đòi khi response cuối
    là HTTPS; khi redirect đổi host, kiểm tra thêm HSTS ở host gốc
    (`HDR-HSTS-MISSING-ON-START-HOST`, LOW).
  - **JSON `schema_version` 1.2** (chỉ thêm trường): `final_url`,
    `redirect_chain`; tên check mới `hsts-start-host`.
  - **User-Agent mới:** `TECHVIFY-OWASP-Scanner/1.3.0 (+non-intrusive security
    configuration check)`. Cập nhật luật lọc log/WAF nếu đang dựa vào chuỗi cũ.
  - Text sản phẩm đổi "Passive" thành "Non-intrusive" (FIX-11).
  - Lưu ý môi trường: phần mềm chặn TLS cục bộ (ví dụ Avast Web/Mail Shield) làm
    kết quả nhóm TLS không đáng tin; xem SRS mục 10.
- **v1.2.0** (Sprint 3) — thay đổi hành vi cần lưu ý:
  - **Che secret mặc định (D2):** giá trị cookie và tham số URL nhạy cảm
    (`token`, `key`, `session`, `password`, `sig`…) được thay bằng
    `<redacted len=N>` trong mọi output. CLI có `--show-secrets` để debug cục
    bộ; Web UI luôn che.
  - **Severity CORS (D3):** `CORS-WILDCARD-WITH-CREDENTIALS` hạ từ CRITICAL
    xuống MEDIUM, nên tổ hợp này **không còn làm exit code `1`**.
  - **JSON `schema_version` 1.1** (chỉ thêm trường): `scanner_version`,
    `rules_version`, `scan_id`, `secrets_redacted`; mỗi finding thêm `cwe`,
    `confidence`, `references`, `instance_key`, `fingerprint`. Schema ở
    `docs/report.schema.json`.
  - Thứ tự finding cố định giữa các lần quét (severity → id → instance_key).
  - CLI và Web UI dùng chung một bộ xử lý đầu ra; Web UI đọc hết body request
    trước khi trả lỗi (tránh connection reset trên Windows).
  - Dev: `pyproject.toml`, ruff, `jsonschema` (MIT); đã chạy test trên Python
    3.9, 3.12, 3.14.
- **v1.1.0** — sửa 6 vấn đề phát hiện khi review SRS v1.0: (1) TLS check tách
  thành 2 bước kết nối để không bỏ lỡ finding hết hạn chứng chỉ khi trust
  chain cũng lỗi; (2) sitemap.xml được parse đúng cú pháp `<loc>` thay vì áp
  nhầm cú pháp `Disallow:` của robots.txt; (3) X-Frame-Options không còn bị
  báo "thiếu" khi CSP đã có `frame-ancestors`; (4) HSTS không còn bị yêu cầu
  khi quét qua `http://`; (5) `Finding.id` của các path nhạy cảm nay khai báo
  tường minh thay vì suy ra từ chuỗi; (6) thêm dependency `cryptography` để
  đọc hạn chứng chỉ độc lập với xác thực trust chain. Chi tiết đầy đủ ở mục 0
  của `docs/SRS-owasp-scanner.md`.
- **v1.0.0** — bản đầu tiên.

## ⚠️ Chỉ dùng cho hệ thống bạn được phép kiểm tra

Tool này **chỉ gửi các request GET thông thường**, không gửi payload tấn công
(không SQLi, không brute-force, không fuzzing). Tuy nhiên việc quét một
website mà không có sự cho phép vẫn có thể vi phạm pháp luật hoặc điều khoản
dịch vụ của bên sở hữu. Trước khi chạy:

- Chỉ quét domain/hệ thống của chính bạn, hoặc
- Đã có xác nhận bằng văn bản (authorization letter / rules of engagement) từ
  chủ sở hữu hệ thống.

Tool sẽ hỏi xác nhận trước khi chạy; dùng `--yes` để bỏ qua xác nhận tương tác
(ví dụ khi chạy trong CI/CD với hệ thống nội bộ đã được phê duyệt).

## Phạm vi kiểm tra (non-intrusive configuration scan)

Tool không hoàn toàn thụ động: ngoài request tới trang chủ, nó chủ động gửi
khoảng 29 request GET (target `https://`) tới các path và thư mục cụ thể, kèm
một request có header `Origin` giả lập và 2 lần bắt tay TLS. Không gửi payload
khai thác, không thay đổi dữ liệu phía target. Chi tiết ở SRS mục 1.2.

| Check | Nội dung | OWASP mapping |
|---|---|---|
| Security headers | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, header rò rỉ thông tin (Server, X-Powered-By...) | A05:2021, A03:2021 |
| Cookies | Thiếu cờ Secure / HttpOnly / SameSite | A05:2021 |
| TLS/SSL | Giao thức yếu (TLS &lt; 1.2), cipher yếu, chứng chỉ hết hạn/sắp hết hạn/không hợp lệ | A02:2021 |
| HTTP → HTTPS | Có redirect HTTP sang HTTPS hay không | A02:2021 |
| CORS | `Access-Control-Allow-Origin` phản xạ origin tuỳ ý, kết hợp với credentials | A05:2021 |
| Exposed files | `.git/`, `.env`, backup file, `id_rsa`, `docker-compose.yml`, `phpinfo.php`... | A01:2021 |
| Directory listing | Thư mục cho phép liệt kê file (`Index of /`) | A05:2021 |
| robots.txt | Có `Disallow:` tiết lộ đường dẫn nhạy cảm (admin, backup, staging...) không | A01:2021 |
| sitemap.xml | Có `<loc>` tiết lộ URL nhạy cảm (staging, internal...) không | A01:2021 |

**Giới hạn:** đây là quét cấu hình không xâm lấn (non-intrusive), KHÔNG phải DAST toàn diện.
Tool không phát hiện injection (SQLi/XSS thực sự cần test chủ động), business
logic flaw, broken authentication ở tầng ứng dụng, v.v. Với các hạng mục đó,
nên dùng thêm công cụ chuyên sâu như OWASP ZAP, Burp Suite, hoặc pentest thủ
công — sau khi đã có phạm vi và cho phép rõ ràng.

## Cài đặt

```bash
# (từ thư mục gốc của repo)
pip install -r requirements.txt
```

## Sử dụng

```bash
# Quét cơ bản, in kết quả ra terminal
python -m owasp_scanner https://example.com

# Xuất thêm báo cáo JSON, bỏ qua câu hỏi xác nhận (đã có authorization)
python -m owasp_scanner https://example.com --json report.json --yes

# Tuỳ chỉnh timeout / số luồng khi kiểm tra các đường dẫn nhạy cảm
python -m owasp_scanner https://example.com --timeout 15 --workers 8
```

Exit code: `0` nếu không có finding mức CRITICAL/HIGH, `1` nếu có, `2` nếu
người dùng không xác nhận quyền quét.

## Giao diện web (chạy trên máy local)

```bash
python -m owasp_scanner.web        # mở http://127.0.0.1:8765/
python -m owasp_scanner.web --port 9000 --timeout 15 --workers 8
```

Nhập URL, tick ô xác nhận quyền quét, bấm **Scan**. Kết quả hiện bên dưới ô
nhập: bảng tổng hợp theo severity, trạng thái gate (tương đương exit code của
CLI), lỗi không nghiêm trọng, và danh sách finding có lọc theo mức độ. Giao diện
dùng tiếng Anh (ngôn ngữ mặc định của hệ thống).

- Link **Download Test result** (ngay dưới ô nhập URL, chỉ hiện sau khi quét
  xong) tải báo cáo HTML độc lập: CSS nhúng sẵn, không có script, mở được
  offline, in được. Server chỉ giữ báo cáo của 20 lần quét gần nhất, trong bộ
  nhớ, mất khi tắt server.
- Nút **Download JSON** tải báo cáo cùng định dạng với `--json` của CLI.

- Giao diện gọi đúng `run_scan()` của CLI nên kết quả giống hệt nhau.
- Server chỉ lắng nghe `127.0.0.1` theo mặc định và từ chối request có
  `Host`/`Origin` lạ (chống DNS rebinding và request chéo site). Mỗi lúc chỉ
  chạy 1 lần quét. Không dùng `--host 0.0.0.0` trừ khi thật sự cần — khi đó
  bất kỳ ai truy cập được cổng này đều có thể ra lệnh quét từ máy của bạn.
- Không cần thêm thư viện: server dùng `http.server` của Python, giao diện là
  HTML/CSS/JS tĩnh trong `owasp_scanner/static/`, không tải gì từ internet.

## Cấu trúc project

```
owasp_scanner/
  cli.py            # Entry point, điều phối các check
  http_utils.py      # HTTP session dùng chung (timeout, User-Agent, không retry-storm)
  models.py           # Finding / ScanResult / Severity
  report.py           # In CLI + xuất JSON
  web.py              # Giao diện web local (python -m owasp_scanner.web)
  html_report.py      # Báo cáo HTML độc lập (link "Download Test result")
  static/             # index.html, app.js, app.css của giao diện web
  checks/
    headers.py        # Security headers
    cookies.py         # Cookie flags
    tls_check.py        # TLS/certificate
    cors_check.py        # CORS misconfiguration
    exposure.py           # File/path exposure, directory listing, robots.txt
    redirect_check.py      # HTTP -> HTTPS redirect
```

## Kiểm thử offline (không cần internet)

`tests/mock_server.py` dựng một server giả lập có sẵn các lỗi cấu hình phổ
biến (thiếu header, cookie thiếu cờ, `.env`/`.git` bị lộ, bật directory
listing...) để kiểm thử nhanh mà không cần quét một site thật:

```bash
python3 tests/mock_server.py 8899 &
python3 -m owasp_scanner http://127.0.0.1:8899 --yes
```

Bộ test tự động (pytest) phủ các kịch bản AT-01…AT-28 của `docs/SRS-owasp-scanner.md` mục 9,
tự dựng HTTP/HTTPS server trên `127.0.0.1` và tự sinh chứng chỉ test (hết hạn,
chưa hiệu lực, sắp hết hạn, tự ký) — không cần internet:

```bash
pip install -r requirements-dev.txt
python -m pytest
```

## Gợi ý mở rộng sau này

- Thêm chế độ "Active nhẹ" (crawl link nội bộ, kiểm tra form login, phát hiện
  open redirect) — cần xác nhận phạm vi rõ ràng hơn.
- Tích hợp vào pipeline CI/CD nội bộ (chạy `--yes` với `--json` rồi parse kết
  quả để gate build).
- Xuất báo cáo HTML cho khách hàng nếu cần trình bày trực quan hơn JSON.
