# OWASP-Aligned Passive Web Security Scanner

Công cụ dòng lệnh (Python) quét một website và đối chiếu với các khuyến nghị
của OWASP: [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/),
[OWASP Top 10:2021](https://owasp.org/Top10/) và một phần [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/).

**Đặc tả yêu cầu chi tiết:** xem [`SRS.md`](./SRS.md) trong cùng thư mục này —
đây là baseline "as-built" duy nhất, đã được đối chiếu và kiểm thử cùng mã
nguồn (không phải tài liệu rời rạc).

## Changelog

- **v1.1.0** — sửa 6 vấn đề phát hiện khi review SRS v1.0: (1) TLS check tách
  thành 2 bước kết nối để không bỏ lỡ finding hết hạn chứng chỉ khi trust
  chain cũng lỗi; (2) sitemap.xml được parse đúng cú pháp `<loc>` thay vì áp
  nhầm cú pháp `Disallow:` của robots.txt; (3) X-Frame-Options không còn bị
  báo "thiếu" khi CSP đã có `frame-ancestors`; (4) HSTS không còn bị yêu cầu
  khi quét qua `http://`; (5) `Finding.id` của các path nhạy cảm nay khai báo
  tường minh thay vì suy ra từ chuỗi; (6) thêm dependency `cryptography` để
  đọc hạn chứng chỉ độc lập với xác thực trust chain. Chi tiết đầy đủ ở mục 0
  của `SRS.md`.
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

## Phạm vi kiểm tra (Passive / Header scan)

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

**Giới hạn:** đây là quét passive/config-check, KHÔNG phải DAST toàn diện.
Tool không phát hiện injection (SQLi/XSS thực sự cần test chủ động), business
logic flaw, broken authentication ở tầng ứng dụng, v.v. Với các hạng mục đó,
nên dùng thêm công cụ chuyên sâu như OWASP ZAP, Burp Suite, hoặc pentest thủ
công — sau khi đã có phạm vi và cho phép rõ ràng.

## Cài đặt

```bash
cd owasp-scanner
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

## Cấu trúc project

```
owasp_scanner/
  cli.py            # Entry point, điều phối các check
  http_utils.py      # HTTP session dùng chung (timeout, User-Agent, không retry-storm)
  models.py           # Finding / ScanResult / Severity
  report.py           # In CLI + xuất JSON
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

## Gợi ý mở rộng sau này

- Thêm chế độ "Active nhẹ" (crawl link nội bộ, kiểm tra form login, phát hiện
  open redirect) — cần xác nhận phạm vi rõ ràng hơn.
- Tích hợp vào pipeline CI/CD nội bộ (chạy `--yes` với `--json` rồi parse kết
  quả để gate build).
- Xuất báo cáo HTML cho khách hàng nếu cần trình bày trực quan hơn JSON.
