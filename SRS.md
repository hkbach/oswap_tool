# SRS – OWASP-Aligned Passive Web Security Scanner

| | |
|---|---|
| **Tài liệu** | Software Requirements Specification (SRS) |
| **Sản phẩm** | OWASP-Aligned Passive Web Security Scanner (CLI) |
| **Phiên bản tài liệu** | 1.1 |
| **Ngày** | 2026-09-23 |
| **Chuẩn tham chiếu** | IEEE 830-1998 (rút gọn) |
| **Trạng thái** | Mô tả lại (as-built) phiên bản đã triển khai `v1.1.0`, dùng làm baseline để phát triển tiếp trong VS Code |
| **Mã nguồn tham chiếu** | Đóng gói kèm chính tài liệu này trong `owasp-scanner.zip` (cùng thư mục `owasp_scanner/` chứa mã, `SRS.md` này, và `tests/` chứa harness kiểm thử offline) — xem mục 0 |

---

## 0. Ghi chú phiên bản / Changelog

Bản 1.1 sửa các điểm review kỹ thuật trên bản 1.0 (giữ nguyên số thứ tự FR cũ khi có thể, đánh dấu rõ chỗ nào đổi số):

| # | Vấn đề được nêu | Thay đổi trong tài liệu | Thay đổi trong mã nguồn |
|---|---|---|---|
| 1 | Bản 1.0 tự nhận "as-built" nhưng không đóng gói cùng mã nguồn, gây khó xác minh | Thêm dòng "Mã nguồn tham chiếu" ở trên; SRS này được zip cùng thư mục `owasp_scanner/` làm baseline duy nhất, thay thế các lần gửi rời rạc trước đó | Không đổi |
| 2 | `ssl.create_default_context()` tự chặn cert hết hạn ở bước xác thực → `TLS-CERT-EXPIRED` (FR-TLS-06 cũ) không bao giờ chạy tới; AT-10 mâu thuẫn | Viết lại toàn bộ mục 4.5 (FR-TLS-01…09) theo thiết kế 2 lần kết nối; viết lại AT-10, thêm AT-15 | `tls_check.py` viết lại: kết nối không xác thực để đọc `notAfter` trước, kết nối xác thực chỉ để kiểm tra trust và CHỈ chạy khi cert còn hạn |
| 3 | FR-EXP-08 áp `Disallow:` (cú pháp robots.txt) lên `sitemap.xml`, vốn dùng `<loc>` | Tách FR-EXP-08 thành 2 yêu cầu riêng cho robots.txt và sitemap.xml | `exposure.py`: thêm `_check_sitemap_xml()` parse `<loc>` bằng regex, tách khỏi `_check_robots_txt()` |
| 4 | Nhánh "missing X-Frame-Options" không loại trừ trường hợp CSP đã có `frame-ancestors`, trong khi nhánh "giá trị lạ" có loại trừ — không nhất quán | Gộp lại một điều kiện loại trừ duy nhất, áp dụng cho cả 2 nhánh (FR-HDR-04, FR-HDR-05) | `headers.py`: tính `has_frame_ancestors` một lần, dùng chung cho cả nhánh missing và nhánh weak-value |
| 5 | HSTS bị yêu cầu ngay cả khi quét `http://`, trong khi trình duyệt bỏ qua HSTS gửi qua HTTP | Thêm điều kiện tường minh vào FR-HDR-01 | `headers.py`: thêm tham số `is_https`; bỏ qua yêu cầu HSTS khi `is_https=False`; `cli.py` truyền `parsed.scheme == "https"` |
| 6 | FR-CLI-05 tham chiếu nhầm "mục 4.3" (phải là 4.5); cột Severity của FR-COOKIE-01 ghi nhầm "M" (giá trị Priority, không phải Severity hợp lệ) | Sửa cả hai | Không áp dụng (chỉ là lỗi đánh máy trong tài liệu) |
| 7 | Bảng 4.8.1 chưa nêu `Finding.id` cụ thể cho từng path | Thêm cột `Finding.id` vào bảng 4.8.1 | `exposure.py`: đổi `_SENSITIVE_PATHS` từ `path -> (severity, label)` sang `path -> (id, severity, label)` khai báo tường minh, thay vì suy ra id bằng biến đổi chuỗi (tránh rủi ro trùng id) |
| 8 | FR-CORS-02 gắn CRITICAL cho tổ hợp `Access-Control-Allow-Origin: *` + credentials — nhưng trình duyệt tự chặn tổ hợp này, nên mức CRITICAL có thể quá cao | **Đã xác nhận với chủ SRS (2026-09-23): giữ CRITICAL.** Lý do: đây là chỉ báo cấu hình CORS bị sao chép/nhầm lẫn nghiêm trọng, cần rà soát ngay toàn bộ policy — dù bản thân tổ hợp này không khai thác trực tiếp được qua trình duyệt thông thường. Đã cập nhật mô tả finding ở FR-CORS-02 để nêu rõ điều này, tránh hiểu nhầm "khai thác được ngay". | Không đổi (severity giữ nguyên CRITICAL trong `cors_check.py`) |

---

## 1. Giới thiệu

### 1.1 Mục đích

Tài liệu này đặc tả yêu cầu chi tiết cho công cụ dòng lệnh **OWASP-Aligned Passive Web Security Scanner** — quét một website và đối chiếu cấu hình HTTP/TLS quan sát được với các khuyến nghị của OWASP. Tài liệu dùng làm cơ sở để:

- Lập trình/mở rộng tool trong Visual Studio Code (giữ đúng hành vi hiện có, hoặc port sang ngôn ngữ/kiến trúc khác).
- Viết test case kiểm thử chấp nhận (acceptance test).
- Làm tài liệu tham chiếu khi bàn giao/đánh giá nội bộ hoặc cho khách hàng.

### 1.2 Phạm vi sản phẩm

Sản phẩm là một **CLI tool bằng Python**, nhận vào một URL/hostname, gửi các HTTP request **thông thường (GET), không chứa payload tấn công**, và trả về danh sách finding (phát hiện) về cấu hình bảo mật, kèm mức độ nghiêm trọng, mã OWASP Top 10:2021 tương ứng, evidence và khuyến nghị khắc phục. Kết quả xuất ra terminal (có màu) và tuỳ chọn xuất file JSON.

Đây là **passive/config scanner**, không phải DAST (Dynamic Application Security Testing) toàn diện — xem mục 2.4 (Out of scope) và mục 10 (Hạn chế).

### 1.3 Đối tượng đọc

Kỹ sư phần mềm/security engineer thực hiện code, mở rộng hoặc review lại tool trong VS Code; QA viết test case; kỹ sư phụ trách tích hợp CI/CD.

### 1.4 Định nghĩa, từ viết tắt

| Thuật ngữ | Ý nghĩa |
|---|---|
| SRS | Software Requirements Specification |
| Finding | Một phát hiện đơn lẻ (1 vấn đề cấu hình bảo mật) |
| Severity | Mức độ nghiêm trọng: CRITICAL, HIGH, MEDIUM, LOW, INFO |
| Target | URL/hostname được quét |
| Soft-404 | Server trả về HTTP 200 cho một path không tồn tại (thay vì 404), gây false positive nếu không xử lý |
| ASVS | OWASP Application Security Verification Standard |
| DAST | Dynamic Application Security Testing (kiểm thử bảo mật động, có gửi payload khai thác) |

### 1.5 Tài liệu tham khảo

- OWASP Secure Headers Project — <https://owasp.org/www-project-secure-headers/>
- OWASP Top 10:2021 — <https://owasp.org/Top10/>
- OWASP ASVS (V9 Communications, V14 Configuration) — <https://owasp.org/www-project-application-security-verification-standard/>
- README.md của source code hiện có (`owasp-scanner/README.md`)

---

## 2. Mô tả tổng quan

### 2.1 Bối cảnh sản phẩm

Tool chạy độc lập (standalone CLI), không có thành phần server/UI. Người dùng chạy trực tiếp bằng `python -m owasp_scanner <target>` từ terminal, hoặc gọi từ pipeline CI/CD.

### 2.2 Đối tượng người dùng

- Kỹ sư bảo mật / DevSecOps thực hiện kiểm tra nhanh cấu hình bảo mật trước khi release.
- Delivery/QA lead muốn có báo cáo nhanh về "vệ sinh" cấu hình HTTP của một website nội bộ hoặc website khách hàng **đã được cấp phép**.
- Pipeline CI/CD chạy tự động, gate build khi phát hiện CRITICAL/HIGH.

### 2.3 Giả định và ràng buộc

- Người vận hành tool **có quyền hợp pháp** để quét target (sở hữu hệ thống hoặc có văn bản uỷ quyền). Đây là ràng buộc bắt buộc, không phải tuỳ chọn — xem FR-CONSENT-01.
- Target phản hồi HTTP(S) tiêu chuẩn; tool không hỗ trợ site yêu cầu đăng nhập/OAuth để truy cập trang chủ.
- Môi trường chạy có Python ≥ 3.9 và có thể cài `pip` package (`requests`, `urllib3`, `cryptography` — thư viện `cryptography` cần cho việc đọc ngày hết hạn chứng chỉ độc lập với bước xác thực trust chain, xem mục 4.5).
- Không có yêu cầu về giao diện đồ hoạ (GUI) trong phạm vi tài liệu này.

### 2.4 Phạm vi KHÔNG bao gồm (Out of scope)

Để tránh hiểu nhầm khi mở rộng, các mục sau **không** thuộc phạm vi bản đặc tả này (có thể là roadmap giai đoạn 2 — xem mục 11):

- Gửi payload khai thác chủ động (SQL injection, XSS reflected/stored thật, command injection, brute-force đăng nhập, fuzzing).
- Crawl toàn bộ site / theo link nội bộ nhiều cấp.
- Kiểm tra business logic, broken authentication ở tầng ứng dụng, broken access control ở tầng dữ liệu (yêu cầu tài khoản test).
- Quét nhiều target song song trong một lần chạy (multi-target batch).
- Giao diện web/GUI, lưu trữ lịch sử quét, dashboard.
- Xuất báo cáo HTML (chỉ nêu như gợi ý mở rộng ở mục 11).

---

## 3. Kiến trúc hệ thống

### 3.1 Thành phần (module) và trách nhiệm

```
owasp_scanner/
├── __main__.py          # Cho phép `python -m owasp_scanner`
├── cli.py                # Entry point: argparse, consent gate, điều phối scan, in kết quả
├── http_utils.py          # HTTP session dùng chung: timeout mặc định, User-Agent, retry có kiểm soát
├── models.py               # Kiểu dữ liệu: Severity, Finding, ScanResult
├── report.py                # In báo cáo CLI (có màu ANSI) + ghi file JSON
└── checks/
    ├── headers.py             # Kiểm tra security headers
    ├── cookies.py              # Kiểm tra cờ cookie (Secure/HttpOnly/SameSite)
    ├── tls_check.py             # Kiểm tra TLS/chứng chỉ
    ├── redirect_check.py         # Kiểm tra redirect HTTP → HTTPS
    ├── cors_check.py              # Kiểm tra cấu hình CORS
    └── exposure.py                 # File/path nhạy cảm lộ, directory listing, robots/sitemap
```

Mỗi module trong `checks/` là **hàm thuần (pure-ish function)**: nhận session/URL/dữ liệu response đầu vào, trả về `list[Finding]`, không giữ state toàn cục — giúp dễ viết unit test độc lập từng check.

### 3.2 Luồng xử lý chính (FR-CLI-01 → FR-REPORT-02)

1. Người dùng chạy `python -m owasp_scanner <target> [options]`.
2. Tool in **consent banner** và yêu cầu xác nhận quyền quét (bỏ qua nếu có `--yes`). Từ chối → thoát với exit code `2`.
3. Chuẩn hoá target (thêm scheme `https://` nếu thiếu, thêm `/` cuối path).
4. Gửi GET baseline tới trang chủ target. Thất bại → ghi lỗi vào `errors`, dừng, in báo cáo rỗng.
5. Thành công → lần lượt chạy các check (thứ tự cố định, xem bảng FR bên dưới), mỗi check trả về danh sách `Finding`, gộp vào `ScanResult`.
6. In báo cáo ra terminal (sắp xếp theo severity); nếu có `--json PATH`, ghi thêm file JSON.
7. Thoát với exit code phản ánh mức độ nghiêm trọng cao nhất tìm được.

---

## 4. Yêu cầu chức năng (Functional Requirements)

Quy ước mã: `FR-<NHÓM>-<SỐ>`. Priority: **M**ust / **S**hould / **C**ould (MoSCoW).

### 4.1 Nhóm CLI & vòng đời chạy

| ID | Yêu cầu | Priority |
|---|---|---|
| FR-CLI-01 | Tool PHẢI nhận một tham số bắt buộc `target` (URL hoặc hostname). Nếu không có scheme, tool PHẢI tự thêm `https://`. | M |
| FR-CLI-02 | Tool PHẢI hỗ trợ các tham số tuỳ chọn: `--json PATH` (xuất JSON), `--timeout N` (giây, mặc định 10), `--workers N` (số luồng cho check exposure, mặc định 5), `--no-color` (tắt màu ANSI), `--yes`/`--i-have-authorization` (bỏ qua xác nhận tương tác). | M |
| FR-CLI-03 | Nếu GET baseline tới target thất bại (lỗi kết nối/DNS/timeout), tool PHẢI ghi lỗi vào danh sách `errors` của kết quả, KHÔNG được crash, và vẫn in được báo cáo (rỗng finding, có mục lỗi). | M |
| FR-CLI-04 | Exit code: `0` nếu không có finding CRITICAL/HIGH; `1` nếu có ít nhất 1 finding CRITICAL hoặc HIGH; `2` nếu người dùng không xác nhận quyền quét ở bước consent. | M |
| FR-CLI-05 | Nếu quét target với scheme `http://` (không phải https), tool KHÔNG được chạy nhóm check TLS (mục 4.5) vì không áp dụng. | M |

### 4.2 Nhóm xác nhận quyền quét (Consent Gate)

| ID | Yêu cầu | Priority |
|---|---|---|
| FR-CONSENT-01 | Trước khi gửi bất kỳ request nào tới target, tool PHẢI hiển thị banner cảnh báo nêu rõ: tool chỉ gửi GET thông thường, không khai thác, nhưng quét không phép có thể vi phạm pháp luật/điều khoản dịch vụ. | M |
| FR-CONSENT-02 | Nếu không truyền `--yes`, tool PHẢI hỏi xác nhận tương tác (prompt Y/N) trước khi quét. Chỉ các câu trả lời `y`/`yes` (không phân biệt hoa/thường) được coi là đồng ý. | M |
| FR-CONSENT-03 | Nếu người dùng từ chối (hoặc input rỗng/EOF), tool PHẢI dừng ngay, KHÔNG gửi bất kỳ request nào tới target, và thoát với exit code `2`. | M |
| FR-CONSENT-04 | `--yes` PHẢI cho phép bỏ qua bước hỏi tương tác (dùng trong CI/CD với hệ thống nội bộ đã được phê duyệt từ trước). | M |

### 4.3 Nhóm kiểm tra Security Headers (`checks/headers.py`)

Cơ sở: OWASP Secure Headers Project.

| ID | Yêu cầu | Severity mặc định | OWASP mapping | Priority |
|---|---|---|---|---|
| FR-HDR-01 | Nếu response KHÔNG có header `Strict-Transport-Security`, PHẢI tạo finding `HDR-STRICT-TRANSPORT-SECURITY-MISSING`. **Ngoại lệ:** yêu cầu này CHỈ áp dụng khi baseline request dùng scheme `https://`; khi quét `http://`, tool PHẢI bỏ qua hoàn toàn yêu cầu HSTS (không tạo finding thiếu/đủ), vì trình duyệt bỏ qua header HSTS gửi qua kết nối không mã hoá — flag thiếu HSTS trên một response HTTP thuần là vô nghĩa/gây hiểu nhầm. | HIGH | A02:2021 | M |
| FR-HDR-02 | Nếu response KHÔNG có header `Content-Security-Policy`, PHẢI tạo finding `HDR-CONTENT-SECURITY-POLICY-MISSING`. | MEDIUM | A05:2021 | M |
| FR-HDR-03 | Nếu response KHÔNG có header `X-Content-Type-Options`, PHẢI tạo finding tương ứng. | LOW | A05:2021 | M |
| FR-HDR-04 | Nếu response KHÔNG có header `X-Frame-Options`, PHẢI tạo finding tương ứng — **trừ khi** CSP đã có directive `frame-ancestors` (xem điều kiện loại trừ chung ở FR-HDR-05). | MEDIUM | A05:2021 | M |
| FR-HDR-05 | Điều kiện loại trừ dùng chung cho FR-HDR-04 và cho trường hợp `X-Frame-Options` có giá trị khác `DENY`/`SAMEORIGIN` (không phân biệt hoa/thường): nếu CSP đã có `frame-ancestors`, tool KHÔNG được tạo finding nào về X-Frame-Options (dù là "thiếu" hay "giá trị lạ") — vì `frame-ancestors` đã thay thế chức năng chống clickjacking ở các trình duyệt hiện đại. Nếu KHÔNG có `frame-ancestors` và giá trị X-Frame-Options khác chuẩn, PHẢI tạo finding `HDR-XFO-WEAK`. *(Bản 1.0 chỉ áp dụng điều kiện loại trừ này cho nhánh "giá trị lạ", không áp dụng cho nhánh "thiếu" — đã sửa ở bản 1.1, xem mục 0.)* | LOW | A05:2021 | S |
| FR-HDR-06 | Nếu response KHÔNG có header `Referrer-Policy`, PHẢI tạo finding tương ứng. | LOW | A05:2021 | M |
| FR-HDR-07 | Nếu response KHÔNG có header `Permissions-Policy`, PHẢI tạo finding tương ứng. | INFO | A05:2021 | S |
| FR-HDR-08 | Nếu CSP có chứa `unsafe-inline` hoặc `unsafe-eval` (không phân biệt hoa/thường), PHẢI tạo finding `HDR-CSP-UNSAFE`. | MEDIUM | A03:2021 | M |
| FR-HDR-09 | Nếu có header `X-XSS-Protection` với giá trị khác `0`, PHẢI tạo finding `HDR-XXP-LEGACY` (khuyến nghị dùng CSP thay thế, giá trị bật có thể tự gây XSS ở trình duyệt cũ). | INFO | A05:2021 | C |
| FR-HDR-10 | Nếu response có bất kỳ header nào trong nhóm rò rỉ thông tin (`Server`, `X-Powered-By`, `X-AspNet-Version`, `X-AspNetMvc-Version`), PHẢI tạo 1 finding riêng cho mỗi header, kèm giá trị quan sát được làm evidence. | INFO | A05:2021 | S |

### 4.4 Nhóm kiểm tra Cookie (`checks/cookies.py`)

| ID | Yêu cầu | Severity | OWASP mapping | Priority |
|---|---|---|---|---|
| FR-COOKIE-01 | Với mỗi `Set-Cookie` header trong response, tool PHẢI parse tên cookie và kiểm tra 3 thuộc tính: `Secure`, `HttpOnly`, `SameSite`. | — | A05:2021 | M |
| FR-COOKIE-02 | Nếu thiếu `Secure` hoặc thiếu `HttpOnly`, finding PHẢI có severity MEDIUM. Nếu chỉ thiếu `SameSite` (đã có Secure + HttpOnly), severity LOW. | — | — | M |
| FR-COOKIE-03 | Nếu `SameSite` có giá trị KHÔNG thuộc {`Lax`,`Strict`,`None`} (không phân biệt hoa/thường), PHẢI coi là "thiếu hợp lệ" và liệt kê giá trị sai trong finding. | — | — | S |
| FR-COOKIE-04 | Evidence của finding PHẢI chứa nguyên văn giá trị `Set-Cookie` gốc (phục vụ debug), KHÔNG cần che giá trị cookie (tool chỉ đọc response của chính người dùng, không log ra ngoài). | — | — | S |

### 4.5 Nhóm kiểm tra TLS/Chứng chỉ (`checks/tls_check.py`)

Chỉ chạy khi target dùng scheme `https://` (FR-CLI-05).

**Vấn đề thiết kế đã sửa ở bản 1.1 (xem mục 0, dòng #2):** một context TLS xác thực mặc định (`ssl.create_default_context()`) sẽ ném `SSLCertVerificationError` ngay trong bước bắt tay (handshake) nếu chứng chỉ hết hạn — nghĩa là code KHÔNG BAO GIỜ đọc được `notAfter` cho một chứng chỉ đã hết hạn nếu chỉ dùng 1 kết nối xác thực. Vì vậy bản 1.1 yêu cầu tách thành **2 bước kết nối độc lập**:

- **Bước A (không xác thực):** mở kết nối TLS với `verify_mode=ssl.CERT_NONE`, `check_hostname=False`, chỉ để đọc chứng chỉ thô (`getpeercert(binary_form=True)`) và giao thức/cipher đã thương lượng — luôn thực hiện được bất kể chứng chỉ có được tin cậy hay không.
- **Bước B (xác thực):** mở kết nối TLS bằng `ssl.create_default_context()` như bình thường, nhưng **chỉ để phát hiện lỗi trust chain/hostname**, và **chỉ chạy khi Bước A cho thấy chứng chỉ còn trong thời hạn hiệu lực** (không hết hạn, không "chưa tới ngày hiệu lực") — để tránh báo trùng 2 finding CRITICAL cho cùng một nguyên nhân gốc (hết hạn cũng khiến verify thất bại).

| ID | Yêu cầu | Severity | OWASP mapping | Priority |
|---|---|---|---|---|
| FR-TLS-01 | Tool PHẢI thực hiện Bước A (kết nối không xác thực) để lấy: bytes chứng chỉ thô (DER), giao thức TLS đã thương lượng, cipher suite đã thương lượng. Bước này KHÔNG được thất bại chỉ vì lý do trust/hostname (vì không bật xác thực). | — | — | M |
| FR-TLS-02 | Nếu Bước A thất bại vì lý do kết nối (timeout, DNS lỗi, connection refused, lỗi OS/SSL khác — KHÔNG phải do trust), PHẢI tạo finding `TLS-CONN-FAILED` và DỪNG toàn bộ các kiểm tra TLS còn lại cho target đó. | INFO | A02:2021 | M |
| FR-TLS-03 | Nếu giao thức lấy được ở Bước A thuộc {`SSLv2`,`SSLv3`,`TLSv1`,`TLSv1.1`}, PHẢI tạo finding `TLS-WEAK-PROTOCOL`. | HIGH | A02:2021 | M |
| FR-TLS-04 | Nếu tên cipher suite lấy được ở Bước A chứa bất kỳ chuỗi con nào trong {`RC4`,`3DES`,`MD5`,`NULL`,`EXPORT`}, PHẢI tạo finding `TLS-WEAK-CIPHER`. | HIGH | A02:2021 | M |
| FR-TLS-05 | Tool PHẢI giải mã chứng chỉ DER lấy được ở Bước A (dùng thư viện `cryptography`, KHÔNG phụ thuộc kết quả xác thực) để đọc `not_valid_before`/`not_valid_after`. Nếu thời điểm hiện tại SỚM HƠN `not_valid_before`, PHẢI tạo finding `TLS-CERT-NOT-YET-VALID`. | CRITICAL | A02:2021 | S |
| FR-TLS-06 | Nếu thời điểm hiện tại TRỄ HƠN `not_valid_after` (đã hết hạn), PHẢI tạo finding `TLS-CERT-EXPIRED`. Việc này PHẢI dựa hoàn toàn vào dữ liệu đọc được ở Bước A, độc lập với kết quả Bước B — để không bao giờ rơi vào tình trạng "không thể tạo được" như ở bản 1.0. | CRITICAL | A02:2021 | M |
| FR-TLS-07 | Nếu chứng chỉ còn hiệu lực (không rơi vào FR-TLS-05/06) nhưng còn dưới 30 ngày tới `not_valid_after`, PHẢI tạo finding `TLS-CERT-EXPIRING-SOON`. Ngưỡng 30 ngày PHẢI là hằng số dễ cấu hình (constant ở đầu module). | MEDIUM | A02:2021 | S |
| FR-TLS-08 | Tool PHẢI thực hiện Bước B (kết nối xác thực bằng default trust store) **CHỈ KHI** FR-TLS-05 và FR-TLS-06 đều KHÔNG phát sinh finding (tức chứng chỉ đang trong thời hạn hiệu lực). Nếu Bước B ném `SSLCertVerificationError`, PHẢI tạo finding `TLS-CERT-NOT-TRUSTED` với evidence là thông điệp lỗi gốc (bao gồm các nguyên nhân: self-signed, thiếu intermediate, sai hostname, CA không được tin cậy — bản 1.1 gộp chung 1 mã lỗi, xem mục 10 về giới hạn phân loại chi tiết hơn). | CRITICAL | A02:2021 | M |
| FR-TLS-09 | Nếu FR-TLS-05 hoặc FR-TLS-06 đã tạo finding (chứng chỉ có vấn đề về thời hạn), tool PHẢI **bỏ qua** Bước B hoàn toàn — không được tạo thêm `TLS-CERT-NOT-TRUSTED` cho cùng kết nối đó, để tránh 2 CRITICAL trùng lặp giải thích cùng một nguyên nhân gốc. | — | — | M |

**Đã xác minh bằng kết nối TLS thật (không chỉ review code):** dựng 2 server test cục bộ — (a) chứng chỉ tự ký đã hết hạn từ 2020, (b) chứng chỉ tự ký còn hiệu lực nhưng không được hệ thống tin cậy. Kết quả: (a) chỉ tạo đúng 1 finding `TLS-CERT-EXPIRED` (không có `TLS-CERT-NOT-TRUSTED` trùng lặp); (b) chỉ tạo đúng 1 finding `TLS-CERT-NOT-TRUSTED` (không có finding hết hạn sai). Khớp với FR-TLS-08/09.

### 4.6 Nhóm kiểm tra Redirect HTTP → HTTPS (`checks/redirect_check.py`)

| ID | Yêu cầu | Severity | OWASP mapping | Priority |
|---|---|---|---|---|
| FR-REDIR-01 | Chỉ chạy khi target gốc dùng `https://` (đã xác nhận TLS hoạt động ở nhóm 4.5). Tool PHẢI gửi GET tới `http://<hostname>/` với `allow_redirects=True`. | — | — | M |
| FR-REDIR-02 | Nếu request HTTP thất bại hoàn toàn (không có phản hồi), KHÔNG được coi là finding (cổng 80 có thể đóng hoàn toàn theo thiết kế — đây là hành vi chấp nhận được). | — | — | M |
| FR-REDIR-03 | Nếu request có phản hồi nhưng URL cuối cùng sau redirect KHÔNG bắt đầu bằng `https://`, PHẢI tạo finding `TLS-NO-HTTPS-REDIRECT`. | HIGH | A02:2021 | M |

### 4.7 Nhóm kiểm tra CORS (`checks/cors_check.py`)

Nguyên tắc: chỉ gửi 1 request GET với header `Origin` giả lập rõ ràng là request kiểm thử (KHÔNG dùng domain thật của bên thứ ba), không gửi credential thật.

| ID | Yêu cầu | Severity | OWASP mapping | Priority |
|---|---|---|---|---|
| FR-CORS-01 | Tool PHẢI gửi GET tới target kèm header `Origin: https://owasp-scanner-cors-test.invalid` (hoặc giá trị placeholder tương đương, rõ ràng không phải domain thật). | — | — | M |
| FR-CORS-02 | Nếu `Access-Control-Allow-Origin: *` VÀ `Access-Control-Allow-Credentials: true` xuất hiện đồng thời, PHẢI tạo finding `CORS-WILDCARD-WITH-CREDENTIALS`. Mô tả finding PHẢI nêu rõ: trình duyệt tự chặn tổ hợp này cho request có credentials, nên đây là **chỉ báo cấu hình CORS bị sao chép/nhầm lẫn nghiêm trọng cần rà soát ngay**, không phải "khai thác được trực tiếp qua trình duyệt thông thường". | CRITICAL *(đã xác nhận với chủ SRS ngày 2026-09-23 — xem mục 0, dòng #8)* | A05:2021 | M |
| FR-CORS-03 | Nếu `Access-Control-Allow-Origin` phản xạ đúng giá trị Origin giả lập đã gửi (không phải whitelist thật), PHẢI tạo finding `CORS-REFLECTS-ARBITRARY-ORIGIN`; severity HIGH nếu đồng thời có `Access-Control-Allow-Credentials: true`, ngược lại MEDIUM. | HIGH/MEDIUM | A05:2021 | M |
| FR-CORS-04 | Nếu `Access-Control-Allow-Origin: *` (không có credentials), PHẢI tạo finding `CORS-WILDCARD` ở mức thông tin (có thể chấp nhận được với API công khai). | INFO | A05:2021 | S |

### 4.8 Nhóm kiểm tra lộ file/path nhạy cảm (`checks/exposure.py`)

| ID | Yêu cầu | Priority |
|---|---|---|
| FR-EXP-01 | Tool PHẢI duy trì danh sách path nhạy cảm cần kiểm tra kèm severity tương ứng (xem bảng 4.8.1). Danh sách PHẢI dễ mở rộng (data-driven, không hard-code logic riêng cho từng path trừ trường hợp đặc biệt). | M |
| FR-EXP-02 | Trước khi kiểm tra danh sách path, tool PHẢI gửi 1 request "probe" tới một path chắc chắn không tồn tại (ví dụ chuỗi ngẫu nhiên cố định) để phát hiện **soft-404** (server trả 200 cho path không tồn tại). | M |
| FR-EXP-03 | Nếu phát hiện soft-404, tool KHÔNG được tạo finding lộ file dựa trên riêng mã trạng thái 200 (tránh false positive hàng loạt). | M |
| FR-EXP-04 | Nếu không có soft-404 và path trong danh sách trả về HTTP 200, PHẢI tạo finding tương ứng với severity đã khai báo, category `A01:2021 - Broken Access Control`, evidence gồm mã trạng thái và URL đầy đủ. | M |
| FR-EXP-05 | Các request kiểm tra path PHẢI được gửi song song có giới hạn (thread pool), số luồng tối đa lấy từ `--workers` (mặc định 5), để không gây tải bất thường lên target. | M |
| FR-EXP-06 | Path `.well-known/security.txt` PHẢI được xử lý riêng: nếu tồn tại (200), tạo finding mức INFO mang tính **tích cực** (thông báo tốt), KHÔNG tính là lỗ hổng. | S |
| FR-EXP-07 | Tool PHẢI kiểm tra directory listing tại một tập thư mục phổ biến (mặc định: `images/`, `uploads/`, `backup/`, `files/`, `assets/`, `static/`). Nếu response 200 và nội dung (tối đa 2000 ký tự đầu) chứa dấu hiệu listing (`Index of /`, `<title>Index of`, `Directory Listing For`), PHẢI tạo finding `EXPOSURE-DIR-LISTING` mức MEDIUM, category A05:2021. | M |
| FR-EXP-08a | Tool PHẢI tải `robots.txt` (nếu có), trích các dòng có tiền tố `Disallow:` (đúng cú pháp Robots Exclusion Protocol), và lọc ra path có chứa từ khoá nhạy cảm (`admin`, `backup`, `config`, `internal`, `private`, `secret`, `staging`, `test` — không phân biệt hoa/thường). Nếu có ít nhất 1 path khớp, PHẢI tạo finding `EXPOSURE-ROBOTS-HINTS` mức LOW, category A01:2021, evidence là tối đa 10 path đầu tiên khớp. | S |
| FR-EXP-08b | Tool PHẢI tải `sitemap.xml` (nếu có) và trích nội dung các thẻ `<loc>...</loc>` (đúng định dạng chuẩn Sitemap XML — **không** áp dụng cú pháp `Disallow:` của robots.txt lên file này, đây là lỗi đã sửa so với bản 1.0). Với mỗi URL trích được, lấy phần path và so khớp với cùng danh sách từ khoá nhạy cảm ở FR-EXP-08a. Nếu có ít nhất 1 URL khớp, PHẢI tạo finding `EXPOSURE-SITEMAP-HINTS` mức LOW, category A01:2021, evidence là tối đa 10 URL đầu tiên khớp. | S |

**Bảng 4.8.1 — Danh sách path nhạy cảm mặc định:**

`Finding.id` PHẢI là giá trị khai báo tường minh gắn với từng path (không được suy ra bằng biến đổi chuỗi từ path tại runtime, để tránh rủi ro 2 path khác nhau vô tình sinh cùng 1 id).

| Path | `Finding.id` | Severity |
|---|---|---|
| `.git/HEAD` | `EXPOSURE-GIT-HEAD` | CRITICAL |
| `.git/config` | `EXPOSURE-GIT-CONFIG` | CRITICAL |
| `.env` | `EXPOSURE-ENV` | CRITICAL |
| `.env.local` | `EXPOSURE-ENV-LOCAL` | CRITICAL |
| `.env.production` | `EXPOSURE-ENV-PRODUCTION` | CRITICAL |
| `wp-config.php.bak` | `EXPOSURE-WP-CONFIG-BAK` | CRITICAL |
| `config.php.bak` | `EXPOSURE-CONFIG-PHP-BAK` | CRITICAL |
| `backup.sql` | `EXPOSURE-BACKUP-SQL` | CRITICAL |
| `id_rsa` | `EXPOSURE-ID-RSA` | CRITICAL |
| `.svn/entries` | `EXPOSURE-SVN-ENTRIES` | HIGH |
| `docker-compose.yml` | `EXPOSURE-DOCKER-COMPOSE` | HIGH |
| `backup.zip` | `EXPOSURE-BACKUP-ZIP` | HIGH |
| `web.config` | `EXPOSURE-WEB-CONFIG` | MEDIUM |
| `phpinfo.php` | `EXPOSURE-PHPINFO` | MEDIUM |
| `server-status` | `EXPOSURE-SERVER-STATUS` | MEDIUM |
| `.DS_Store` | `EXPOSURE-DS-STORE` | LOW |
| `.well-known/security.txt` | `EXPOSURE-SECURITY-TXT` | INFO (xử lý riêng, xem FR-EXP-06) |

### 4.9 Nhóm báo cáo kết quả (`report.py`)

| ID | Yêu cầu | Priority |
|---|---|---|
| FR-REPORT-01 | Tool PHẢI in ra terminal: tên target, thời điểm bắt đầu/kết thúc (UTC, ISO 8601), danh sách các nhóm check đã chạy, bảng tổng hợp số lượng finding theo từng severity, và chi tiết từng finding (severity, title, OWASP category, description, evidence nếu có, recommendation nếu có, URL). | M |
| FR-REPORT-02 | Danh sách finding trong output CLI và JSON PHẢI được sắp xếp theo mức độ nghiêm trọng giảm dần: CRITICAL → HIGH → MEDIUM → LOW → INFO. | M |
| FR-REPORT-03 | Với tham số `--no-color`, output CLI KHÔNG được chứa mã màu ANSI (phục vụ ghi log file/CI không hỗ trợ màu). | M |
| FR-REPORT-04 | Với tham số `--json PATH`, tool PHẢI ghi ra file JSON hợp lệ theo schema ở mục 6.2, encoding UTF-8, `ensure_ascii=False` (giữ nguyên tiếng Việt/ký tự Unicode nếu có trong evidence). | M |
| FR-REPORT-05 | Nếu quá trình quét có lỗi không nghiêm trọng (non-fatal, ví dụ 1 check bị timeout riêng lẻ), tool PHẢI vẫn hoàn tất các check còn lại và liệt kê lỗi trong mục `errors` của báo cáo, KHÔNG được làm dừng toàn bộ tiến trình quét. | M |

---

## 5. Yêu cầu phi chức năng (Non-Functional Requirements)

| ID | Nhóm | Yêu cầu |
|---|---|---|
| NFR-SEC-01 | Bảo mật/đạo đức | Tool TUYỆT ĐỐI KHÔNG được gửi bất kỳ payload khai thác nào (SQLi, XSS thật, command injection, path traversal thật, brute-force). Mọi request đều là GET tiêu chuẩn, không sửa đổi dữ liệu phía target. |
| NFR-SEC-02 | Bảo mật/đạo đức | Tool PHẢI có bước xác nhận quyền quét (FR-CONSENT-*) không thể tắt hoàn toàn bằng cấu hình mặc định — chỉ bỏ qua được bằng cờ tường minh `--yes`. |
| NFR-SEC-03 | Bảo mật/đạo đức | Mọi request PHẢI gửi kèm `User-Agent` nhận diện rõ ràng là scanner (không giả mạo trình duyệt thật), để hệ thống đích/WAF có thể nhận diện và log lại nguồn quét. |
| NFR-PERF-01 | Hiệu năng | Mỗi request PHẢI có timeout cấu hình được (mặc định 10 giây), không được treo vô hạn. |
| NFR-PERF-02 | Hiệu năng | Số luồng song song khi kiểm tra danh sách path nhạy cảm PHẢI giới hạn qua `--workers` (mặc định 5) để tránh trở thành công cụ DoS ngoài ý muốn. |
| NFR-PERF-03 | Hiệu năng | Tool KHÔNG được tự động retry ồ ạt khi target trả lỗi HTTP (4xx/5xx là tín hiệu, không phải lỗi mạng cần retry); chỉ retry ở tầng kết nối mạng, tối đa 1 lần. |
| NFR-REL-01 | Độ tin cậy | Một check thất bại (timeout, lỗi parse) KHÔNG được làm crash toàn bộ tiến trình quét; lỗi phải được bắt và ghi nhận riêng. |
| NFR-REL-02 | Độ tin cậy | Tool PHẢI xử lý được trường hợp target không phản hồi từ bước đầu tiên (baseline fetch) mà không ném exception ra ngoài. |
| NFR-USA-01 | Khả dụng | Output CLI PHẢI dễ đọc: có phân cách rõ ràng, có bảng tổng hợp số lượng theo severity ở đầu báo cáo trước khi liệt kê chi tiết. |
| NFR-USA-02 | Khả dụng | Mọi finding PHẢI có khuyến nghị khắc phục (recommendation) khi khả thi — không chỉ báo "có vấn đề" mà không nói cách sửa. |
| NFR-PORT-01 | Khả chuyển | Tool PHẢI chạy được trên Python ≥ 3.9, hệ điều hành Linux/macOS/Windows (không phụ thuộc thư viện chỉ có trên 1 OS). |
| NFR-MAINT-01 | Bảo trì | Mỗi nhóm check PHẢI nằm trong module riêng, có thể unit test độc lập mà không cần gọi mạng thật (nhận input là response/headers đã có sẵn, hoặc dùng session giả lập). |
| NFR-MAINT-02 | Bảo trì | Danh sách header bắt buộc (4.3) và path nhạy cảm (4.8.1) PHẢI là cấu trúc dữ liệu khai báo (dict/list ở đầu file), không hard-code rải rác trong logic, để dễ thêm/bớt. |
| NFR-COMP-01 | Tuân thủ | README/tài liệu đi kèm PHẢI nêu rõ giới hạn phạm vi (không phải DAST toàn diện) để tránh khách hàng/nội bộ hiểu nhầm mức độ đảm bảo. |

---

## 6. Đặc tả dữ liệu (Data Model)

### 6.1 Các kiểu dữ liệu lõi

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
    id: str                  # mã ổn định, VD "HDR-CSP-UNSAFE"
    title: str
    severity: Severity
    owasp_category: str      # VD "A05:2021 - Security Misconfiguration"
    description: str
    evidence: str = ""
    recommendation: str = ""
    url: str = ""

@dataclass
class ScanResult:
    target: str
    started_at: str          # ISO 8601 UTC
    finished_at: str = ""
    findings: list[Finding] = field(default_factory=list)
    checks_run: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
```

**Quy tắc bắt buộc:**

- `Finding.id` PHẢI là mã định danh ổn định (không đổi giữa các lần chạy cho cùng loại lỗi), dùng để dedupe/diff giữa các lần quét khi tích hợp CI.
- `ScanResult.findings` khi xuất ra (CLI/JSON) PHẢI được sắp xếp theo `severity.rank` tăng dần (CRITICAL trước).

### 6.2 JSON Schema (mô tả phi hình thức)

```json
{
  "target": "https://example.com/",
  "started_at": "2026-09-22T08:26:08.822920Z",
  "finished_at": "2026-09-22T08:26:09.273000Z",
  "checks_run": ["security-headers", "cookies", "tls", "http-to-https-redirect", "cors", "sensitive-paths", "directory-listing", "robots-sitemap"],
  "summary": { "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0 },
  "findings": [
    {
      "id": "EXPOSURE-ENV",
      "title": "Exposed .env file (often contains secrets)",
      "severity": "CRITICAL",
      "owasp_category": "A01:2021 - Broken Access Control",
      "description": "GET .env returned HTTP 200, suggesting the file/path is publicly accessible.",
      "evidence": "HTTP 200 for https://example.com/.env",
      "recommendation": "Remove the file from the web root or block access at the web server/proxy layer.",
      "url": "https://example.com/.env"
    }
  ],
  "errors": []
}
```

Đây là JSON thực tế lấy từ lần chạy kiểm thử của tool (đã xác minh bằng mock server nội bộ trong quá trình phát triển) — không phải dữ liệu suy đoán.

---

## 7. Đặc tả giao diện dòng lệnh (CLI Interface)

### 7.1 Cú pháp

```
python -m owasp_scanner <target> [--json PATH] [--timeout N] [--workers N] [--no-color] [--yes]
```

### 7.2 Bảng tham số

| Tham số | Bắt buộc | Mặc định | Mô tả |
|---|---|---|---|
| `target` | Có | — | URL hoặc hostname cần quét. Nếu thiếu scheme, tự thêm `https://`. |
| `--json PATH` | Không | (không xuất) | Đường dẫn file JSON để ghi báo cáo đầy đủ. |
| `--timeout N` | Không | `10` | Timeout mỗi request (giây). |
| `--workers N` | Không | `5` | Số luồng song song khi kiểm tra path nhạy cảm. |
| `--no-color` | Không | tắt (có màu) | Tắt mã màu ANSI trong output CLI. |
| `--yes` / `--i-have-authorization` | Không | tắt | Bỏ qua bước hỏi xác nhận quyền quét tương tác. |

### 7.3 Exit code

| Code | Ý nghĩa |
|---|---|
| `0` | Quét thành công, không có finding CRITICAL/HIGH. |
| `1` | Quét thành công, có ít nhất 1 finding CRITICAL hoặc HIGH (dùng để gate CI/CD). |
| `2` | Người dùng không xác nhận quyền quét — không có request nào được gửi. |

---

## 8. Ma trận truy vết OWASP (Traceability Matrix)

| Nhóm check | FR liên quan | OWASP Top 10:2021 | OWASP Secure Headers / ASVS |
|---|---|---|---|
| Security headers | FR-HDR-01 … FR-HDR-10 | A02, A03, A05 | Secure Headers Project |
| Cookies | FR-COOKIE-01 … FR-COOKIE-04 | A05 (liên quan A07) | ASVS V3 (Session Management) |
| TLS/Certificate | FR-TLS-01 … FR-TLS-09 | A02 | ASVS V9 (Communications) |
| HTTP→HTTPS redirect | FR-REDIR-01 … FR-REDIR-03 | A02 | ASVS V9 |
| CORS | FR-CORS-01 … FR-CORS-04 | A05 (liên quan A01) | — |
| File/path lộ | FR-EXP-01 … FR-EXP-06 | A01 | — |
| Directory listing | FR-EXP-07 | A05 | ASVS V14 (Configuration) |
| robots.txt | FR-EXP-08a | A01 | — |
| sitemap.xml | FR-EXP-08b | A01 | — |

**Lưu ý phạm vi:** các hạng mục A04 (Insecure Design), A06 (Vulnerable Components — chỉ fingerprint gián tiếp qua header, chưa đối chiếu CVE), A08, A09, A10 của OWASP Top 10:2021 **không** được kiểm tra đầy đủ bởi bản đặc tả này vì cần phân tích chủ động/mã nguồn/log — xem mục 11 (roadmap).

---

## 9. Kịch bản kiểm thử chấp nhận (Acceptance Test Scenarios)

Khuyến nghị dùng một **mock HTTP server nội bộ** (không cần internet) để test độc lập, tương tự cách tool gốc đã được xác minh trong quá trình xây dựng.

| ID | Kịch bản | Input | Kết quả mong đợi |
|---|---|---|---|
| AT-01 | Từ chối quét khi chưa xác nhận | Chạy tool, trả lời `no` ở prompt consent | Không có request nào gửi tới target; exit code `2` |
| AT-02 | Bỏ qua consent bằng `--yes` | `--yes` | Không hiện prompt chờ input; quét chạy bình thường |
| AT-03 | Thiếu toàn bộ security headers | Server trả response không có CSP/HSTS/X-Frame-Options/... | Có đủ finding tương ứng FR-HDR-01…07, đúng severity |
| AT-04 | Cookie thiếu cờ | `Set-Cookie: session=abc123; Path=/` | Finding MEDIUM liệt kê thiếu Secure, HttpOnly, SameSite |
| AT-05 | Lộ `.env` và `.git/HEAD` | Mock server trả 200 cho 2 path này | 2 finding CRITICAL, category A01:2021 |
| AT-06 | Soft-404 không gây false positive | Mock server trả 200 cho MỌI path (kể cả path ngẫu nhiên) | KHÔNG có finding lộ file nào được tạo (đã phát hiện soft-404) |
| AT-07 | Directory listing | `/images/` trả HTML chứa `Index of /images/` | Finding MEDIUM `EXPOSURE-DIR-LISTING` |
| AT-08 | robots.txt tiết lộ path nhạy cảm | `Disallow: /admin/`, `Disallow: /backup/` | Finding LOW liệt kê 2 path trên |
| AT-09 | CORS phản xạ origin tuỳ ý + credentials | Server echo lại `Origin` gửi lên và `Access-Control-Allow-Credentials: true` | Finding HIGH `CORS-REFLECTS-ARBITRARY-ORIGIN` |
| AT-10 | Chứng chỉ TLS hết hạn | Target HTTPS có cert tự ký hết hạn (đã kiểm thử thật với cert hết hạn từ 2020) | Đúng 1 finding CRITICAL `TLS-CERT-EXPIRED`; KHÔNG có `TLS-CERT-NOT-TRUSTED` trùng lặp (Bước B bị bỏ qua theo FR-TLS-09); check giao thức/cipher yếu (FR-TLS-03/04) vẫn chạy bình thường nếu áp dụng được |
| AT-11 | Target không phản hồi | DNS sai / server down | `errors` chứa 1 dòng mô tả lỗi; tool không crash; báo cáo vẫn in được (0 finding) |
| AT-12 | Xuất JSON hợp lệ | `--json out.json` | File tồn tại, parse được bằng `json.load`, đủ các khoá ở mục 6.2 |
| AT-13 | Exit code phản ánh mức độ | Có ít nhất 1 CRITICAL | Exit code `1` |
| AT-14 | Không màu khi `--no-color` | `--no-color` | Output không chứa ký tự escape ANSI (`\x1b[`) |
| AT-15 | Chứng chỉ tự ký còn hạn nhưng không được tin cậy | Target HTTPS có cert tự ký, còn hiệu lực thời gian, không phải CA hệ thống (đã kiểm thử thật) | Đúng 1 finding CRITICAL `TLS-CERT-NOT-TRUSTED`; KHÔNG có finding hết hạn/chưa-hiệu-lực nào (phân biệt rõ với AT-10) |
| AT-16 | HSTS không bị yêu cầu trên target `http://` | Quét `http://example.local/` (không phải https) | KHÔNG có finding `HDR-STRICT-TRANSPORT-SECURITY-MISSING`; khi quét lại đúng site đó qua `https://`, finding này xuất hiện bình thường nếu vẫn thiếu header |
| AT-17 | X-Frame-Options bị bỏ qua khi đã có frame-ancestors | Response có `Content-Security-Policy: frame-ancestors 'none'`, không có header `X-Frame-Options` | KHÔNG có finding nào liên quan X-Frame-Options (không "missing", không "weak") |
| AT-18 | sitemap.xml dùng đúng cú pháp `<loc>` | `sitemap.xml` chứa `<loc>https://.../staging/internal-tool</loc>` | Finding LOW `EXPOSURE-SITEMAP-HINTS`, evidence chứa URL trên (đã kiểm thử thật, không chỉ suy đoán) |

---

## 10. Rủi ro và hạn chế đã biết

- **Không phải DAST toàn diện:** không phát hiện injection thật (SQLi/XSS cần gửi payload thật để xác nhận), broken authentication ở tầng logic, IDOR, SSRF, business logic flaw.
- **Chỉ quét 1 trang** (trang chủ) cho phần lớn check; không crawl các trang con — có thể bỏ sót header/cookie cấu hình khác nhau giữa các route.
- **Có thể có false positive** ở check robots.txt (một path "nghe có vẻ nhạy cảm" trong Disallow không đồng nghĩa nó thực sự lộ hoặc thực sự tồn tại).
- **Có thể có false negative** nếu target dùng CDN/WAF chặn hoặc trả response khác cho traffic có `User-Agent` là scanner.
- **TLS check dùng CA hệ thống của máy chạy tool** — môi trường CI dùng CA bundle tuỳ chỉnh (như proxy nội bộ) có thể cần cấu hình thêm để tránh false positive ở FR-TLS-08.
- **TLS check mở 2 kết nối** tới target thay vì 1 (Bước A + Bước B khi áp dụng, xem mục 4.5) — tăng nhẹ độ trễ và số lượng kết nối tới target so với bản 1.0; chấp nhận được vì vẫn chỉ là GET/handshake thông thường, không lặp lại nhiều lần.
- **`TLS-CERT-NOT-TRUSTED` gộp chung nhiều nguyên nhân khác nhau** (self-signed, thiếu chain trung gian, sai hostname, CA lạ) vào 1 mã finding — đủ để cảnh báo nhưng chưa phân loại nguyên nhân cụ thể; có thể cải thiện bằng cách phân tích message lỗi hoặc parse chain chi tiết hơn ở giai đoạn sau (xem mục 11).
- **FR-CORS-02 (severity CRITICAL cho wildcard+credentials) đã được chủ SRS xác nhận giữ nguyên** ngày 2026-09-23 (xem mục 0, dòng #8) — nêu ở đây để người đọc hiểu đây là severity phản ánh mức độ "cần rà soát ngay", không phải mức độ "khai thác được trực tiếp qua trình duyệt".

---

## 11. Lộ trình mở rộng (đề xuất, ngoài phạm vi v1.0)

| Đề xuất | Mô tả ngắn | Ưu tiên đề xuất |
|---|---|---|
| Active-scan nhẹ | Crawl link nội bộ giới hạn độ sâu, kiểm tra form login (HTTPS, autocomplete), phát hiện open redirect — cần mở rộng bước consent để nêu rõ phạm vi active hơn | Trung bình |
| Báo cáo HTML | Xuất báo cáo trực quan cho khách hàng, dựa trên cùng JSON schema ở mục 6.2 | Trung bình |
| Multi-target | Quét danh sách nhiều URL trong 1 lần chạy, gộp báo cáo | Thấp |
| Fingerprint & CVE lookup (A06) | Nhận diện phiên bản thư viện/CMS qua header/HTML, đối chiếu CSDL CVE công khai | Thấp |
| Tích hợp CI/CD mẫu | Cung cấp sẵn GitHub Actions/GitLab CI job mẫu dùng exit code (FR-CLI-04) để gate pipeline | Cao (dễ làm, giá trị cao) |

---

*Tài liệu này mô tả đúng hành vi của mã nguồn `owasp_scanner` (v1.1.0) đã được xây dựng và kiểm thử end-to-end — bao gồm cả kiểm thử TLS thật với chứng chỉ hết hạn và chứng chỉ tự ký không được tin cậy (không chỉ mock HTTP thông thường). Mã nguồn được đóng gói cùng tài liệu này trong `owasp-scanner.zip` làm baseline duy nhất. Toàn bộ 8 điểm review trên bản 1.0 đã được xử lý và xác nhận (xem mục 0). Khi code trong VS Code thay đổi, cập nhật lại các mục FR/NFR tương ứng để tài liệu và mã nguồn không lệch nhau.*
