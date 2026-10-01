# Phase B – Bổ sung chức năng so với tool thương mại có trả phí

| | |
|---|---|
| **Tài liệu** | Lộ trình sprint cho Phase B |
| **Ngày** | 2026-10-01 (bản đầu: 2026-09-30) |
| **Trạng thái** | Bản nháp, chờ chủ sản phẩm duyệt thứ tự và các điểm `[CONFIRM]`. Cập nhật 2026-10-01 theo thực tế sau Sprint 9 và Sprint 10: **đánh số sprint lùi 1** kể từ "Kiểm soát quét an toàn", vì Sprint 10 thực tế đã làm phần điểm số và báo cáo (vốn xếp ở Sprint 14/18 của bản đầu). Khối lượng công việc còn lại **không đổi**. |
| **Xuất phát điểm** | `websec_scanner` v1.13.0 (sau Sprint 10, branch `feat/sprint-10`); bản đầu viết trên `owasp_scanner` v1.7.0 |
| **Tài liệu liên quan** | `docs/PRODUCT-BACKLOG.md` (ID FR, mục 2, 9.2, Phụ lục A) · `docs/SRS-websec-scanner.md` · `CLAUDE.md` |

Ký hiệu: `[FACT]` đã kiểm chứng trong repo · `[ASSUMPTION]` giả định của đội ngũ phát triển · `[REC]` khuyến nghị · `[CONFIRM]` cần người có thẩm quyền quyết định.

---

## 1. Mục tiêu và phạm vi

**Mục tiêu** `[REC]`: từ một scanner cấu hình chỉ xét trang chủ, trở thành **CLI bán được (MSP-1)** cho nhóm dev/SMB: quét web nhiều trang, API (OpenAPI) và có đăng nhập; kết quả theo dõi được qua nhiều lần quét; an toàn khi giao cho khách.

**Điều kiện hoàn thành Phase B** (theo backlog mục 9.2):

1. Quét được web nhiều trang, API (OpenAPI) và có xác thực đơn giản.
2. Xác minh sở hữu domain trước khi quét.
3. Benchmark trên app thử nghiệm chạy local, có số đo baseline.
4. Tài liệu người dùng và pháp lý (ToS/AUP) đã được duyệt.
5. Có khách thử nghiệm đầu tiên.

**Ngoài phạm vi Phase B:**
- Active checks (E9, payload khai thác): Phase D, cần review pháp lý/bảo mật; Claude không tự thêm (CLAUDE.md).
- Server, DB, queue, đa người dùng, thanh toán (E12–E18 phần SaaS): Phase C, chỉ khi đổi quyết định D1.
- Khám phá tài sản (E11), SSO/SCIM (E16).

**Giữ nguyên các nguyên tắc hiện có:** non-intrusive mặc định (chỉ GET/HEAD/OPTIONS), mọi evidence qua `redact()`, CLI và Web UI cùng JSON, dữ liệu khai báo thay vì hard-code, test offline bằng mock server/app local, không quét host thật.

## 2. So sánh với tool thương mại

`[ASSUMPTION]` Cột "Tool khác" giữ nguyên từ bảng so sánh nội bộ trước đó (đối chiếu với HostedScan, Pentest-Tools và các DAST phổ biến, tra cứu 2026-09-30 khi tool ở v1.0.0); **chưa kiểm tra lại với từng hãng**, cần xác minh trước khi dùng cho tài liệu bán hàng. Cột "v1.13.0" đối chiếu trực tiếp với code, test và SRS v1.15 ngày 2026-10-01.

### 2.1 Tóm tắt

| Trạng thái | v1.0.0 (lần so sánh trước) | v1.7.0 | v1.13.0 |
|---|---|---|---|
| Có | 1 | 2 | 2 |
| Một phần | 6 | 6 (nội dung đổi, số dòng giữ nguyên) | 6 (nội dung đổi, số dòng giữ nguyên) |
| Chưa có | 13 | 12 | 12 |
| Ngoài phạm vi (cố ý không làm) | 2 | 2 | 2 |

Sprint 9 và 10 làm sâu thêm các dòng "Một phần" (image Docker chính thức, báo cáo HTML đầy đủ, điểm CVSS ước tính, nhận diện cipher yếu) nhưng **không dòng nào đổi nhóm**, nên số lượng giữ nguyên.

### 2.2 Chức năng còn thiếu hoặc mới có một phần (ưu tiên bổ sung ở Phase B)

Đây là danh sách chính cho Phase B: mọi dòng "Chưa có" và "Một phần" của bảng so sánh, kèm hiện trạng cụ thể trong code và sprint sẽ xử lý.

| # | Chức năng | Trạng thái v1.13.0 | Hiện trạng cụ thể | Tool khác | FR liên quan | Sprint |
|---|---|---|---|---|---|---|
| 1 | Dò đủ phiên bản TLS và cipher, chấm điểm TLS | Một phần | Từ v1.6.0 phát hiện được server chỉ hỗ trợ TLS 1.0/1.1 (`TLS-WEAK-PROTOCOL`) và cảnh báo khi TLS bị phần mềm/proxy chặn ký lại (FR-DET-16). Từ v1.13.0 nhận diện cipher yếu đầy đủ theo bảng khai báo kèm lý do (FR-DET-17, trước đó bỏ lọt 3DES/DES/suite ẩn danh). Vẫn **chưa dò lần lượt** từng phiên bản/cipher server chấp nhận, chưa có điểm tổng kiểu SSL Labs | SSL Labs, Pentest-Tools | FR-DET-04, FR-DET-05 | 15 |
| 2 | Crawl nhiều trang, crawl SPA (JavaScript) | Chưa có | Mọi check vẫn chỉ chạy trên trang chủ (baseline) đã fetch; không có crawler | ZAP (spider, AJAX spider), Acunetix, Invicti | E6 (FR-CRAWL-01…07) | 14 (SPA: 21) |
| 3 | Quét chủ động: SQLi, XSS, SSRF, open redirect thật | Chưa có (cố ý) | Chỉ gửi GET/HEAD/OPTIONS, không có payload khai thác; đây là định vị non-intrusive của sản phẩm, không phải thiếu sót | ZAP, Burp, Acunetix, Invicti, Pentest-Tools | E9 (FR-ACTIVE-01…09) | Phase D, ngoài Phase B |
| 4 | Quét sau khi đăng nhập | Chưa có | Không có auth profile, không giữ session, không có form login | Hầu hết tool trả phí (HostedScan từ gói Premium) | E8 (FR-AUTH-01, 03, 04, 08) | 16 |
| 5 | Quét API (OpenAPI, Postman, GraphQL) | Chưa có | Không nạp được spec API; mọi check chạy trên response HTML của trang chủ | Pentest-Tools, Invicti, StackHawk, ZAP | E7 (FR-API-01…11) | 17 |
| 6 | Nhận diện công nghệ và đối chiếu CVE | Chưa có | Chỉ báo lộ phiên bản qua header (`HDR-INFO-SERVER`, `HDR-INFO-X-POWERED-BY`); không có fingerprint công nghệ, không đối chiếu NVD/OSV/KEV | Nuclei (hàng nghìn template), Pentest-Tools, Acunetix | E10 (FR-CVE-01…04) | 18 |
| 7 | Quét lỗ hổng riêng của CMS (WordPress, Joomla...) | Chưa có | Gần với FR-CVE nhưng là plugin/theme signature riêng cho từng CMS. **Duyệt bởi chủ sản phẩm 2026-09-30**: phải là một test target chọn được trên CLI/Web UI, giống 8 nhóm hiện có (Sprint 8) | Pentest-Tools, WPScan | E10 (FR-CVE-05) | 18 |
| 8 | Xác nhận lỗ hổng để giảm báo sai (benchmark, proof-based) | Một phần | Có kiểm tra nội dung file khớp chữ ký (FR-DET-01), soft-404 theo vân tay (FR-DET-02), `confidence` theo từng loại finding, golden file. Chưa có benchmark đo precision/recall, chưa có xác minh lại bằng chứng như Invicti (proof-based) | Invicti (proof-based), Pentest-Tools (ML) | FR-QA-03, FR-QA-04 | 14 (baseline), 20 (so sánh) |
| 9 | Khám phá subdomain và tài sản | Chưa có | Chỉ quét đúng target được chỉ định, không tự tìm subdomain | HostedScan, Pentest-Tools, Detectify | E11 (FR-ASSET-01…04) | Ngoài Phase B |
| 10 | Lịch quét, lịch sử, so sánh giữa các lần quét | Chưa có | Web UI chỉ giữ 20 báo cáo gần nhất trong bộ nhớ, mất khi tắt server; không có lịch chạy định kỳ. Đã có nền sẵn: `fingerprint` ổn định qua các lần quét | HostedScan, Pentest-Tools, Detectify | FR-RPT-06 (so sánh); E13 (lịch sử, chỉ khi SaaS) | 12 (so sánh 2 lần); E13 ở Phase C |
| 11 | Quản lý finding (false positive, chấp nhận rủi ro) | Chưa có | Không có trạng thái finding qua các lần quét; mỗi lần quét độc lập | Hầu hết tool trả phí | FR-MODEL-06 (suppression file); E14 (Phase C) | 12 |
| 12 | Báo cáo PDF, logo khách, mẫu báo cáo pentest | Một phần | HTML độc lập (embedded CSS, không script) có tóm tắt theo test target và theo OWASP Top 10 (từ v1.7.0); từ v1.13.0 có đủ tóm tắt điều hành: Top issues, điểm CVSS ước tính và dòng cách tái hiện cho từng finding (FR-RPT-01, FR-MODEL-03 — **xong ở Sprint 10**). Chưa có PDF, chưa có logo tùy biến, chưa có mẫu executive/technical riêng | HostedScan, Pentest-Tools (xuất DOCX) | FR-RPT-01, 04, 05 | 18 |
| 13 | SARIF, baseline, ngưỡng fail cho CI/CD | Một phần (gần đủ) | SARIF 2.1.0 (từ v1.13.0 `security-severity` lấy theo điểm CVSS, FR-RPT-10), `--fail-on`, exit code 3 khi quét không hoàn tất, `--ca-bundle`, 4 template CI, image Docker chính thức trên GHCR (xong ở Sprint 9). Còn thiếu `--baseline` (chỉ fail vì finding mới) | StackHawk, Snyk, ZAP | FR-CI-02 (baseline); FR-CI-04 (Docker) | 11 (baseline); 9 (Docker) |
| 14 | Jira, Slack, Teams, webhook, API thông báo | Chưa có | Không có tích hợp bên thứ ba nào | HostedScan, Pentest-Tools | E17 (Phase C) | Ngoài Phase B |
| 15 | Nhiều user, phân quyền, SSO, audit log | Chưa có | Web UI chạy một tiến trình cục bộ theo D1, không có khái niệm user | HostedScan (SSO ở gói Professional), Invicti | E16 (Phase C) | Ngoài Phase B |
| 16 | Ánh xạ tiêu chuẩn tuân thủ (PCI DSS, ISO 27001...) | Một phần | Mỗi finding có `owasp_category` (OWASP Top 10:2021), `cwe` và (từ v1.13.0) `cvss_vector`/`cvss_score` ước tính; xem theo nhóm OWASP Top 10 trong Web UI/HTML (từ v1.7.0). Chưa có ASVS, PCI DSS, ISO 27001, SOC 2 | Acunetix, Invicti | FR-MODEL-04, FR-RPT-07 | 19 |
| 17 | Xác minh quyền sở hữu domain | Một phần | Chỉ là xác nhận tự khai (checkbox CLI/Web UI "tôi có quyền quét"); không xác minh bằng DNS TXT hay file `/.well-known/`. Đã có scope guard: không theo redirect ra host ngoài phạm vi | Các SaaS thường bắt buộc xác minh | FR-AUTHZ-01 | 20 |
| 18 | Quét mạng nội bộ qua agent | Chưa có | Không có agent riêng; CLI/template CI có thể chạy trực tiếp trong mạng nội bộ của khách, thay thế được một phần nhu cầu này | HostedScan, Pentest-Tools (add-on) | Không có FR riêng — giải pháp thay thế: kênh cài đặt (Docker, S9) | xong ở Sprint 9 |

### 2.3 Đã có, không cần làm thêm ở Phase B

| Chức năng | v1.7.0 |
|---|---|
| Header, cookie, TLS cơ bản, CORS | Có: 8 nhóm kiểm thử chọn được (`--checks`), che secret trong mọi output (D2), scope guard chống redirect ra ngoài |
| Dò file lộ và kiểm tra nội dung file | Có: 17 path với chữ ký nội dung, soft-404 theo vân tay, `confidence`, giới hạn đọc 8 KiB, rules dạng JSON (không hard-code) |
| Quét mạng và cổng dịch vụ | Ngoài phạm vi — cố ý không làm, không phải DAST/network scanner |
| Kiểm thử thủ công (proxy, chặn và sửa request) | Ngoài phạm vi — khác phân khúc với Burp Suite |

## 3. Thứ tự ưu tiên và lý do

`[REC]` Thứ tự dựa trên **phụ thuộc kỹ thuật** trước, **giá trị cho khách** sau:

1. ~~**Đóng Phase A** (Sprint 9)~~ — **xong**: các P0 còn sót là điều kiện để giao bất kỳ bản nào cho khách.
2. ~~**Điểm số và báo cáo** (Sprint 10)~~ — **xong**, làm sớm hơn kế hoạch theo yêu cầu chủ sản phẩm (bản đầu xếp ở Sprint 14/18).
3. **An toàn khi quét rộng** (Sprint 11): rate limit và exclusion phải có **trước** crawler, API và quét có đăng nhập, vì các tính năng đó tăng số request và rủi ro chạm vào hành động nguy hiểm.
4. **CI với nợ cũ** (Sprint 12): rẻ, dùng lại `fingerprint` đã có, giá trị ngay cho khách dùng CI.
5. **File cấu hình** (Sprint 13): cần cho auth profile, exclusion, nhiều target.
6. **Crawler** (Sprint 14): mở rộng coverage từ trang chủ ra toàn site; bắt đầu benchmark.
7. **Chiều sâu check thụ động** (Sprint 15), **có đăng nhập** (Sprint 16), **API** (Sprint 17), **A06** (Sprint 18).
8. **Báo cáo bán được** (Sprint 19) và **đóng gói thương mại** (Sprint 20).

## 4. Sprint

Mỗi sprint theo quy trình của CLAUDE.md: lập kế hoạch → duyệt → test trước → code → cập nhật SRS/backlog cùng thay đổi → kiểm tra cuối (ruff, test trên Python 3.12 và 3.14, dependency tối thiểu, gitleaks, pip-audit) → push khi được duyệt. Definition of Done: backlog mục 0.4.

---

### Sprint 9 – Đóng Phase A (tiền đề giao cho khách) — ✅ XONG (v1.8.0)

**Mục tiêu:** không còn P0 của Phase A chặn việc giao bản CLI/Web UI.

| FR | P | Việc cần làm |
|---|---|---|
| FR-WEB-02 | P0 | Bind khác `127.0.0.1` phải qua cờ tường minh, in cảnh báo và **bắt buộc token truy cập**; test cho từng kiểm tra Host/Origin/Content-Type/kích thước body. |
| FR-RPT-08 | P0 | Mọi báo cáo (console, JSON, HTML, SARIF) có mục **phạm vi & giới hạn**; test chặn cụm từ đảm bảo tuyệt đối. |
| FR-SEC-10 | P0 | Kiểm kê license dependency và dữ liệu đi kèm → `THIRD_PARTY_LICENSES`; job CI kiểm tra license. |
| FR-CI-04 | P0 | Image Docker chính thức, user không phải root; template CI thêm cách chạy bằng Docker (sửa luôn vấn đề `apt-get` của template Jenkins). |
| FR-DOC-01 | P0 | Rà README toàn bộ trước phát hành. |

**Kết quả (2026-09-30):** đủ cả 5 FR. Web UI bind ra ngoài bắt buộc `--allow-remote` + access token; `output.SCOPE_NOTE` dùng chung cho console/HTML và từ v1.10.0 có trong JSON (`disclaimer`); `THIRD_PARTY_LICENSES.md` + test đối chiếu `pyproject.toml`; image Docker 2 giai đoạn chạy user không phải root, có job CI `docker` và `docker-publish`; README rà lại toàn bộ kèm 2 test chống lệch.
**Đã chốt:** image phát hành trên GHCR (`ghcr.io/hkbach/websec-scanner`), job `docker-publish` chỉ chạy khi push tag `v*`.

---

### Sprint 10 – Điểm số rủi ro và báo cáo đầy đủ — ✅ XONG (v1.13.0)

**Không có trong bản kế hoạch đầu**: chủ sản phẩm chọn làm phần điểm số và báo cáo trước (bản đầu xếp FR-RPT-01 và FR-MODEL-03 ở Sprint 18, FR-DET-17 chưa tồn tại). Vì vậy mọi sprint từ "Kiểm soát quét an toàn" trở đi **lùi một số**.

| FR | P | Đã làm |
|---|---|---|
| FR-MODEL-03 | P1 | Điểm CVSS v3.1 ước tính theo loại finding: `cvss.py` cài công thức base score chính thức, bảng vector khai báo trong `catalog.py`, `schema_version` 1.6. Đã qua một vòng review bảng vector (2026-10-01) và sửa theo. |
| FR-RPT-01 | P0 | Báo cáo HTML đầy đủ: Top issues, điểm rủi ro (dùng CVSS), dòng cách tái hiện cho từng finding. |
| FR-RPT-10 | P1 | **FR mới**: SARIF `security-severity` lấy theo `cvss_score`. |
| FR-DET-17 | P1 | **FR mới**: nhận diện cipher yếu theo bảng khai báo có lý do — bịt lỗ hổng cũ bỏ lọt 3DES (SWEET32), DES 56-bit, suite ẩn danh `ADH-`/`AECDH-`, RC2, IDEA. |
| SRS FR-UI-12 | — | Web UI hiện cùng điểm CVSS như console và báo cáo HTML. |

**Còn treo:** `[CONFIRM]` bảng vector CVSS cần **người làm bảo mật** rà lần cuối trước khi đưa số cho khách trả tiền (review 2026-10-01 là của chủ sản phẩm).
**Lưu ý khi phát hành:** SARIF đổi cách tính `security-severity` → GitHub code scanning sẽ xếp lại mức cảnh báo của finding cũ; và sẽ xuất hiện `TLS-WEAK-CIPHER` mới trên server còn dùng 3DES/DES/suite ẩn danh (lỗi bỏ lọt có từ trước).

---

### Sprint 11 – Kiểm soát quét an toàn

**Mục tiêu:** tool tự giới hạn tải và tránh vùng nguy hiểm trước khi mở rộng số request.

| FR | P | Việc cần làm |
|---|---|---|
| FR-AUTHZ-05 | P0 | `--rate-limit` (request/giây), `--max-requests`, `--max-duration`; tự giảm tốc khi gặp 429/503; áp dụng cho mọi request, kể cả TLS handshake. |
| FR-AUTHZ-06 | P1 | Exclusion theo path/regex/host (mặc định loại `/logout`, `/delete`, thanh toán…), dữ liệu khai báo. |
| FR-AUTHZ-03 | P0 | Phần còn lại: phạm vi khai báo nhiều host; cảnh báo redirect ra ngoài phạm vi trong UI. |
| FR-AUTHZ-09 | P1 | Header tùy chọn `X-Scanner-Scan-Id` để bên đích lọc log/WAF. |
| FR-QA-05 | P1 | Test chứng minh tool tuân thủ giới hạn tốc độ trên mock server (đếm request theo thời gian). |

**Xong khi:** test đo được tốc độ không vượt `--rate-limit`; đạt `--max-requests` thì dừng và báo `incomplete` rõ ràng; path bị exclusion không nhận request nào.
**Rủi ro:** thêm trường vào báo cáo (giới hạn đã áp dụng) → có thể nâng `schema_version`.

---

### Sprint 12 – CI với nợ cũ

**Mục tiêu:** khách bật gate CI mà không bị chặn vì finding đã biết.

| FR | P | Việc cần làm |
|---|---|---|
| FR-CI-02 | P0 | `--baseline FILE` (JSON của lần quét trước): gate chỉ tính finding **mới** theo `fingerprint`; báo cáo đánh dấu new/existing. |
| FR-MODEL-06 | P1 | `.scannerignore.yaml`: bỏ qua theo `id`/`fingerprint`/path, **bắt buộc lý do và ngày hết hạn**; finding bị bỏ qua vẫn liệt kê riêng. |
| FR-RPT-06 | P1 | Báo cáo so sánh hai lần quét: mới / đã sửa / còn tồn tại. |
| FR-RPT-03 | P1 | Xuất CSV và JUnit XML. |

**Xong khi:** baseline đúng với finding trùng fingerprint; suppression hết hạn thì finding quay lại; JUnit mở được trong GitLab/Azure/Jenkins (kiểm tra cấu trúc bằng test, chạy CI thật khi có repo mẫu).
**Phụ thuộc:** `fingerprint` ổn định (đã có, SRS FR-MODEL-01). Nếu parse YAML cần thư viện mới `[CONFIRM]` license (hoặc dùng JSON/TOML của stdlib).

---

### Sprint 13 – File cấu hình và tham số vận hành

**Mục tiêu:** một file cấu hình cho mọi tùy chọn; chạy nhiều target.

| FR | P | Việc cần làm |
|---|---|---|
| FR-CI-06 | P1 | `scanner.toml` (hoặc YAML, tùy quyết định ở Sprint 12): target, nhóm kiểm thử, exclusion, rate limit, ngưỡng fail, đường dẫn báo cáo; tham số CLI ghi đè. |
| FR-CI-05 | P1 | `--targets-file` và nhiều target một lần chạy, có giới hạn tuần tự/song song; báo cáo gộp hoặc mỗi target một file. |
| FR-CI-07 | P1 | `--proxy`, `--header K:V`, `--cookie`, `--user-agent`, `--version`, `--quiet`/`--verbose`. `--cookie`/`--header` phải qua `redact()`. |

**Xong khi:** mọi tùy chọn CLI có tương đương trong file; secret dạng plaintext trong file → cảnh báo (chuẩn bị cho Sprint 15).
**Lưu ý:** TLS check hiện kết nối trực tiếp, không qua proxy; cần quyết định hỗ trợ CONNECT proxy cho TLS hay ghi rõ giới hạn.

---

### Sprint 14 – Crawler nhiều trang

**Mục tiêu:** finding phản ánh toàn site, không chỉ trang chủ.

| FR | P | Việc cần làm |
|---|---|---|
| FR-CRAWL-01 | P0 | Crawler HTTP cùng origin: `max_depth`, `max_pages`, `max_duration`; tôn trọng scope, exclusion, rate limit. |
| FR-CRAWL-03 | P0 | Chạy check header/cookie/CORS trên nhiều route đại diện; gộp finding trùng theo `fingerprint`, ghi số URL bị ảnh hưởng. |
| FR-CRAWL-04 | P1 | Tùy chọn tôn trọng `robots.txt` (mặc định bật khi crawl). |
| FR-AUTHZ-02 | P0 | Consent theo mức: `config` (mặc định) / `crawl`; banner và xác nhận riêng cho `crawl`. |
| FR-QA-03 (bước 1) | P1 | Dựng benchmark trên app thử nghiệm **chạy local** (ví dụ OWASP Juice Shop), đo số đo baseline đầu tiên; lưu kết quả theo phiên bản. |

**Xong khi:** mock site nhiều trang có vòng lặp link: dừng đúng giới hạn, không ra ngoài scope; có số đo benchmark baseline (không đặt mục tiêu con số trước khi đo).
**Cần quyết định** `[CONFIRM]`: app benchmark nào (kiểm tra license từng dự án); chạy benchmark trong CI hay thủ công.
**Rủi ro:** schema thêm trường (URL bị ảnh hưởng) → nâng `schema_version`.

---

### Sprint 15 – Chiều sâu check thụ động

**Mục tiêu:** bắt kịp các check cấu hình mà tool trả phí và scanner miễn phí (SSL Labs, Observatory) có.

| FR | P | Việc cần làm |
|---|---|---|
| FR-DET-04 | P0 | Dò chủ động phiên bản TLS (TLS 1.0–1.3) và cipher server chấp nhận. `[CONFIRM]` có tính là non-intrusive không (chỉ handshake, nhưng thêm kết nối); OpenSSL 3 không còn SSLv3 nên có thể phải tự dựng ClientHello. |
| FR-DET-05 | P1 | TLS nâng cao: hostname mismatch, thiếu intermediate, khóa yếu, SHA-1, forward secrecy (tách `TLS-CERT-NOT-TRUSTED` theo nguyên nhân). |
| FR-DET-06, 07 | P1 | Chất lượng HSTS và CSP. |
| FR-DET-08, 09 | P1 | Cookie nâng cao (`__Host-`, `SameSite=None` thiếu `Secure`), CORS nâng cao (`null`, suffix match) theo D3. |
| FR-DET-10, 11 | P1 | `OPTIONS` quảng bá `TRACE`/`PUT`/`DELETE` (không thực thi); COOP/CORP/COEP, `Cache-Control` trang có cookie phiên. |
| FR-DET-12 | P1 | Mixed content, thiếu SRI cho script/link bên ngoài. |
| FR-DET-13 | P1 | Mở rộng danh sách path nhạy cảm (dạng dữ liệu, mỗi path có chữ ký nội dung). |

**Xong khi:** mỗi check mới có mock server đúng/sai, confidence phù hợp, có mặt trong `CHECK_GROUPS` và golden file.
**Có thể tách** thành 14a (TLS) và 14b (header/cookie/CORS/nội dung) nếu quá lớn.

---

### Sprint 16 – Quét có đăng nhập

**Mục tiêu:** kiểm tra phần site sau đăng nhập, không làm lộ credential.

| FR | P | Việc cần làm |
|---|---|---|
| FR-AUTH-01 | P0 | Auth profile trong file cấu hình: `bearer`, `api_key`, `basic`, `cookie`, `header`; giá trị lấy từ biến môi trường; secret không vào log, evidence, báo cáo. |
| FR-AUTH-03 | P1 | Form login theo kịch bản khai báo, giữ session cookie. |
| FR-AUTH-04 | P1 | Phát hiện mất phiên (redirect về login, 401) và đăng nhập lại. |
| FR-AUTH-08 | P1 | Exclusion mặc định cho hành động nguy hiểm khi đã đăng nhập (logout, xóa, thanh toán); khuyến nghị dùng staging. |

**Xong khi:** test quét toàn bộ output (console/JSON/HTML/SARIF/CSV, CLI và Web UI) và fail nếu còn credential mẫu; mock app có vùng cần đăng nhập được quét.
**Rủi ro:** Web UI có nhận credential không `[CONFIRM]`; nếu có, phải giữ quy tắc D2 và không lưu credential.

---

### Sprint 17 – Quét API

**Mục tiêu:** quét API theo tài liệu OpenAPI, ánh xạ OWASP API Security Top 10 (2023).

| FR | P | Việc cần làm |
|---|---|---|
| FR-API-01 | P0 | Nạp OpenAPI 3.x/Swagger 2.0 (file hoặc URL); Postman v2.1; GraphQL introspection nếu được phép. Parse lỗi → thông báo rõ. |
| FR-API-02 | P0 | Check không xâm lấn trên từng endpoint GET/HEAD/OPTIONS: header, CORS, `Content-Type`, lộ lỗi chi tiết. |
| FR-API-03 | P0 | Thiếu xác thực: endpoint mà spec yêu cầu auth trả 2xx khi không gửi credential (chỉ method an toàn). |
| FR-API-11 | P1 | Xác thực API bằng auth profile của Sprint 16. |
| FR-API-10 | P1 | Ánh xạ OWASP API Top 10 (2023) trong báo cáo. |
| FR-API-04, 05, 06 | P1 | Lộ dữ liệu quá mức (heuristic, confidence thấp), thiếu header rate limit, GraphQL introspection ở production. |

**Xong khi:** mock API có endpoint bảo vệ đúng/sai cho kết quả đúng; nhóm kiểm thử mới trong `CHECK_GROUPS`.
**Cần quyết định** `[CONFIRM]`: thư viện parse OpenAPI/YAML (license) hay tự parse JSON.

---

### Sprint 18 – Thành phần có lỗ hổng đã biết (OWASP A06)

| FR | P | Việc cần làm |
|---|---|---|
| FR-CVE-01 | P1 | Nhận diện công nghệ/phiên bản (header, meta generator, file tĩnh, thư viện JS), quy tắc dạng dữ liệu. |
| FR-CVE-02 | P1 | Đối chiếu với OSV/NVD và CISA KEV, hỗ trợ bản sao offline; finding ghi rõ phiên bản là **suy đoán**, không khẳng định "khai thác được". |
| FR-CVE-04 | P2 | JS library lỗi thời theo chữ ký dạng retire. |
| FR-CVE-05 | P2 | Chữ ký lỗ hổng riêng theo CMS phổ biến (WordPress, Joomla, Drupal): phiên bản plugin/theme lộ qua đường dẫn tĩnh, đối chiếu CSDL công khai của CMS đó (ví dụ WPScan Vulnerability Database). **Là một test target chọn được** trong `catalog.CHECK_GROUPS`, xuất hiện ở `--checks`/`--list-checks` và ở danh sách nhóm kiểm thử trên Web UI trước khi quét (giống 8 nhóm hiện có từ Sprint 8); không chọn thì không gửi request nào của nhóm này. |

**Cần quyết định** `[CONFIRM]`: điều khoản sử dụng dữ liệu NVD/OSV/KEV và CSDL lỗ hổng CMS; cách cập nhật dữ liệu khi chạy offline; tên nhóm hiển thị trên UI cho FR-CVE-05 (ví dụ `cms` — "CMS vulnerabilities").

---

### Sprint 19 – Báo cáo bán được và tuân thủ

| FR | P | Việc cần làm |
|---|---|---|
| ~~FR-RPT-01~~ | P0 | ~~HTML đầy đủ: tóm tắt điều hành, điểm rủi ro, top vấn đề, cách tái hiện.~~ **Xong ở Sprint 10.** |
| ~~FR-MODEL-03~~ | P1 | ~~Điểm CVSS ước tính (ghi rõ "estimated").~~ **Xong ở Sprint 10**; còn `[CONFIRM]` security review bảng vector. |
| FR-RPT-05 | P1 | Hai mẫu: Executive summary và Technical report. |
| FR-RPT-04 | P1 | PDF từ HTML, trang bìa, logo tùy biến. `[CONFIRM]` công cụ/thư viện PDF (license). |
| FR-MODEL-04 | P1 | Ánh xạ tuân thủ dạng dữ liệu: OWASP ASVS, API Top 10 trước; PCI DSS/ISO 27001 sau khi có người rà nội dung. |
| FR-DOC-04, FR-DOC-06 | P1 | Tài liệu người dùng; catalog check tự sinh từ rules. |

**Lưu ý:** ánh xạ tuân thủ phải có disclaimer, không nói "đạt chuẩn".

---

### Sprint 20 – Đóng gói thương mại và khách thử nghiệm

| FR | P | Việc cần làm |
|---|---|---|
| FR-AUTHZ-01 | P0 | Xác minh sở hữu domain (DNS TXT hoặc file `/.well-known/`); không xác minh được → không quét (trừ target local/đã cho phép tường minh). |
| E18 (FR-BILL-01 cho CLI) | P0 | License key/entitlement cho CLI: bật tắt tính năng theo gói, kiểm tra ở một điểm duy nhất. |
| FR-DOC-02 | P0 | ToS, AUP, chính sách quyền riêng tư: **pháp lý soạn và duyệt**. |
| FR-QA-03 (bước 2), FR-QA-04 | P1 | So sánh benchmark với baseline Sprint 14; quy trình corpus false positive từ khách thử nghiệm. |

**Cần quyết định** `[CONFIRM]`: mô hình gói và giá (backlog mục 2.2); cơ chế license key (offline hay có kiểm tra online); khách thử nghiệm đầu tiên.

---

### Sprint 21 (tùy chọn) – Crawl SPA và đăng nhập bằng trình duyệt

| FR | P | Việc cần làm |
|---|---|---|
| FR-CRAWL-02 | P1 | Crawler SPA bằng trình duyệt headless: route, form, XHR/fetch endpoint (chuyển sang danh sách API của Sprint 17). |
| FR-AUTH-06 | P1 | Đăng nhập SPA bằng trình duyệt headless. |

**Cần quyết định** `[CONFIRM]`: thêm dependency trình duyệt (ví dụ Playwright; kiểm tra license và kích thước image) hay chỉ hỗ trợ trong image Docker riêng. Chỉ làm nếu khách mục tiêu có nhiều SPA.

## 5. Quyết định cần chốt trước hoặc trong Phase B

| # | Câu hỏi | Cần trước sprint | Ghi chú |
|---|---|---|---|
| Q1 | Khách mục tiêu (dev/CI, SMB, doanh nghiệp tuân thủ)? | **quá hạn** (đặt ở Sprint 9) | Backlog mục 11, Q1; quyết định thứ tự Sprint 15–19. Vẫn chưa chốt |
| Q2 | Định dạng file cấu hình và suppression (TOML stdlib hay YAML cần thư viện)? | 12 | License nếu thêm thư viện |
| Q3 | Consent theo mức (`config`/`crawl`) áp dụng thế nào cho CI (`--yes`)? | 14 | FR-AUTHZ-02 |
| Q4 | Dò chủ động phiên bản TLS có nằm trong "non-intrusive"? | 15 | FR-DET-04 |
| Q5 | Web UI có nhận credential cho quét có đăng nhập? | 16 | D2, không lưu credential |
| Q6 | Thư viện OpenAPI/YAML, PDF, dữ liệu CVE: license và điều khoản | 17–19 | FR-SEC-10 |
| Q7 | Mô hình gói, giá, license key | 20 | Quyết định thương mại |
| Q8 | Có làm SPA headless (Sprint 21)? | 21 | Dependency lớn |
| Q9 | Ai rà bảng vector CVSS trước khi giao số cho khách trả tiền? | trước khi bán | `[CONFIRM]` còn lại của FR-MODEL-03 (Sprint 10) |

## 6. Rủi ro chính

| Rủi ro | Ảnh hưởng | Giảm thiểu |
|---|---|---|
| Crawler/API/có đăng nhập làm tăng tải và chạm hành động nguy hiểm | Ảnh hưởng hệ thống của khách, rủi ro pháp lý | Sprint 11 trước; exclusion mặc định; khuyến nghị staging |
| Lộ credential khi quét có đăng nhập | Mất niềm tin, vi phạm D2 | `redact()` cho mọi output, test quét toàn bộ output, secret từ biến môi trường |
| False positive tăng khi mở rộng check | Khách bỏ dùng | Benchmark từ Sprint 14, corpus false positive, hạ `confidence` khi không chắc |
| Schema JSON đổi nhiều lần | Công cụ của khách hỏng | Chỉ thêm trường, nâng `schema_version`, changelog. Đã dùng 3 lần sau bản đầu: 1.4 → 1.5 (`disclaimer`) → 1.6 (`cvss_vector`/`cvss_score`) |
| Dependency mới không phù hợp thương mại hóa | Không bán được | Kiểm tra license trước (FR-SEC-10, xong ở Sprint 9) |
| Hứa tính năng như DAST lớn | Kỳ vọng sai | Giữ định vị non-intrusive, ghi rõ giới hạn trong mọi báo cáo (FR-RPT-08) |

## 7. Việc còn treo từ Phase A

Không thuộc sprint nào ở trên, cần chủ repo làm:

- ~~Merge PR `feat/sprint-5` → `6` → `7` → `8`~~ — xong, đã vào `main` (kèm `feat/sprint-9` và `chore/rename-websec-scanner`).
- Mở và merge PR cho `feat/sprint-10` (đã push, CI xanh đủ 8 job).
- Tạo tag `v1.13.0` (template CI đang trỏ tới tag này). Tag `v*` cũng là thứ kích hoạt job `docker-publish`.
- Sau lần publish đầu: admin đặt visibility công khai cho package GHCR (README, mục Docker).
- Bật branch protection cho `main` với 8 check (README, mục "Branch protection for main"); sau đó tick FR-QA-07.
- Thu xếp **security review** bảng vector CVSS (`[CONFIRM]` của FR-MODEL-03, Sprint 10).
- Quyết định Q1 (khách mục tiêu) đang quá hạn và chi phối thứ tự Sprint 15–19.
