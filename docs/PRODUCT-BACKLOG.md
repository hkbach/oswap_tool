# PRODUCT BACKLOG – Commercial Web & API Security Scanner

> File này dùng làm **nguồn ngữ cảnh** khi vibe-code cùng Claude trong VS Code. Vị trí trong repo: `docs/PRODUCT-BACKLOG.md`; quy tắc làm việc nằm ở `CLAUDE.md` (thư mục gốc repo); đặc tả hiện trạng ở `docs/SRS-websec-scanner.md` (v1.2). **Phạm vi:** chỉ các chức năng lõi/backend/API còn thiếu để thương mại hóa; **không** gồm giao diện (UI) vì UI đã có sẵn.

| | |
|---|---|
| **Sản phẩm** | Web & API security scanner thương mại (tên tạm: *OWASP Scanner Pro* – chưa chốt) |
| **Phiên bản tài liệu** | 0.4 (đồng bộ với SRS v1.2; thêm D4, D5, FR-FIX-09/10/11; tick các FR đã xong; sửa giả định B1 ở FR-CI-10) |
| **Ngày** | 2026-09-30 |
| **Trạng thái** | Draft – cần review của người quyết định sản phẩm trước khi cam kết với khách hàng |

**Quy ước nhãn trong tài liệu (tách bạch sự thật, giả định, khuyến nghị):**

- `[FACT]` – lấy từ SRS v1.2 (đã đối chiếu code) hoặc từ nguồn đã dẫn.
- `[ASSUMPTION]` – giả định của đội ngũ phát triển, chưa được khách hàng/thị trường xác nhận.
- `[REC]` – khuyến nghị kỹ thuật/sản phẩm, có thể đổi khi có bằng chứng.
- `[CONFIRM]` – cần người có thẩm quyền xác nhận trước khi làm (pháp lý, thương mại, kiến trúc lớn).

**Ưu tiên:** `P0` = phải có trước khi thu tiền của khách đầu tiên · `P1` = cần để cạnh tranh · `P2` = khác biệt hóa / enterprise.
**Tier gợi ý** `[ASSUMPTION]`: `Free` · `Pro` · `Business` · `Enterprise` (chỉ là giả thuyết đóng gói, xem mục 2).

---

## 0. Cách dùng file này với Claude trong VS Code

### 0.1 Quy trình làm việc đề xuất

1. Chọn **một epic** (mục 5) hoặc một nhóm FR nhỏ. Không nhờ Claude "làm hết".
2. Nhờ Claude **lập kế hoạch trước** (liệt kê file sẽ sửa, rủi ro, test cần viết), bạn duyệt rồi mới cho code.
3. Code theo lát nhỏ, mỗi lát có test chạy được **không cần internet** (mock server, xem E21).
4. Chạy test + linter; xem diff; commit nhỏ, message tham chiếu ID (ví dụ `feat(FR-DET-01): validate .env content`).
5. Cập nhật SRS/backlog khi hành vi thay đổi (tài liệu và code không được lệch nhau).

### 0.2 `CLAUDE.md`

Quy tắc cho Claude nằm trong file riêng `CLAUDE.md` ở thư mục gốc repo (được giao kèm tài liệu này). Không lặp lại ở đây để tránh hai nơi lệch nhau.

### 0.3 Mẫu prompt

```text
@docs/PRODUCT-BACKLOG.md @docs/SRS-websec-scanner.md
Hãy đọc Sprint 4 ở mục 9.1 (FR-DET-01, FR-DET-03). Chưa viết code. Cho tôi: (1) các file sẽ sửa/tạo,
(2) cách kiểm chứng bằng mock server, (3) rủi ro false positive. Chờ tôi duyệt.
```

```text
Triển khai FR-DET-01 theo kế hoạch đã duyệt. Viết test trước (AT mới + unit test),
sau đó code. Không đổi hành vi các FR khác. Chạy test và báo kết quả.
```

### 0.4 Definition of Done (áp dụng cho mọi FR)

- [ ] Có test tự động (unit hoặc integration với mock server), chạy được offline.
- [ ] `ruff check` và `ruff format --check` sạch; toàn bộ `pytest` đạt.
- [ ] Acceptance criteria (AC) của FR đều được kiểm chứng.
- [ ] Không có secret/dữ liệu thật trong code, log, fixture, ví dụ.
- [ ] Finding mới có đủ trường bắt buộc và khuyến nghị khắc phục.
- [ ] Không làm hỏng exit code/JSON schema hiện có (hoặc đã nâng `schema_version` + ghi changelog).
- [ ] Tài liệu (SRS/backlog/README) đã cập nhật; có người review trước khi merge (AI-generated code không tự động được tin cậy).

---

## 1. Bối cảnh và baseline

### 1.1 Hiện trạng `[FACT – từ SRS v1.2, đã đối chiếu code v1.1.0 ngày 2026-09-30]`

- CLI Python `python -m websec_scanner <target>`; module: `cli.py`, `http_utils.py`, `models.py`, `report.py`, `checks/{headers,cookies,tls_check,redirect_check,cors_check,exposure}.py`.
- Chỉ gửi GET thông thường, không payload khai thác; quét **1 trang** (trang chủ) cho hầu hết check.
- Có consent gate (`--yes` để bỏ qua), exit code 0/1/2 (2 = không xác nhận quyền quét), JSON output có `summary`, `findings`, `errors`, `checks_run`.
- Mapping OWASP Top 10:2021 (chủ yếu A01, A02, A03, A05); mỗi finding có id ổn định, severity, evidence, recommendation.
- Đã có từ v1.1.0: TLS kiểm tra 2 bước (đọc hạn chứng chỉ độc lập với trust, `TLS-CERT-EXPIRED`/`TLS-CERT-NOT-YET-VALID`/`TLS-CERT-NOT-TRUSTED`); tách robots.txt và sitemap.xml; HSTS chỉ khi `https://`; `frame-ancestors` loại trừ X-Frame-Options; `Finding.id` khai báo tường minh cho từng path.
- Đã sửa sau v1.1.0 (SRS v1.2): baseline lỗi ở tầng TLS vẫn chạy nhóm TLS; một check lỗi không dừng cả lần quét; cookie ở các bước redirect cũng được kiểm tra; chuẩn hoá đúng `host:port`; soft-404 áp dụng cho cả `security.txt`.
- 110 test pytest chạy offline (mock HTTP/HTTPS, chứng chỉ tự sinh), đã chạy trên Python 3.12 và 3.14 (Windows). Chưa có lint và CI.
- **Web UI cục bộ** `[FACT – đã đối chiếu `web.py` ngày 2026-09-30; đặc tả ở SRS mục 3.3 và 4.10]`: `python -m websec_scanner.web` chạy `http.server` tại `127.0.0.1:8765` (`web.py`), phục vụ `static/{index.html,app.js,app.css}`. `POST /api/scan` với `{"target", "authorized": true}`; server kiểm tra Host/Origin, Content-Type, kích thước body, cờ authorized, URL target rồi gọi `run_scan(target, timeout, workers)` của `cli.py` **trong thread xử lý request**, mỗi lúc một lần quét. Trả JSON đúng SRS 6.2 + `gate_failed`, `report_id`, `report_url`. `GET /api/report/<id>.html` sinh HTML bằng `render_html()` từ báo cáo trong bộ nhớ (giữ 20 báo cáo gần nhất). UI và báo cáo dùng tiếng Anh.
- Hạn chế đã biết: không phải DAST; không crawl; không auth; không API; có thể false positive (robots, path 200) và false negative (WAF/CDN).

### 1.2 Vấn đề tồn đọng cần xử lý trước khi thương mại hóa `[FACT – rút ra từ review SRS]`

Đã xử lý (SRS v1.1/v1.2): lỗi tham chiếu tài liệu, TLS không đọc được hạn chứng chỉ khi trust lỗi, HSTS/`frame-ancestors`, sitemap dùng sai cú pháp, định vị "passive" trong SRS/README.

Còn tồn đọng (xem **E0**, **E1**, **E2**, **E8**): TLS chỉ xét giao thức được thương lượng (FR-DET-04); lộ file chỉ dựa trên HTTP 200 (FR-DET-01); CORS `*`+credentials cần hạ mức theo D3 (FR-FIX-07); `Finding.id` thiếu khoá theo vị trí (FR-MODEL-01); evidence in nguyên cookie (FR-AUTH-02); hai kho chứng chỉ khác nhau khiến không quét được HTTPS sau proxy (FR-CI-10); redirect check và HSTS xét sai URL (FR-FIX-09, FR-FIX-10); chữ "Passive" còn trong UI/CLI/báo cáo (FR-FIX-11).

### 1.3 Giả định và điểm cần xác nhận

| # | Nội dung | Nhãn |
|---|---|---|
| 1 | Mục tiêu là **thu phí** khách hàng; khách chính chưa xác định (SMB, doanh nghiệp cần tuân thủ, hay đội dev cần scan trong CI/CD). | `[CONFIRM]` |
| 2 | Hình thức phân phối: CLI/thư viện, SaaS, on-premise (Docker), hoặc kết hợp. Khuyến nghị bắt đầu bằng CLI + báo cáo + CI, sau đó thêm server. | `[CONFIRM]` |
| 3 | Yêu cầu dữ liệu không rời hệ thống khách (data residency) ở nhóm khách mục tiêu. | `[CONFIRM]` |
| 4 | Có dùng engine mã nguồn mở (ZAP, Nuclei, sslyze...) hay tự viết: cần kiểm tra license cho mục đích thương mại từng thành phần. | `[CONFIRM]` |
| 5 | Pháp lý: trách nhiệm khi scan nhầm/làm gián đoạn hệ thống khách, điều khoản dịch vụ, chính sách quyền riêng tư. | `[CONFIRM]` cần luật sư |
| 6 | Hóa đơn/thuế/thanh toán tại Việt Nam và quốc tế. | `[CONFIRM]` với tài chính/kế toán |
| 7 | UI hiện có là Web UI cục bộ, cùng tiến trình với scanner (xem D1). Đã chốt. | Đã chốt |

### 1.4 Quyết định đã chốt (2026-09-30)

| ID | Câu hỏi | Quyết định | Ảnh hưởng |
|---|---|---|---|
| **D1** | UI kết nối scanner thế nào? | Web UI cục bộ **chạy chung tiến trình**, gọi thẳng `run_scan()`; không có server/service riêng. | Không làm server/REST API/multi-tenant (E12 FR-PLAT-*, E16, E18 thanh toán online) ở giai đoạn này; thay bằng **E12a** (hoàn thiện Web UI cục bộ). E12 chỉ mở lại khi chọn bán dạng SaaS. CLI và Web UI phải cho ra **cùng** JSON (một nguồn sự thật: `run_scan()`). |
| **D2** | Giá trị cookie trong evidence | **Che mặc định**, có cờ debug tường minh `--show-secrets` **chỉ ở CLI**. | Thay FR-COOKIE-04 của SRS. Chi tiết ở FR-AUTH-02. Web UI không bao giờ bật được cờ này. |
| **D3** | Severity CORS | **Hạ theo khả năng khai thác**: `*`+credentials → MEDIUM; phản xạ origin + credentials → HIGH; phản xạ origin không credentials → MEDIUM; `*` đơn lẻ → INFO. | Thay FR-CORS-02 (CRITICAL→MEDIUM); FR-CORS-03/04 giữ mức nhưng ghi rõ lý do. Chi tiết ở FR-FIX-07. |
| **D4** | Phạm vi (scope) khi theo redirect | Chỉ theo redirect tới **cùng host**, hoặc host chỉ khác tiền tố `www.`. Ra ngoài phạm vi thì không gửi request tới host đó, dừng và ghi vào `errors`. Không dùng Public Suffix List. | Dùng cho FR-FIX-09, FR-FIX-10; là phần tối thiểu của FR-AUTHZ-03. |
| **D5** | Cookie xét trên response nào | **Cookie xét trên toàn chuỗi redirect** (giữ hành vi hiện có, vì session cookie hay được đặt trên response 302); header xét trên response cuối. | Dùng cho FR-FIX-10. |
| **D6** | Benchmark dùng app nào, chạy ở đâu? (Sprint 14) | Mock server + Juice Shop + VAmPI + badssl.com (tự host, ghim digest); crAPI để sau; DVWA tùy chọn. PR chỉ chạy mock; benchmark Docker chạy theo lịch + thủ công trước release. | Dùng cho FR-QA-03a..e. |
| **D7** | Dò chủ động phiên bản TLS còn "non-intrusive"? (Sprint 15) | **Có**, nếu chỉ dùng handshake chuẩn, số kết nối có giới hạn, không gửi bản tin dị dạng. Tự viết bộ dò, **không** dùng sslyze (AGPL-3.0) hay testssl.sh (GPL-2.0). | Dùng cho FR-DET-04a..e; cập nhật SRS mục 1.2/4.5/NFR-SEC-01. |
| **D8** | Web UI có nhận credential? (Sprint 16) | **Không.** Quét có đăng nhập chỉ ở CLI/CI; secret chỉ qua biến môi trường/config. | Dùng cho FR-WEB-07/08. |
| **D9** | Parse OpenAPI bằng thư viện hay tự viết? (Sprint 17) | PyYAML (`safe_load`) + `json` chuẩn + tự xử lý `$ref` nội bộ. Không dùng prance. Chặn `$ref` ra ngoài (URL, path tuyệt đối, `..`). | Dùng cho FR-API-01a..d. |
| **D10** | Điều khoản NVD/OSV/KEV? (Sprint 18) `[CONFIRM-LEGAL]` | Dùng được, kèm nghĩa vụ ghi chú/attribution; không nhúng API key NVD vào bản cài; loại nguồn OSV CC-BY-SA. | Dùng cho FR-CVE-05..10. |
| **D11** | Gói/giá, license key, khách thử nghiệm? (Sprint 20) `[CONFIRM]` + duyệt thương mại | 2 dòng sản phẩm; license file ký Ed25519 kiểm tra offline; token chỉ cho khách kích hoạt online; 3-5 khách thử nghiệm có ủy quyền bằng văn bản. | Dùng cho FR-BILL-05a..g, FR-DOC-07..09. |

D6-D11 chốt ngày 2026-10-04; chi tiết đầy đủ (bảng app/license, mẫu prompt, Definition of Done riêng) ở `docs/DECISIONS-S14-S20.md`. **Thứ tự thực hiện:** S16 → S14 → S15 → S17 → S18 → S20 (số sprint là nhãn chủ đề, không phải thứ tự chạy — xem mục 9.1).

---

## 2. Vì sao khách hàng trả tiền – định vị và đóng gói

### 2.1 Nguyên tắc `[REC]`

Khách không trả tiền cho việc "chạy scan"; họ trả tiền cho **kết quả tin cậy, dễ hành động và có thể làm bằng chứng tuân thủ**. Engine scan miễn phí (ZAP, Nuclei, Nikto) ai cũng dùng được, nên giá trị nằm ở: ít false positive, coverage đúng nơi khách cần (web + API + có đăng nhập), báo cáo/quy trình (theo dõi, retest, so sánh), tích hợp CI/CD và ticketing, ánh xạ tuân thủ, và độ an toàn/tin cậy của chính tool.

### 2.2 Đóng gói gợi ý `[ASSUMPTION]`

| Tier | Đối tượng | Năng lực chính (tham chiếu epic) |
|---|---|---|
| **Free** | Dùng thử, cộng đồng | CLI scan cấu hình 1 target, JSON/HTML cơ bản (E1, E3) |
| **Pro** | Dev/pentester/SMB | Multi-target, crawl, scan API, scan có xác thực đơn giản, SARIF, CI/CD (E3–E8) |
| **Business** | Team bảo mật | Server + lịch scan + lịch sử/so sánh + finding lifecycle + tích hợp Jira/Slack + báo cáo PDF (E12–E17) |
| **Enterprise** | Doanh nghiệp/tuân thủ | SSO, RBAC nâng cao, audit log, on-premise, mapping tuân thủ, SLA hỗ trợ (E16, E19) |

Mô hình tính phí thường gặp: theo **số target (FQDN/app/API)**, theo **số user/developer**, hoặc theo **gói**. Chốt sau khi có phản hồi khách hàng thật `[CONFIRM]`.

### 2.3 Tham chiếu giá thị trường `[FACT – nguồn bên thứ ba, chưa xác minh với hãng]`

Các con số dưới đây tổng hợp từ các trang review/so sánh (AppSec Santa, Beagle Security, DEV.to, Vendr) tra cứu ngày 2026-09-30 (các nguồn tự ghi cập nhật trong 2026); chỉ dùng làm mốc so sánh, **không** dùng để định giá khi chưa kiểm tra lại với nguồn chính thức.

| Nhóm | Ví dụ | Mốc tham khảo |
|---|---|---|
| Open-source | ZAP, Nuclei, Nikto | $0 |
| SaaS nhỏ | HostedScan, Intruder, Detectify, Astra, Beagle | ~$60–$300/tháng hoặc ~$1.200–$2.500/năm khởi điểm |
| Cho từng pentester | Burp Suite Pro | ~$475–$499/user/năm |
| Trung bình → doanh nghiệp | Acunetix, Invicti | khởi điểm ~$4.500–$7.000/năm; 1–10 target thường ~$5.000–$60.000/năm |
| Enterprise | Qualys WAS, Tenable WAS, Burp DAST | báo giá riêng, thường ~$30.000–$200.000+/năm |

---

## 3. Guardrails bất biến (áp dụng cho mọi epic)

1. **Chỉ quét khi có ủy quyền.** Phiên bản thương mại phải có xác minh sở hữu target (E5), không chỉ tự khai báo.
2. **An toàn theo mặc định.** Mặc định chỉ GET không payload; active checks là opt-in, có consent riêng, có giới hạn tốc độ, không gửi phương thức thay đổi dữ liệu (POST/PUT/PATCH/DELETE) nếu chưa được cho phép tường minh.
3. **Không lộ secret.** Credential, cookie, token, dữ liệu khách hàng luôn được che (`redact`) trong log, evidence, báo cáo; lưu trữ có mã hóa.
4. **Không bịa kết quả.** Finding phải có bằng chứng quan sát được; nếu không chắc, hạ `confidence` thay vì nâng severity. Không hứa "đảm bảo an toàn" trong báo cáo hay tài liệu.
5. **Đơn giản trước.** Modular monolith + worker; không thêm microservices, Kubernetes, vector DB, AI agent khi chưa có lý do rõ ràng và người duyệt.
6. **Dữ liệu khách hàng không gửi ra dịch vụ AI công cộng** trừ khi khách đồng ý bằng văn bản `[CONFIRM]`.
7. **Có con người review** trước: deploy production, hành động phá hủy, thay đổi kiến trúc lớn, cam kết SLA/giá/hợp đồng với khách hàng.

---

## 4. Kiến trúc mục tiêu (theo giai đoạn)

### 4.1 Nguyên tắc `[REC]`

Giữ lõi scan là **thư viện Python thuần** (checks + engine), dùng chung cho CLI, CI và server. Server chỉ là lớp bọc: nhận yêu cầu → xếp hàng → worker gọi lõi → lưu kết quả. Nhờ vậy mỗi giai đoạn bán được độc lập.

```text
Stage 1  CLI + Web UI cục bộ ──►  Stage 2  + Server (API + worker)  ──►  Stage 3  + multi-tenant, billing, integrations
[run_scan() dùng chung]         [chỉ khi chọn SaaS – D1]              [chỉ khi chọn SaaS – D1]
[core engine + checks]       [scheduler, DB, queue, REST API]        [RBAC, SSO, billing, integrations]
```

### 4.2 Cấu trúc thư mục gợi ý

```text
websec_scanner/
├── core/            # engine: runner, session, rate limiter, scope, redaction
├── checks/          # các check (hàm thuần) – gom theo nhóm: config/, api/, active/
├── rules/           # dữ liệu khai báo: headers, paths, signatures (YAML/JSON)
├── models/          # Finding, ScanResult, Target, AuthProfile (pydantic hoặc dataclass)
├── reporters/       # console, json, sarif, html, pdf, csv
├── crawler/         # HTTP crawler + headless (Playwright) – Stage 1.5
├── auth/            # auth profiles, session handling
├── cli/             # argparse/typer entry
├── web.py           # (đã có) Web UI cục bộ: http.server, /api/scan, /api/report/<id>.html
├── html_report.py   # (đã có) render_html(): báo cáo HTML độc lập, dùng chung cho Web UI và (sau này) CLI --html
├── static/          # (đã có) index.html, app.js, app.css
├── server/          # (Stage 2) FastAPI app, jobs, db, auth, billing
├── worker/          # (Stage 2) job runner
└── tests/           # unit + integration + mock_server + benchmarks
docs/                # PRODUCT-BACKLOG.md, SRS, ADRs
```

### 4.3 Lựa chọn công nghệ `[REC]` (đổi được khi có lý do)

| Hạng mục | Đề xuất | Lý do / lưu ý |
|---|---|---|
| Ngôn ngữ lõi | Python (giữ nguyên) | Đã có code + SRS; hệ sinh thái security phong phú |
| HTTP client | `requests` → cân nhắc `httpx` (async) | Async giúp scale crawl/scan; đổi khi thực sự cần |
| Crawl SPA | Playwright (headless Chromium) | Xử lý được JavaScript-rendered app; kiểm tra license/điều kiện phân phối |
| Server | FastAPI | Nhẹ, có OpenAPI sẵn |
| DB | PostgreSQL | Đủ cho multi-tenant; JSONB cho evidence |
| Queue/worker | RQ hoặc Celery + Redis | Chưa cần Kubernetes; Docker Compose là đủ cho giai đoạn đầu |
| UI | Web UI cục bộ đã có (`http.server` + static) | Giữ nguyên; chỉ hoàn thiện theo E12a. Không thêm framework web khi chưa cần |
| Lint/format | `ruff` (check + format) | Nhanh, một công cụ; chạy trong CI (FR-QA-07) |
| Đóng gói | Docker image + `pip` package | Phục vụ cả SaaS và on-premise |
| Thanh toán | Stripe (hoặc nhà cung cấp tương đương) | Không tự xử lý dữ liệu thẻ `[CONFIRM]` |
| Tích hợp engine ngoài | Đánh giá ZAP/Nuclei/sslyze | Kiểm tra license + điều khoản thương mại trước khi nhúng `[CONFIRM]` |

---

## 5. Backlog chức năng theo epic

Cách đọc: `- [ ] **ID** (Ưu tiên · Tier) Mô tả.` theo sau là `AC:` (acceptance criteria) và `Phụ thuộc:` nếu có. Tick `[x]` khi đạt Definition of Done (mục 0.4).

### E0. Sửa lỗi baseline (SRS v1.0)

- [x] **FR-FIX-01** (P0 · all) *(xong ở SRS v1.2)* Sửa lỗi tham chiếu chéo: FR-CLI-05 trỏ đúng mục 4.5 (TLS); mục 3.2 ghi đúng phạm vi FR-CLI-01 → FR-REPORT-05.
  AC: SRS không còn tham chiếu sai (rà bằng tìm kiếm).
- [x] **FR-FIX-02** (P0 · all) *(xong ở SRS v1.2)* Sửa bảng FR-COOKIE-01 (cột Severity đang chứa "M").
  AC: bảng đúng cột; nêu rõ severity theo FR-COOKIE-02.
- [x] **FR-FIX-03** (P0 · all) *(xong: SRS v1.2 mục 9 có AT-01…AT-28, mỗi AT trỏ tới test pytest cụ thể)* Bổ sung acceptance test cho FR-TLS, FR-REDIR-03, FR-CORS-02/04, FR-HDR-05/08, FR-COOKIE-03, FR-EXP-06, FR-CLI-05, FR-REPORT-05.
  AC: mỗi FR có ít nhất 1 AT tương ứng, chạy được bằng mock server.
- [x] **FR-FIX-04** (P0 · all) *(xong ở SRS v1.2 và README; chữ "Passive" còn trong code được tách thành FR-FIX-11)* Đổi định vị sản phẩm từ "passive" thành "non-intrusive configuration scanner" trong SRS/README (tool gửi request tới các path cụ thể, không thuần thụ động).
  AC: mô tả nhất quán, nêu rõ giới hạn (NFR-COMP-01).
- [x] **FR-FIX-05** (P0 · all) *(xong từ code v1.1.0; test AT-16)* HSTS chỉ được kiểm tra khi target là `https://` (header bị bỏ qua trên HTTP). Phần "xét trên URL cuối" chuyển sang FR-FIX-10.
  AC: quét `http://` không sinh finding HDR-STRICT-TRANSPORT-SECURITY-MISSING sai ngữ cảnh.
- [x] **FR-FIX-06** (P0 · all) *(xong từ code v1.1.0; test AT-17)* FR-HDR-04 (thiếu X-Frame-Options) không sinh finding nếu CSP có `frame-ancestors` hợp lệ.
  AC: có test cho cả hai trường hợp; thống nhất với FR-HDR-05.
- [x] **FR-FIX-07** (P0 · all) *(xong ở Sprint 3: AT-33; changelog v1.2.0)* Áp dụng quyết định **D3** cho CORS: `CORS-WILDCARD-WITH-CREDENTIALS` → MEDIUM (trình duyệt từ chối tổ hợp này, rủi ro chủ yếu là cấu hình sai và client không phải trình duyệt); `CORS-REFLECTS-ARBITRARY-ORIGIN` → HIGH nếu có credentials, MEDIUM nếu không; `CORS-WILDCARD` → INFO.
  AC: test cho 4 tổ hợp; description/recommendation của từng finding giải thích lý do mức độ; SRS mục 4.7 và mục 12 cập nhật khi code xong; exit code thay đổi được ghi changelog (`*`+credentials không còn làm exit 1).
- [x] **FR-FIX-08** (P0 · all) *(xong: SRS v1.2 mục 3.3, 4.10, 6.3, 7.4 đã đối chiếu `web.py`)* Cập nhật SRS để mô tả Web UI cục bộ (đã có trong code) và đối chiếu lại với code thật.
  AC: SRS mô tả khớp với `web.py`; mọi khác biệt được sửa ở tài liệu hoặc code.
- [x] **FR-FIX-09** (P0 · all) *(xong ở Sprint 3b: SRS FR-CLI-05, FR-REDIR-01/03, AT-35)* **Điều kiện chạy redirect check** (B3, SRS mục 12). Luôn chạy redirect check cho hostname của target, kể cả khi nhập `http://`. Nếu `http://` được chuyển sang `https://` trong phạm vi **D4**, chạy nhóm TLS trên URL cuối; nếu không được chuyển, báo `TLS-NO-HTTPS-REDIRECT`. Lỗi chứng chỉ không chặn redirect check, hai loại lỗi báo riêng. Redirect ra ngoài phạm vi thì dừng và ghi vào `errors`.
  AC: mock `http://` redirect sang `https://` cùng host → có kết quả nhóm TLS; mock `http://` không redirect → có `TLS-NO-HTTPS-REDIRECT`; mock redirect sang host khác → không gửi request tới host đó, có lỗi trong `errors`; cert hết hạn + không redirect → có cả hai finding. SRS sửa FR-CLI-05, FR-REDIR-01; changelog ghi rõ target `http://` có thể đổi exit code.
  Phụ thuộc: D4.
- [x] **FR-FIX-10** (P0 · all) *(xong ở Sprint 3b: SRS FR-HDR-01, FR-HDR-11, 6.2 `schema_version` 1.2, AT-36)* **HSTS và header xét theo URL nào** (B4, SRS mục 12). Check header chạy trên response cuối; HSTS chỉ xét khi response cuối là HTTPS. Cookie vẫn xét trên toàn chuỗi redirect (**D5**). Nếu redirect đổi host (ví dụ `example.com` → `www.example.com`), kiểm tra thêm HSTS ở host gốc qua HTTPS; thiếu thì tạo finding mức LOW. JSON thêm `final_url`, `redirect_chain`; nâng `schema_version`.
  AC: target `https://` redirect về `http://` → không đòi HSTS trên response HTTP; `example.com` → `www.example.com` có HSTS ở www nhưng thiếu ở gốc → 1 finding LOW; JSON có `final_url`, `redirect_chain` và `schema_version` mới; SRS sửa FR-HDR-01 và mục 6.2.
  Phụ thuộc: FR-MODEL-01, FR-MODEL-02, D4, D5.
- [x] **FR-FIX-11** (P1 · all) *(xong ở Sprint 3b: SRS NFR-SEC-03, AT-37)* Bỏ chữ "Passive" khỏi text sản phẩm cho khớp FR-FIX-04: banner CLI (`cli.py`), tiêu đề và footer Web UI (`static/index.html`, footer còn trỏ tới `SRS.md` cũ), tiêu đề/footer báo cáo HTML (`html_report.py`), User-Agent (`http_utils.py`, đồng thời sửa `/1.0` thành phiên bản thật).
  AC: `grep -i passive websec_scanner/` chỉ còn trong comment/docstring; test UI và báo cáo HTML được cập nhật; text vẫn là tiếng Anh (NFR-USA-03).

### E1. Độ chính xác và chiều sâu của các check hiện có

Mục tiêu: giảm false positive/negative – yếu tố quyết định khách có tiếp tục dùng và trả tiền hay không.

- [x] **FR-DET-01** (P0 · all) *(xong ở Sprint 4: chữ ký trong `rules/sensitive_paths.json`, SRS FR-EXP-04, AT-39)* Xác thực **nội dung** khi kiểm tra path nhạy cảm, không chỉ HTTP 200.
  AC: `.git/HEAD` phải chứa `ref:`; `.git/config` chứa `[core]`; `.env*` khớp mẫu `KEY=VALUE`; `*.sql`/`backup.sql` khớp dấu hiệu SQL dump; `id_rsa` chứa `BEGIN ... PRIVATE KEY`; `docker-compose.yml` chứa `services:`. Chữ ký khai báo dạng dữ liệu (rules/). Trang HTML chung (SPA/WAF) trả 200 → không tạo finding. Test bằng mock server trả 200 + HTML cho mọi path.
- [x] **FR-DET-02** (P0 · all) *(xong ở Sprint 4: `soft404.py`, SRS FR-EXP-02, AT-40)* Nâng cấp phát hiện soft-404: so sánh vân tay nội dung (độ dài, hash, độ tương đồng) và xử lý cả redirect về trang login/home.
  AC: mock server trả 200 hoặc 302→/login cho mọi path → không có finding lộ file; hành vi FR-EXP-02/03 vẫn đúng.
- [x] **FR-DET-03** (P0 · Pro) *(xong ở Sprint 4: SRS 6.1, AT-41)* Đánh dấu `confidence` (high/medium/low) cho mỗi finding; finding chỉ dựa trên tín hiệu gián tiếp (robots, banner) mặc định là low/medium.
  AC: trường `confidence` có trong JSON; finding có xác thực nội dung (FR-DET-01) là high.
- [ ] **FR-DET-04** (P0 · all) *(D7, Sprint 15)* TLS: **dò chủ động** các phiên bản (SSLv3, TLS1.0, 1.1, 1.2, 1.3) và nhóm cipher server hỗ trợ, không chỉ giao thức được thương lượng (sửa FR-TLS-04/05). Tự viết bộ dò (`checks/tls_probe.py`); **không** dùng sslyze (AGPL-3.0) hay testssl.sh (GPL-2.0) — chi tiết `docs/DECISIONS-S14-S20.md` mục 2.
  AC: mock TLS server bật TLS1.0/1.1 → finding `TLS-WEAK-PROTOCOL` dù client thương lượng được 1.3. Nếu môi trường Python/OpenSSL không cho phép dò bản cũ, ghi rõ trong `errors` là "không kiểm tra được", không im lặng bỏ qua.
- [ ] **FR-DET-04a** (P0) Module `checks/tls_probe.py`: ClientHello chuẩn cho mỗi phiên bản, đọc phiên bản trong ServerHello/alert, không hoàn tất trao đổi dữ liệu ứng dụng. OpenSSL 3 qua `ssl` không bắt tay được SSLv3/TLS1.0 mặc định → tự dựng ClientHello tối thiểu bằng `socket`+`struct` (ưu tiên), hoặc chứng minh `SECLEVEL=0` hoạt động trên các nền tảng hỗ trợ.
  AC: phát hiện đúng phiên bản bật/tắt trên badssl tự host và mock TLS server; không dò được một phiên bản thì ghi vào `errors`, không im lặng.
- [ ] **FR-DET-04b** (P0) Dò nhóm cipher yếu với danh sách khai báo (dữ liệu, không hard-code); mỗi nhóm tối đa 1 kết nối.
- [ ] **FR-DET-04c** (P0) Giới hạn tổng số handshake mỗi target (hằng số cấu hình, mặc định ≤ 30) + khoảng nghỉ giữa các kết nối; tôn trọng `--rate-limit`.
  AC: test đếm số kết nối tới mock TLS server không vượt giới hạn.
- [ ] **FR-DET-04d** (P0) Cập nhật mô tả `CheckGroup("tls")` (hiện ghi "2 TLS handshakes") thành con số tối đa mới; cập nhật consent banner và SRS mục 1.2, 4.5, NFR-SEC-01.
- [ ] **FR-DET-04e** (P1) README: ghi rõ IDS/WAF có thể ghi log các handshake phiên bản cũ. Cập nhật `THIRD_PARTY_LICENSES`/ADR với lý do không dùng sslyze/testssl.sh.
- [x] **FR-DET-16** (P1 · all) *(xong ở Sprint 4 theo danh sách issuer: `rules/tls_interceptors.json`, SRS FR-TLS-11, AT-41)* `[REC]` **Phát hiện TLS bị chặn giữa đường** (phần mềm diệt virus, proxy TLS inspection): so issuer/chuỗi chứng chỉ thấy được với dấu hiệu đã biết, hoặc so với kết quả từ môi trường tham chiếu; khi phát hiện thì ghi cảnh báo vào `errors` và đánh dấu kết quả nhóm TLS là không đáng tin (hạ `confidence`). Phát hiện ngày 2026-09-30: Avast Web/Mail Shield ký lại cả TLS tới `127.0.0.1`.
  AC: mock mô phỏng chứng chỉ bị ký lại → có cảnh báo, finding TLS có `confidence` thấp; không chặn → không cảnh báo.
- [x] **FR-DET-17** (P1 · all) *(xong ở Sprint 10: `tls_check._WEAK_CIPHER_MARKERS`, `weak_cipher_reason()`, SRS FR-TLS-04, AT-62. Phát hiện khi làm FR-MODEL-03: danh sách cũ `{RC4,3DES,MD5,NULL,EXPORT}` khớp chuỗi con trên tên suite của **OpenSSL** (`ssl.cipher()` trả về), mà các dấu hiệu lại viết theo kiểu tên IANA, nên bỏ lọt: **3DES** — tên OpenSSL là `DES-CBC3-SHA`, không chứa chuỗi `3DES`, nên SWEET32 thực tế chưa bao giờ bị phát hiện; **DES đơn 56-bit** (`DES-CBC-SHA`); **suite ẩn danh** không xác thực hai bên (`ADH-`, `AECDH-`); và `EXPORT` chỉ khớp tên IANA chứ không khớp `EXP-RC4-MD5`/`EXP1024-…` của OpenSSL nên suite export bị xếp nhầm mức nhẹ)* **Nhận diện cipher yếu cho đủ**: bảng khai báo theo dấu hiệu trong tên suite của OpenSSL, mỗi dấu hiệu kèm **lý do** (không mã hoá / không xác thực / đã bị phá nhưng vẫn mã hoá) và lý do đó quyết định luôn mức CVSS theo FR-MODEL-03.
  AC: phát hiện NULL, export (`EXP-`/`EXP1024`/`EXPORT`), ẩn danh (`ADH-`/`AECDH-`), RC4, RC2, DES **và** 3DES, IDEA, MD5; không báo nhầm suite hiện đại (AES-GCM, ChaCha20, TLS 1.3); finding ghi rõ vì sao suite đó yếu; thêm suite chỉ cần sửa bảng, không sửa logic.
- [ ] **FR-DET-05** (P1 · Pro) TLS nâng cao: hostname mismatch, chuỗi chứng chỉ thiếu intermediate, self-signed, độ mạnh khóa/chữ ký (RSA < 2048, SHA-1), hỗ trợ forward secrecy, HTTP/2, OCSP stapling (info).
  AC: mỗi loại lỗi có finding riêng với id ổn định, evidence là giá trị quan sát được.
- [ ] **FR-DET-06** (P1 · Pro) Chất lượng HSTS: `max-age` < 15552000 (~180 ngày), thiếu `includeSubDomains`, thiếu `preload` (info).
  AC: ngưỡng là hằng số cấu hình; finding phân biệt "missing" và "weak".
- [ ] **FR-DET-07** (P1 · Pro) Chất lượng CSP: thiếu `default-src`/`object-src`/`base-uri`, dùng wildcard `*`, `data:` trong `script-src`, `http:` sources; hỗ trợ `Content-Security-Policy-Report-Only` (info).
  AC: parse CSP thành directive; test cho từng trường hợp.
- [ ] **FR-DET-08** (P1 · Pro) Cookie nâng cao: tiền tố `__Host-`/`__Secure-`, `SameSite=None` không kèm `Secure`, thời hạn cookie phiên quá dài, cookie có tên gợi ý session nhưng thiếu cờ.
- [ ] **FR-DET-09** (P1 · Pro) CORS nâng cao: kiểm tra origin `null`, biến thể subdomain/regex yếu (ví dụ suffix match), preflight quá rộng (`Access-Control-Allow-Methods`, `-Headers`). Severity theo D3 (FR-FIX-07).
- [ ] **FR-DET-10** (P1 · Pro) HTTP methods: gửi `OPTIONS` để phát hiện `TRACE`, `PUT`, `DELETE` được quảng bá; **không** thực thi các method thay đổi dữ liệu.
- [ ] **FR-DET-11** (P1 · Pro) Header bổ sung: `Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy`, `Cross-Origin-Embedder-Policy`, `Cache-Control`/`Pragma` cho trang có cookie phiên, `Clear-Site-Data` (info).
- [ ] **FR-DET-12** (P1 · Pro) Mixed content và tài nguyên bên thứ ba: `http://` resource trong trang HTTPS; `<script>`/`<link>` bên ngoài thiếu Subresource Integrity (SRI).
- [ ] **FR-DET-13** (P1 · Pro) Mở rộng danh sách path nhạy cảm (data-driven): file backup/dump, `.htpasswd`, `composer.json`, `package.json`, `.npmrc`, `.aws/credentials`, `WEB-INF/web.xml`, `actuator/*`, `swagger`/`openapi` công khai, admin panel phổ biến, `crossdomain.xml`. Mỗi path có chữ ký nội dung nếu có thể.
  AC: thêm path chỉ cần sửa file rules, không sửa logic. *(Cơ chế đã có ở Sprint 4: `rules/sensitive_paths.json` + `rule_loader.py`; còn phần mở rộng danh sách.)*
- [ ] **FR-DET-14** (P2 · Business) Phát hiện banner/thông báo lỗi chi tiết (stack trace, đường dẫn tệp, SQL error) trong response lỗi thông thường (404/500) mà không cố ý gây lỗi bằng payload.
- [ ] **FR-DET-15** (P2 · Business) Email/DNS hygiene cho domain (SPF, DKIM gợi ý, DMARC, CAA, DNSSEC – chỉ đọc bản ghi công khai).

### E2. Mô hình finding và ánh xạ tuân thủ

- [x] **FR-MODEL-01** (P0 · all) *(xong ở Sprint 3: `catalog.py`, SRS 6.1, AT-29)* Mở rộng `Finding`: `cwe`, `confidence`, `references[]` (link OWASP/MDN/RFC), `instance_key` (khóa vị trí: URL/tên cookie/tên header/path), `fingerprint = hash(id + instance_key + target)`.
  AC: cùng một lỗi ở lần quét sau cho cùng `fingerprint`; hai cookie thiếu cờ khác nhau cho hai fingerprint khác nhau; fingerprint không phụ thuộc giá trị bị redact hay thời gian quét.
  Là tiền đề cho: FR-CI-02 (baseline), FR-RPT-06 (so sánh), FR-RPT-02 (SARIF).
- [x] **FR-MODEL-02** (P0 · all) *(xong ở Sprint 3: `schema_version` 1.1, `docs/report.schema.json`, AT-30)* Thêm `schema_version`, `scanner_version`, `scan_id` (UUID), `rules_version` vào JSON; giữ tương thích ngược hoặc nâng version có changelog.
  AC: test schema (jsonschema) cho JSON output; AT-12 vẫn đạt.
- [x] **FR-MODEL-03** (P1 · Pro) *(xong ở Sprint 10: CVSS v3.1 thật — quyết định chủ sản phẩm ngày 2026-10-01, không phải bảng severity thay thế. `websec_scanner/cvss.py` cài công thức base score chính thức, test đối chiếu ví dụ đã công bố (AT-61). `catalog._CVSS_VECTORS` gán 1 vector/loại cho 34/47 id; 13 id trong `catalog.NO_CVSS` không có điểm (3 id `NOT_A_WEAKNESS` cộng với mọi finding severity INFO theo quyết định C1). `schema_version` 1.6, SRS mục 6.1/6.2. Mọi nơi hiển thị ghi "(estimated)")* Điểm số: `cvss_vector`/`cvss_score` ước tính theo loại finding (ghi rõ "estimated") hoặc bảng severity có lý do; báo cáo giải thích cách tính.
  **Review ngày 2026-10-01 đã thực hiện** trên bảng vector; kết quả áp dụng trong cùng Sprint 10: sửa kịch bản của HSTS/redirect/chứng chỉ/clickjacking/cookie, thêm `catalog.NO_CVSS`, cho check ghi đè vector theo instance, đổi CWE chứng chỉ sang CWE-324. Hai quyết định đã chốt: **C1** không gán CVSS cho finding severity INFO; **C2** giữ CWE-298 cho `TLS-CERT-NOT-YET-VALID`.
  `[CONFIRM]` Còn lại: vector vẫn gán theo *loại* finding (không theo từng target), và vẫn là thang **tách biệt** khỏi `Severity` nội bộ nên hai thang có thể không khớp. Cần **người làm bảo mật** rà lại lần cuối trước khi giao số cho khách hàng trả tiền (review 2026-10-01 do chủ sản phẩm cung cấp, chưa phải security review nội bộ).
- [ ] **FR-MODEL-04** (P1 · Business) Ánh xạ tuân thủ dạng dữ liệu: OWASP Top 10:2021, OWASP API Top 10 (2023), OWASP ASVS, PCI DSS, ISO 27001 Annex A, SOC 2 (CC), NIST 800-53 (tùy chọn).
  AC: mapping ở file rules, báo cáo có mục "Compliance coverage"; nêu rõ đây là ánh xạ tham khảo, không phải chứng nhận tuân thủ.
- [ ] **FR-MODEL-05** (P1 · Pro) *(một phần ở Sprint 12: `baseline_state` (new/unchanged), `baseline.fixed`/`not_rechecked` và `suppression` đã phủ new / fixed / accepted cho CLI. Còn lại: một trường lifecycle thống nhất lưu được qua nhiều lần quét, kèm `false_positive` — cần lịch sử quét, thuộc E13/E14 ở Phase C)* Trạng thái finding trong model (`open`, `fixed`, `accepted_risk`, `false_positive`) dùng cho baseline/suppression (E13, E14).
- [x] **FR-MODEL-06** (P1 · Pro) *(xong ở Sprint 12: `suppressions.py`, `--suppressions FILE`. Định dạng **TOML** thay cho YAML — quyết định chủ sản phẩm 2026-10-01: `tomllib` có sẵn trong Python nên không thêm dependency, và TOML cho phép comment để ghi lý do. Loader nghiêm ngặt: khoá lạ hoặc mục khớp-mọi-thứ làm hỏng cả file; SRS mục 4.13 FR-SUPP-01…04, AT-69)* Cơ chế **suppression** bằng file (`.scannerignore.toml`, ban đầu dự kiến `.yaml`): bỏ qua theo `id`/`fingerprint`/path kèm lý do bắt buộc và ngày hết hạn.
  AC: finding bị suppress vẫn xuất hiện ở mục riêng của báo cáo (không biến mất âm thầm).
- [x] **FR-MODEL-07** (P0 · all) *(mở và xong ở Sprint 12: `http_utils.site_root()`, SRS mục 6.1, AT-67. Phát hiện khi lập kế hoạch FR-CI-02)* **Fingerprint ổn định theo site**: finding CORS và `TLS-NO-HTTPS-REDIRECT` từng dùng URL bắt đầu quét đầy đủ (gồm path và query) làm `instance_key`, trái với SRS 6.1 ("origin, không phải path"). Hệ quả: quét từ trang khác, hoặc query có token xoay vòng, cho fingerprint khác cho cùng một lỗi — khiến `--baseline` coi finding cũ là mới và chặn CI vô cớ.
  AC: `instance_key` = `scheme://host[:port]/`, không path/query/fragment/thông tin đăng nhập; lần quét từ site root giữ nguyên fingerprint cũ; changelog ghi rõ khoá SARIF của các finding này đổi một lần với lần quét bắt đầu ngoài site root.

### E3. Báo cáo và định dạng đầu ra

- [x] **FR-RPT-01** (P0 · Pro) *(xong ở Sprint 10: `render_html()` — tóm tắt điều hành có số finding theo severity, mục "Top issues" (tối đa 5, nặng nhất trước), và điểm CVSS ước tính của FR-MODEL-03 đóng vai trò "điểm rủi ro"; mỗi finding có mô tả/evidence/khuyến nghị/tham chiếu (đã có từ trước) cộng dòng "Reproduce" (chạy lại `--checks <group>`); phụ lục phạm vi/giới hạn (`output.SCOPE_NOTE`, FR-RPT-08) và check đã chạy (đã có từ trước); golden file cập nhật)* Báo cáo **HTML** tự chứa (một file): tóm tắt điều hành (số finding theo severity, điểm rủi ro, top vấn đề), chi tiết từng finding (mô tả, evidence, cách tái hiện, khuyến nghị, tham chiếu), phụ lục phạm vi/giới hạn/các check đã chạy.
  AC: mở được offline; escape đúng nội dung evidence (chống XSS trong chính báo cáo); có test snapshot.
- [x] **FR-RPT-09** (P0 · all) *(xong ở Sprint 5: `--html`, SRS FR-REPORT-07, AT-45)* Tham số CLI `--html PATH` dùng lại `render_html()` của Web UI (một bộ render cho cả hai nơi).
  AC: HTML từ CLI và từ `GET /api/report/<id>.html` giống nhau cho cùng JSON; evidence đã qua `redact()`; nội dung được escape.
- [x] **FR-RPT-02** (P0 · Pro) *(xong ở Sprint 5: `sarif.py`, `--sarif`, SRS FR-REPORT-06, AT-44; test kiểm tra cấu trúc bắt buộc, chưa validate bằng schema chính thức của OASIS — cần xác nhận license trước khi vendor file schema)* Xuất **SARIF 2.1.0** để hiển thị trong GitHub/GitLab code scanning.
  AC: file hợp lệ theo schema SARIF; rule id = `Finding.id`; `partialFingerprints` lấy từ `fingerprint` (FR-MODEL-01); tham số CLI `--sarif PATH`.
  Phụ thuộc: FR-MODEL-01, FR-AUTH-02.
- [x] **FR-RPT-10** (P1 · Pro) *(xong ở Sprint 10 cùng đợt sửa bảng vector: `sarif._security_severity()`, SRS FR-REPORT-06 và AT-44. Điều kiện chờ đã thỏa — bảng vector được review ngày 2026-10-01 trước khi làm. Đã ghi changelog: GitHub code scanning sẽ xếp lại mức cảnh báo của finding cũ ở lần upload đầu tiên)* SARIF `properties.security-severity` lấy từ `cvss_score` (FR-MODEL-03) thay vì suy ra từ `Severity` nội bộ.
  AC: `security-severity` = `cvss_score` khi có; finding trong `catalog.NO_CVSS` quay về bảng theo severity; changelog ghi rõ mức cảnh báo trên GitHub sẽ thay đổi; cập nhật SRS FR-REPORT-06 và AT-44.
- [x] **FR-RPT-03** (P1 · Pro) *(xong ở Sprint 12: `exports.py`, `--csv`, `--junit`. CSV chặn formula injection; JUnit có `failures` > 0 khi và chỉ khi exit code khác 0; SRS FR-OUT-01/02, AT-70)* Xuất **CSV** và **JUnit XML** (cho CI).
- [ ] **FR-RPT-04** (P1 · Business) Xuất **PDF** (từ HTML) với trang bìa, mục lục, logo tùy biến (white-label).
- [ ] **FR-RPT-05** (P1 · Business) Hai mẫu báo cáo: **Executive summary** (không kỹ thuật) và **Technical report** (cho developer).
- [x] **FR-RPT-06** (P1 · Pro) *(xong ở Sprint 12, gộp vào `--baseline`: mọi định dạng hiện mới / không đổi / đã sửa, không cần lệnh riêng. Finding biến mất chỉ được gọi là đã sửa khi check của nó đã chạy và lần quét hoàn tất, nếu không là `not_rechecked`; SRS FR-BASE-03, AT-68, AT-71)* Báo cáo **so sánh** hai lần quét: mới / đã sửa / còn tồn tại (dựa trên `fingerprint`).
- [ ] **FR-RPT-07** (P2 · Enterprise) Báo cáo tuân thủ theo chuẩn (PCI DSS, ISO 27001...) với disclaimer rõ ràng, không thay thế đánh giá của chuyên gia.
- [x] **FR-RPT-08** (P0 · all) *(xong ở Sprint 9: `output.SCOPE_NOTE`, dùng chung cho console và HTML; JSON có trường `disclaimer` từ v1.10.0 (`schema_version` 1.5); SRS AT-57)* Mọi báo cáo có phần **phạm vi & giới hạn** (những gì KHÔNG được kiểm tra) và **không dùng ngôn ngữ đảm bảo tuyệt đối** ("website an toàn").

### E4. CLI và tích hợp CI/CD

- [x] **FR-CI-01** (P0 · all) *(xong ở Sprint 5 cùng exit code `3` đã xác nhận; SRS FR-CLI-04, 7.3, AT-43)* Tham số `--fail-on {critical,high,medium,low,none}` để điều khiển exit code (mặc định `high` = giữ FR-CLI-04). Web UI dùng cùng logic cho `gate_failed`.
  AC: test cho từng ngưỡng; `gate_failed` của Web UI khớp exit code của CLI với cùng ngưỡng.
  `[CONFIRM]` Thêm exit code `3` = "quét không hoàn tất" (baseline thất bại hoặc có check lỗi), để pipeline không "xanh" khi không quét được gì (B2 trong `docs/srs-feedback.md`; SRS mục 13). Là thay đổi hợp đồng CLI, cần chủ SRS duyệt trước khi làm.
- [x] **FR-CI-02** (P0 · Pro) *(xong ở Sprint 12: `baseline.py`, `--baseline FILE`, chỉ CLI — quyết định chủ sản phẩm 2026-10-01. `summary` giữ nguyên nghĩa, gate đọc `gate.counted`; `schema_version` 1.8; SARIF `baselineState`. Cần sửa trước FR-MODEL-07 vì fingerprint CORS/redirect không ổn định; SRS FR-BASE-01…05, AT-68)* `--baseline FILE`: chỉ tính lỗi **mới** so với baseline (theo `fingerprint`) để không chặn pipeline vì nợ cũ.
  Phụ thuộc: FR-MODEL-01, FR-MODEL-02.
- [x] **FR-CI-03** (P0 · all) *(xong ở Sprint 5: `examples/ci/`, AT-46; chưa chạy trên CI thật)* Template CI/CD: GitHub Actions, GitLab CI, Azure DevOps, Jenkins (trong `examples/ci/`), kèm hướng dẫn upload SARIF/artefact.
- [x] **FR-CI-04** (P0 · Pro) *(xong ở Sprint 9: `Dockerfile` 2 giai đoạn, user không phải root, job CI `docker` build+smoke-test; sửa luôn Jenkinsfile dùng source archive thay vì `git+apt-get`. Publish lên `ghcr.io/hkbach/websec-scanner` thêm ở v1.10.0 theo yêu cầu chủ sản phẩm 2026-09-30 (job `docker-publish`, chỉ chạy khi push tag `v*`); SRS AT-59. Còn việc thủ công của admin: đặt visibility package công khai, xem README mục Docker)* Image Docker chính thức chạy được CLI (`docker run ... scan https://...`), user không phải root.
- [x] **FR-CI-05** (P1 · Pro) *(xong ở Sprint 13: nhiều target qua đối số, `--targets-file` hoặc config; mỗi target một bộ file trong `--output-dir` theo `--formats` — quyết định chủ sản phẩm 2026-10-01, giữ nguyên schema JSON để mỗi file dùng thẳng làm baseline —; `--baseline-dir`, `--parallel` 1–64, exit code theo target tệ nhất; từ chối gửi credential tới nhiều host; SRS mục 4.14 FR-MULTI-01…05, AT-73)* `--targets-file FILE` và nhiều `target` trong một lần chạy, gộp báo cáo; giới hạn tuần tự/song song có kiểm soát.
- [x] **FR-CI-06** (P1 · Pro) *(xong ở Sprint 13: `config.py`, `--config scanner.toml` — TOML như suppression ở Sprint 12, không thêm dependency. Mọi tùy chọn CLI có khoá tương đương, trừ `--yes`/`--show-secrets` cố ý chỉ nhận trên dòng lệnh; `${ENV}` cho credential, cảnh báo khi credential ghi thẳng; SRS FR-CFG-01…03, AT-72. Auth profile thuộc FR-AUTH-01, Sprint 16)* File cấu hình (`scanner.toml`, ban đầu dự kiến `.yaml`): target, exclusion, rate limit, auth profile, ngưỡng fail, đường dẫn báo cáo; tham số CLI ghi đè cấu hình.
- [x] **FR-CI-10** (P0 · all) *(xong ở Sprint 5: mặc định kho OS cho cả hai đường, `--ca-bundle`; SRS FR-CLI-06, AT-42)* `--ca-bundle PATH` (và biến môi trường `REQUESTS_CA_BUNDLE`/`SSL_CERT_FILE` được tôn trọng) cho **cả** HTTP session và kiểm tra TLS (`ssl.create_default_context(cafile=...)`). Gỡ blocker **B1** `[FACT – quan sát trên máy dev ngày 2026-09-23; đính chính 2026-09-30: thành phần chặn TLS là Avast Web/Mail Shield chạy trên máy, không phải proxy mạng; SRS mục 10]`: `requests` tin kho `certifi`, còn nhóm TLS tin kho chứng chỉ của hệ điều hành. Sau proxy có TLS inspection, `requests` từ chối **mọi** site HTTPS nên baseline thất bại; nhóm TLS vẫn qua vì kho OS tin CA của proxy. Kết quả: 1 lỗi "Could not fetch", 0 finding, exit code `0`.
  AC: mock HTTPS server ký bởi CA tự tạo → không có `--ca-bundle` thì baseline thất bại và có `TLS-CERT-NOT-TRUSTED`; có `--ca-bundle` trỏ tới CA đó thì baseline thành công, các check HTTP chạy đủ, không có `TLS-CERT-NOT-TRUSTED`; Web UI dùng cùng cấu hình (tham số khi khởi động server).
  `[REC]` Phương án thay thế: dùng kho chứng chỉ của OS cho `requests` (thư viện `truststore`). Cần Python ≥ 3.10, xung đột với NFR-PORT-01 (≥ 3.9); cần kiểm tra license.
- [x] **FR-CI-07** (P1 · Pro) *(xong ở Sprint 13: `request_options.py`. Credential (header nhạy cảm, cookie, mật khẩu proxy) bị che ở mọi nơi kể cả khi target phản xạ; `--proxy` chỉ `http://`, áp cả cho check TLS qua `CONNECT`; `--user-agent` chỉ ghép trước, giữ NFR-SEC-03 — quyết định chủ sản phẩm 2026-10-01; SRS FR-OPT-01…05, AT-74)* Tham số vận hành: `--proxy`, `--header K:V` (lặp được), `--cookie`, `--user-agent`, `--version`, `--quiet`/`--verbose`.
  AC: header/cookie truyền qua CLI không xuất hiện nguyên văn trong log/evidence (dùng `redact`).
- [ ] **FR-CI-11** (P2 · Pro) *(mở ở Sprint 13)* Proxy còn thiếu sau FR-CI-07: (1) proxy `https://` — check TLS cần TLS lồng trong TLS (ví dụ `urllib3.util.ssltransport`) và một proxy https giả để test; (2) proxy SOCKS — cần thêm dependency (rà license theo FR-SEC-10); (3) không có `--proxy` thì check TLS vẫn kết nối thẳng dù `HTTPS_PROXY` có trong môi trường — đổi điều này là đổi hành vi mặc định của người đang dùng proxy qua biến môi trường, nên cần quyết định riêng.
  AC: mỗi phần có test với proxy cục bộ; check TLS không còn kết nối thẳng khi người dùng đã chỉ định proxy dưới bất kỳ hình thức nào.
- [ ] **FR-CI-08** (P2 · Business) Pre-commit/PR comment bot: đăng tóm tắt lên pull request (GitHub/GitLab).

### E5. Ủy quyền target và kiểm soát quét an toàn

- [ ] **FR-AUTHZ-01** (P0 · Business) **Xác minh sở hữu domain** bằng ít nhất 2 cách: bản ghi DNS TXT (`_scanner-verify.<domain>=<token>`) và file `/.well-known/<tool>-verify.txt`; tùy chọn meta tag.
  AC: token ngẫu nhiên gắn với org/target; xác minh thất bại → không gửi request quét; có thể xác minh lại định kỳ; trạng thái lưu cùng target.
- [ ] **FR-AUTHZ-02** (P0 · Business) Chế độ **consent theo mức**: config (non-intrusive) (mặc định) / crawl / active. Mỗi mức hiển thị banner riêng và yêu cầu xác nhận riêng, ghi lại ai xác nhận, lúc nào, cho mức nào.
- [x] **FR-AUTHZ-03** (P0 · all) **Scope guard**: chỉ gửi request tới host/port trong phạm vi khai báo; không theo redirect sang host ngoài phạm vi; cảnh báo khi redirect đi ra ngoài.
  AC: mock server redirect sang host khác → tool không gửi request tới host đó, ghi vào `errors`/`notes`.
  Phần tối thiểu cho redirect (**D4**: cùng host hoặc chỉ khác tiền tố `www.`) **đã xong ở Sprint 3b** (`ScopedSession`, SRS NFR-SEC-05, AT-34); phạm vi khai báo nhiều host (`--scope-host`, áp cho cả hai đường kiểm scope) **xong ở Sprint 11** (SRS FR-SCOPE-01, AT-66). Cảnh báo redirect ra ngoài phạm vi đã có sẵn trong `errors` và hiển thị ở cả Web UI lẫn báo cáo HTML.
- [ ] **FR-AUTHZ-04** (P0 · Business – bắt buộc khi có dịch vụ dùng chung) **Chống SSRF cho dịch vụ**: từ chối target phân giải ra IP loopback, private (RFC1918), link-local (kể cả `169.254.169.254`), multicast, IPv6 tương đương; kiểm tra lại sau mỗi redirect và **ghim IP đã phân giải** (chống DNS rebinding).
  AC: test với `localhost`, `127.0.0.1`, `10.0.0.1`, `169.254.169.254`, hostname trỏ về IP private → đều bị từ chối. Cho phép cấu hình ngoại lệ chỉ cho bản on-premise nội bộ, với cờ tường minh.
- [x] **FR-AUTHZ-05** (P0 · all) *(xong ở Sprint 11: `limits.ScanLimiter`, SRS mục 4.12 FR-LIM-01…06, AT-63…65. Mặc định **không giới hạn** — quyết định chủ sản phẩm 2026-10-01, giữ nguyên hành vi cũ và không làm chậm CI. Áp ở tầng `_TrustAdapter.send` nên tính cả hop redirect và retry của urllib3, và truyền tường minh vào `check_tls` vì nhóm TLS tự mở socket. JSON thêm khối `limits`, `schema_version` 1.7)* **Giới hạn tốc độ** toàn cục và theo host: `--rate-limit` (request/giây), `--max-requests`, `--max-duration`; tự giảm tốc khi gặp 429/503.
- [x] **FR-AUTHZ-06** (P1 · Pro) *(xong ở Sprint 11: `rules/exclusions.json` (dữ liệu khai báo, có trong `rules_version`), `--exclude`, `--exclude-host`, `--no-default-excludes`; chặn cả redirect dẫn vào path bị loại; SRS FR-EXCL-01, AT-66)* **Exclusion**: danh sách path/regex/host bị loại khỏi quét (ví dụ `/logout`, `/delete`, trang thanh toán).
- [ ] **FR-AUTHZ-07** (P1 · Business) **Khung giờ được phép quét** (scan window) và nút **dừng khẩn cấp** (kill switch) cho từng target/org.
- [ ] **FR-AUTHZ-08** (P1 · Pro) **Safe mode** mặc định cho môi trường production: chỉ GET/HEAD/OPTIONS, không submit form, không gọi endpoint có dấu hiệu thay đổi dữ liệu.
- [x] **FR-AUTHZ-09** (P1 · all) *(xong ở Sprint 11: `--scan-id-header`, mặc định tắt; SRS FR-SCANID-01, AT-66)* User-Agent nhận diện rõ scanner + header tùy chọn `X-Scanner-Scan-Id` để bên đích lọc log/WAF (giữ NFR-SEC-03).
- [ ] **FR-AUTHZ-10** (P0 · Business) Điều khoản sử dụng (ToS) và chính sách sử dụng chấp nhận được (AUP) phải được người dùng chấp nhận trước lần quét đầu; backend ghi nhận bằng chứng chấp nhận (ai, lúc nào, phiên bản điều khoản) và cung cấp qua API; việc hiển thị do UI hiện có. `[CONFIRM]` nội dung với pháp lý.

### E6. Crawler và quét nhiều trang (kể cả SPA)

- [ ] **FR-CRAWL-01** (P0 · Pro) Crawler HTTP theo link cùng origin, có `max_depth`, `max_pages`, `max_duration`, tôn trọng scope/exclusion (E5).
  AC: dừng đúng giới hạn; không ra ngoài scope; có test với mock site nhiều trang và vòng lặp link.
- [ ] **FR-CRAWL-02** (P1 · Pro) Crawler SPA bằng trình duyệt headless: thực thi JS, thu thập route, form, XHR/fetch endpoint từ network.
  AC: mock SPA render link bằng JS → crawler tìm được; các endpoint API quan sát được chuyển sang danh sách API (E7).
- [ ] **FR-CRAWL-03** (P0 · Pro) Chạy check header/cookie/CORS/TLS-redirect trên **nhiều route đại diện**, gộp finding trùng theo `fingerprint` (ghi số URL bị ảnh hưởng).
- [ ] **FR-CRAWL-04** (P1 · Pro) Tùy chọn tôn trọng `robots.txt` (mặc định bật cho crawl; tắt được tường minh cho target đã xác minh sở hữu).
- [ ] **FR-CRAWL-05** (P1 · Pro) Phát hiện form: đăng nhập không qua HTTPS, `autocomplete` mật khẩu, thiếu CSRF token (heuristic), form gửi sang origin khác.
- [ ] **FR-CRAWL-06** (P1 · Pro) Phát hiện open redirect **thụ động** (tham số `url=`/`next=` phản xạ trong `Location` khi quan sát bình thường); kiểm tra chủ động thuộc E9.
- [ ] **FR-CRAWL-07** (P2 · Business) Sơ đồ site (sitemap nội bộ) xuất kèm báo cáo, dùng cho asset inventory.

### E7. Quét API

- [ ] **FR-API-01** (P0 · Pro) Nạp định nghĩa API: OpenAPI 3.x/Swagger 2.0 (file hoặc URL), Postman Collection v2.1, và GraphQL (introspection nếu được phép). **Sprint 17 (D9) chỉ làm phần OpenAPI 3.0/3.1 + Swagger 2.0 từ file** (FR-API-01a..d, dùng PyYAML + tự resolve `$ref` nội bộ, không prance); nạp từ URL, Postman và GraphQL để sau, có thể tách FR riêng khi tới lượt.
  AC: parse lỗi → thông báo rõ, không crash; danh sách endpoint/method/tham số hiển thị trong báo cáo.
- [ ] **FR-API-01a** (P0) `api/spec_loader.py`: nhận file `.json`/`.yaml`/`.yml`; YAML dùng `yaml.safe_load` (test: tag `!!python/object` bị từ chối).
- [ ] **FR-API-01b** (P0) Tự resolve `$ref` **nội bộ** (`#/components/...`) và file tương đối trong cùng thư mục spec. **Cấm:** `$ref` tới URL, đường dẫn tuyệt đối, hoặc `..` thoát khỏi thư mục spec → báo lỗi rõ ràng (chống SSRF và đọc file trái phép).
  AC: test với `$ref` trỏ `http://169.254.169.254/`, `/etc/passwd`, `../../secret.yaml` → đều bị từ chối, không có request mạng.
- [ ] **FR-API-01c** (P0) Giới hạn an toàn: kích thước file (≤ 5 MB), độ sâu lồng/`$ref` (≤ 32), `$ref` vòng lặp, số endpoint tối đa (cấu hình).
  AC: test YAML "billion laughs"/alias bomb và `$ref` vòng tròn → lỗi có kiểm soát, không treo.
- [ ] **FR-API-01d** (P0) Hỗ trợ OpenAPI 3.0/3.1 và Swagger 2.0 đủ để liệt kê server, path, method, tham số, security scheme; lỗi spec không crash tool.
  AC: parse thành công spec của VAmPI (benchmark Sprint 14). Thêm PyYAML vào `pyproject.toml`, `THIRD_PARTY_LICENSES`, pip-audit. Web UI: nếu cho tải spec lên thì áp cùng giới hạn; không nhận URL spec từ xa ở Web UI.
- [ ] **FR-API-02** (P0 · Pro) Kiểm tra không xâm lấn trên từng endpoint GET/HEAD/OPTIONS: header bảo mật trên response API, CORS, `Content-Type` sai/thiếu, lộ thông báo lỗi chi tiết, method được quảng bá.
- [ ] **FR-API-03** (P0 · Pro) **Thiếu xác thực**: gọi endpoint mà spec yêu cầu auth khi không gửi credential; nếu trả 2xx kèm dữ liệu → finding (OWASP API2/API5). Chỉ với method an toàn.
  AC: mock API có endpoint bảo vệ đúng/sai → đúng/không finding.
- [ ] **FR-API-04** (P1 · Pro) **Lộ dữ liệu quá mức** (heuristic): response chứa trường nhạy cảm (`password`, `token`, `secret`, `ssn`, số thẻ dạng mẫu...) hoặc dư trường so với schema; đánh dấu confidence thấp/trung bình.
- [ ] **FR-API-05** (P1 · Pro) **Rate limiting**: phát hiện thiếu header giới hạn tốc độ (info) và tùy chọn kiểm tra hành vi 429 với số request nhỏ, có giới hạn cứng (không tạo tải).
- [ ] **FR-API-06** (P1 · Pro) **GraphQL**: introspection bật ở production, giới hạn độ sâu/alias/batching (kiểm tra bằng truy vấn vô hại), gợi ý field suggestion bị lộ.
- [ ] **FR-API-07** (P1 · Business) **Inventory/shadow API**: so sánh endpoint quan sát được (crawl/XHR) với spec để phát hiện endpoint không có trong tài liệu, phiên bản cũ (`/v1` cạnh `/v3`), tài liệu Swagger UI công khai.
- [ ] **FR-API-08** (P2 · Business) **BOLA/IDOR** (OWASP API1): cần **hai tài khoản test** và cờ opt-in; thay đối tượng giữa hai user rồi so sánh phản hồi; chỉ dùng method an toàn nếu chưa được phép.
- [ ] **FR-API-09** (P2 · Business) **Mass assignment / thuộc tính thừa** (API3) và **BFLA** (API5) ở chế độ active có kiểm soát; xem E9.
- [ ] **FR-API-10** (P1 · Pro) Báo cáo API có ánh xạ **OWASP API Security Top 10 (2023)**.
- [ ] **FR-API-11** (P1 · Pro) Xác thực API trong quét: API key (header/query), Bearer/JWT, Basic, OAuth2 client credentials — dùng auth profile của E8.

### E8. Quét có xác thực

- [ ] **FR-AUTH-01** (P0 · Pro) **Auth profile** khai báo trong config: `bearer`, `api_key`, `basic`, `cookie`, `header`; giá trị lấy từ **biến môi trường/secret store**, không ghi thẳng vào file cấu hình.
  AC: cấu hình chứa secret dạng plaintext → cảnh báo; secret không xuất hiện trong log, evidence, báo cáo, JSON.
- [x] **FR-AUTH-02** (P0 · all) *(xong ở Sprint 3: `redact.py`, NFR-SEC-04, AT-32; SARIF áp dụng khi có FR-RPT-02)* Hàm `redact()` dùng chung theo quyết định **D2**: che giá trị `Authorization`, `Cookie`, `Set-Cookie`, token, tham số nhạy cảm trong URL (`token`, `key`, `session`, `password`, `sig`...). **Thay FR-COOKIE-04**: evidence giữ tên cookie + thuộc tính, giá trị thay bằng `<redacted len=N>`.
  Cờ `--show-secrets` (chỉ CLI): tắt che để debug cục bộ; in cảnh báo ra stderr; JSON có `"secrets_redacted": false`; HTML hiển thị băng cảnh báo. Web UI **không** nhận tham số này dưới bất kỳ hình thức nào.
  AC: test quét toàn bộ output (console/JSON/HTML/SARIF, cả CLI và Web UI) và fail nếu còn secret mẫu; test `POST /api/scan` có trường `show_secrets` vẫn bị che.
  Là tiền đề cho: FR-RPT-02, FR-RPT-09, FR-CI-02, E8.
- [ ] **FR-AUTH-03** (P1 · Pro) **Form login** theo kịch bản khai báo (URL, field, selector, dấu hiệu đăng nhập thành công/thất bại) và giữ session cookie.
- [ ] **FR-AUTH-04** (P1 · Pro) Phát hiện **mất phiên** (bị redirect về login, 401) và **đăng nhập lại tự động**; tránh quét khi đang ở trạng thái đăng xuất.
- [ ] **FR-AUTH-05** (P1 · Business) **OAuth2/OIDC**: client credentials, authorization code với token được cung cấp sẵn/refresh; không tự thu thập mật khẩu người dùng cuối.
- [ ] **FR-AUTH-06** (P1 · Business) **Đăng nhập bằng trình duyệt headless** (SPA), có thể ghi lại luồng đăng nhập (recorded login).
- [ ] **FR-AUTH-07** (P2 · Business) Hỗ trợ **MFA** ở mức chấp nhận token/TOTP secret do khách cung cấp cho tài khoản test; tài liệu hướng dẫn dùng tài khoản test riêng.
- [ ] **FR-AUTH-08** (P1 · Business) Cảnh báo/kiểm soát **hành động nguy hiểm khi có đăng nhập** (logout, xóa, thanh toán): exclusion mặc định cho các đường dẫn/nút phổ biến; khuyến nghị dùng môi trường staging.
- [ ] **FR-AUTH-09** (P0 · Business) Trên server: credential lưu **mã hóa** (xem E19), chỉ giải mã trong worker khi chạy job, xóa khỏi bộ nhớ sau job, có audit log truy cập.

### E9. Active checks (opt-in, có kiểm soát)

> `[CONFIRM]` Cần chốt trước: tự viết hay tích hợp engine (ZAP/Nuclei). Cần review pháp lý và security review nội bộ trước khi phát hành. Tất cả check ở đây **mặc định TẮT**, cần consent mức "active" (FR-AUTHZ-02) và target đã xác minh sở hữu (FR-AUTHZ-01).

- [ ] **FR-ACTIVE-01** (P1 · Business) Khung chạy active check: đăng ký check theo `safety_level` (`safe`, `intrusive`), giới hạn số request/tham số, dừng khi có dấu hiệu quá tải (5xx/độ trễ tăng), ghi log request đã gửi (đã `redact`).
- [ ] **FR-ACTIVE-02** (P1 · Business) **Reflected XSS**: chèn chuỗi canary duy nhất vô hại, xác định ngữ cảnh phản xạ (HTML/attribute/JS), xác nhận bằng bằng chứng là chuỗi canary được phản xạ nguyên vẹn, không bị mã hóa; không dùng payload gây hại.
- [ ] **FR-ACTIVE-03** (P1 · Business) **SQL injection** dạng phát hiện an toàn: lỗi SQL đặc trưng, sai khác boolean; **time-based** chỉ khi bật riêng, với giới hạn thời gian; không dùng payload hủy/ghi dữ liệu.
- [ ] **FR-ACTIVE-04** (P1 · Business) **Open redirect** chủ động, **path traversal** ở mức kiểm tra marker an toàn, **header injection/CRLF** phản xạ, **SSTI** dò bằng biểu thức số học vô hại.
- [ ] **FR-ACTIVE-05** (P2 · Business) **SSRF** dò qua tham số URL bằng callback tới máy chủ OAST do chính hệ thống sở hữu (không dùng dịch vụ bên thứ ba khi chưa được khách đồng ý).
- [ ] **FR-ACTIVE-06** (P2 · Business) **CSRF** (kiểm tra cơ chế bảo vệ trên form/endpoint thay đổi trạng thái ở môi trường test có tài khoản test).
- [ ] **FR-ACTIVE-07** (P2 · Enterprise) **Rate-limit/brute-force resilience** ở mức giới hạn cứng nhỏ (vài request), không thực hiện brute-force thật.
- [ ] **FR-ACTIVE-08** (P1 · Business) Mọi finding active phải có **bằng chứng tái hiện** (request/response đã redact) và `confidence`; finding không tái hiện được lần hai bị hạ confidence hoặc loại.
- [ ] **FR-ACTIVE-09** (P1 · Business) Cơ chế **xác minh lại tự động** (verify) trước khi báo finding severity HIGH/CRITICAL từ active check để giảm false positive.

### E10. Thành phần dễ tổn thương (OWASP A06)

- [ ] **FR-CVE-01** (P1 · Pro) Nhận diện công nghệ/phiên bản qua header, meta generator, đường dẫn file tĩnh, thư viện JS (fingerprint). Quy tắc dạng dữ liệu; kiểm tra license nếu dùng bộ luật bên ngoài.
- [ ] **FR-CVE-02** (P1 · Pro) Đối chiếu phiên bản với CSDL lỗ hổng công khai (NVD/OSV) và danh sách **CISA KEV**; hỗ trợ dùng bản sao offline có cập nhật định kỳ (cho on-premise). `[CONFIRM]` điều khoản sử dụng dữ liệu.
  AC: finding ghi rõ **phiên bản quan sát được là suy đoán** (banner có thể bị che/giả); confidence tương ứng; không khẳng định "bị khai thác được".
- [ ] **FR-CVE-03** (P2 · Business) Ưu tiên hóa bằng **EPSS**/KEV, gợi ý bản vá tối thiểu.
- [ ] **FR-CVE-04** (P2 · Business) Phát hiện JS library lỗi thời (ví dụ jQuery/Angular phiên bản cũ) từ file tĩnh với `retire`-style signatures.
- [ ] **FR-CVE-05** (P0) *(D10, Sprint 18)* Module `vulndb/` với một lớp nguồn dữ liệu duy nhất; mỗi bản ghi lưu `source`, `source_license`, `retrieved_at`.
- [ ] **FR-CVE-06** (P0) Danh sách nguồn OSV được phép là **dữ liệu khai báo** (allowlist theo license); mặc định loại `CC-BY-SA-4.0` (Ubuntu).
  AC: test bản ghi từ nguồn bị loại không bao giờ xuất hiện trong finding/report.
- [ ] **FR-CVE-07** (P0) Attribution: báo cáo HTML/PDF + README + `--version`/About mang câu thông báo NVD nguyên văn ("This product uses the NVD API but is not endorsed or certified by the NVD."), danh sách nguồn OSV đã dùng kèm license, ghi nguồn KEV; `docs/DATA_SOURCES.md` liệt kê nguồn/license/link.
  AC: test báo cáo có câu thông báo NVD khi có dùng dữ liệu NVD.
- [ ] **FR-CVE-08** (P0) API key NVD đọc từ biến môi trường `NVD_API_KEY` của **chính khách**; không có key → giới hạn công khai hoặc snapshot offline. Không có key nào trong repo/image/gói phát hành (secret scan CI).
- [ ] **FR-CVE-09** (P1) Snapshot dữ liệu offline cho Enterprise/không internet: lệnh `vulndb update` tạo gói có ngày, chữ ký, metadata license; cảnh báo khi snapshot quá cũ.
- [ ] **FR-CVE-10** (P1) OSV cho thư viện JS phát hiện ở trang (FR-CVE-04); NVD/CPE cho phần mềm máy chủ (nginx, Apache, PHP...). Finding ghi rõ phiên bản là **suy đoán** từ banner, confidence tương ứng.
  `[CONFIRM-LEGAL]` điều khoản NVD/OSV/KEV trước khi phát hành thương mại; chi tiết `docs/DECISIONS-S14-S20.md` mục 5.

### E11. Khám phá tài sản (asset discovery)

- [ ] **FR-ASSET-01** (P1 · Business) Liệt kê subdomain **thụ động** (Certificate Transparency, DNS công khai) cho domain đã xác minh; cho phép người dùng chọn subdomain nào được thêm vào phạm vi quét.
- [ ] **FR-ASSET-02** (P1 · Business) Phát hiện host/port web phổ biến (80/443/8080/8443) của subdomain đã chọn; **không** quét cổng rộng (ngoài phạm vi web) trừ khi có yêu cầu riêng `[CONFIRM]`.
- [ ] **FR-ASSET-03** (P2 · Business) Phát hiện subdomain takeover (CNAME trỏ dịch vụ đã hủy) ở mức bằng chứng DNS/HTTP công khai.
- [ ] **FR-ASSET-04** (P2 · Enterprise) Inventory hợp nhất: domain → subdomain → ứng dụng → API endpoint, có gắn chủ sở hữu/nhóm, lần quét cuối, mức rủi ro.

### E12a. Web UI cục bộ (đã có) – hoàn thiện để bán được

Theo D1: Web UI chạy chung tiến trình với scanner. Các mục dưới đây thay cho FR-PLAT-09/10 ở giai đoạn hiện tại.

- [x] **FR-WEB-01** (P0 · all) *(xong ở Sprint 3: `output.py`, AT-31; `--fail-on` và redact nối vào cùng chỗ ở FR-CI-01, FR-AUTH-02)* **Một nguồn sự thật**: Web UI và CLI cùng gọi `run_scan()` và cùng bộ xử lý đầu ra (redact, sort, `schema_version`, `fingerprint`, `gate_failed` theo `--fail-on`). JSON thêm của Web UI (`gate_failed`, `report_id`, `report_url`) được khai báo trong schema.
  AC: contract test cho `POST /api/scan` và `GET /api/report/<id>.html` (mã lỗi, Content-Type, schema); test so sánh JSON của CLI và Web UI cho cùng mock target.
- [x] **FR-WEB-02** (P0 · all) *(xong ở Sprint 9: `--allow-remote` bắt buộc khi bind ngoài loopback, token ngẫu nhiên sinh và in một lần, kiểm tra Host/Origin giữ nguyên; SRS AT-56. Ô tick bị bỏ sót tới đợt audit 2026-10-04)* **Giữ an toàn mặc định của server cục bộ**: mặc định bind `127.0.0.1`; bind địa chỉ khác phải qua cờ tường minh kèm cảnh báo và **bắt buộc token truy cập**; giữ kiểm tra Host/Origin/Content-Type/kích thước body và bổ sung test cho từng kiểm tra (chống DNS rebinding, CSRF từ trang khác); header bảo mật cho chính trang UI (CSP, `X-Content-Type-Options`, `frame-ancestors 'none'`).
  AC: request Host/Origin lạ → 403; body quá lớn → 413; thiếu `authorized` → 400; tool tự quét UI của chính nó không ra finding header mức MEDIUM trở lên.
- [ ] **FR-WEB-03** (P1 · all) **Quét không chặn request**: chạy scan trong worker thread với `scan_id`; `POST /api/scan` trả ngay `202 + scan_id`; `GET /api/scan/<id>` trả trạng thái/giai đoạn/số finding tạm; nút hủy. Vẫn giới hạn một (hoặc N cấu hình) lần quét đồng thời.
  AC: quét target chậm (mock delay) không làm trình duyệt timeout; hủy dừng các request còn lại.
- [ ] **FR-WEB-04** (P1 · all) **Lưu báo cáo tùy chọn** ra thư mục cục bộ (JSON + HTML) thay vì chỉ 20 bản trong bộ nhớ; chính sách giữ/xóa cấu hình được; không lưu khi evidence chưa redact.
  AC: khởi động lại server vẫn mở được báo cáo đã lưu; `report_id` không đoán được (chuỗi ngẫu nhiên ≥ 128 bit, hiện là `secrets.token_urlsafe(16)`) và không cho path traversal.
- [ ] **FR-WEB-05** (P1 · all) Web UI hỗ trợ các tùy chọn đã có ở CLI: ngưỡng `fail_on`, timeout, workers (có giới hạn trên), tải JSON/HTML/SARIF.
- [ ] **FR-WEB-06** (P1 · all) Nếu Web UI được bind ra mạng: áp dụng FR-AUTHZ-04 (chặn target IP nội bộ/loopback/metadata) trừ khi có cờ cho phép tường minh.
- [ ] **FR-WEB-07** (P0) *(D8, Sprint 16)* `POST /api/scan` từ chối (HTTP 400, mã lỗi rõ ràng) mọi body có trường thuộc nhóm credential: `auth`, `auth_profile_value`, `password`, `token`, `cookie`, `headers`, `authorization`, `api_key`, `show_secrets` (danh sách khai báo). Quét có đăng nhập (E8) là tính năng CLI/CI, không phải Web UI.
  AC: test cho từng trường; log không in giá trị của trường bị từ chối.
- [ ] **FR-WEB-08** (P1, tùy chọn sau) Cho phép chọn **tên** auth profile đã khai báo trong config khởi động server (`--auth-profiles scanner.toml`); giá trị bí mật đọc từ biến môi trường; UI chỉ thấy tên.
  AC: response API và HTML không chứa giá trị secret; test quét toàn bộ output.

### E12. Nền tảng backend (server, job, API) – Stage 2 (chỉ khi chọn SaaS – D1)

- [ ] **FR-PLAT-01** (P0 · Business) Server (modular monolith) với REST API có OpenAPI: quản lý org, target, scan, finding, report, auth profile.
  AC: tài liệu OpenAPI sinh tự động; mọi endpoint có kiểm tra quyền theo org.
- [ ] **FR-PLAT-02** (P0 · Business) Hàng đợi job + worker chạy lõi scan; trạng thái job (`queued`, `running`, `succeeded`, `failed`, `cancelled`); hủy job đang chạy; timeout cứng.
- [ ] **FR-PLAT-03** (P0 · Business) Lưu kết quả vào PostgreSQL (scan, finding, evidence đã `redact`, log job); migration có phiên bản.
- [ ] **FR-PLAT-04** (P0 · Business) Worker chạy trong container **tách quyền** (không root, filesystem chỉ đọc nếu được, network egress giới hạn theo FR-AUTHZ-04).
- [ ] **FR-PLAT-05** (P1 · Business) API key cho tự động hóa (tạo/thu hồi/xoay vòng, scope theo org, hiển thị một lần, lưu dạng băm).
- [ ] **FR-PLAT-06** (P1 · Business) Webhook khi scan hoàn tất/finding mới (có chữ ký HMAC, retry có backoff).
- [ ] **FR-PLAT-07** (P1 · Business) Giới hạn tài nguyên theo org: số scan đồng thời, hàng đợi công bằng (không để một khách chiếm hết worker).
- [ ] **FR-PLAT-08** (P2 · Enterprise) Triển khai **on-premise** bằng Docker Compose/Helm (chỉ khi khách yêu cầu); hướng dẫn nâng cấp, sao lưu, khôi phục; chạy được offline (CVE data cập nhật thủ công).
- [ ] **FR-PLAT-09** (P0 · Business – chỉ khi SaaS; hiện thay bằng FR-WEB-01) **Hợp đồng API với UI hiện có**: OpenAPI được version hóa (`/v1`), chính sách tương thích ngược, mã lỗi thống nhất, phân trang/lọc/sắp xếp cho danh sách target/scan/finding; UI hiện có chỉ gọi qua API này.
  AC: có contract test (schema) giữa backend và UI; thay đổi phá vỡ tương thích phải nâng version và có changelog. `[CONFIRM]` kiểm tra UI đang gọi những API nào.
- [ ] **FR-PLAT-10** (P1 · Business – chỉ khi SaaS; hiện thay bằng FR-WEB-03) **Tiến độ scan cho UI**: endpoint polling và/hoặc SSE/WebSocket trả trạng thái job, phần trăm/giai đoạn, số finding tạm thời, lỗi non-fatal.

### E13. Lập lịch, retest, lịch sử và so sánh

- [ ] **FR-SCHED-01** (P0 · Business) Lịch scan định kỳ (cron/preset: hằng ngày/tuần/tháng) theo target/profile, múi giờ rõ ràng.
- [ ] **FR-SCHED-02** (P0 · Business) Lưu **lịch sử** các lần quét; so sánh hai lần quét (mới/đã sửa/còn tồn tại) bằng `fingerprint`.
- [ ] **FR-SCHED-03** (P1 · Business) **Retest** một finding hoặc nhóm finding (chạy lại đúng check liên quan) và tự động chuyển trạng thái `fixed` khi không còn tái hiện (cần N lần liên tiếp `[CONFIRM]`).
- [ ] **FR-SCHED-04** (P1 · Business) Cảnh báo khi phát hiện finding mới mức ≥ ngưỡng, hoặc chứng chỉ sắp hết hạn, hoặc mất xác minh domain.
- [ ] **FR-SCHED-05** (P1 · Business) API cung cấp dữ liệu xu hướng rủi ro theo thời gian (số finding theo severity, thời gian trung bình để sửa – MTTR) cho UI hiện có hiển thị.

### E14. Quản lý finding (lifecycle)

- [ ] **FR-FM-01** (P0 · Business) Trạng thái finding: `open` → `in_progress` → `fixed` / `accepted_risk` / `false_positive`; ghi lại người thay đổi, lý do, thời điểm.
- [ ] **FR-FM-02** (P0 · Business) Đánh dấu **false positive** kèm lý do; áp dụng cho cả các lần quét sau (theo `fingerprint`), có thể hoàn tác; có báo cáo tỷ lệ false positive theo check để cải thiện engine.
- [ ] **FR-FM-03** (P1 · Business) **Accepted risk** có thời hạn (hết hạn thì mở lại) và người phê duyệt.
- [ ] **FR-FM-04** (P1 · Business) Gán người phụ trách, nhóm, hạn xử lý (SLA nội bộ theo severity); bình luận/thảo luận trên finding.
- [ ] **FR-FM-05** (P1 · Business) API tìm kiếm, lọc, sắp xếp và thao tác hàng loạt trên finding (UI hiện có gọi các API này).
- [ ] **FR-FM-06** (P1 · Business) Tạo ticket **Jira/GitHub Issues/GitLab Issues/Azure Boards** từ finding, đồng bộ trạng thái hai chiều ở mức cơ bản (E17).
- [ ] **FR-FM-07** (P2 · Enterprise) Chính sách theo org: SLA sửa lỗi theo severity, cảnh báo quá hạn, báo cáo tuân thủ SLA.

### E15. (Đã loại) Giao diện web

UI đã có sẵn (Web UI cục bộ, D1) nên không đưa vào backlog. Phần hoàn thiện Web UI ở tầng backend nằm ở **E12a** (FR-WEB-01..06). Các chức năng trước đây nằm trong E15 (onboarding, white-label, i18n giao diện, dashboard) do đội UI quyết định.

### E16. Người dùng, tổ chức, phân quyền, SSO, audit

- [ ] **FR-IAM-01** (P0 · Business) **Đối chiếu cơ chế xác thực/tài khoản hiện có** của UI/backend (đăng nhập, đặt lại mật khẩu, quản lý user) và chỉ bổ sung phần còn thiếu ở tầng API: token có hạn, chống brute-force (rate limit + khóa tạm), thu hồi phiên. Không làm lại màn hình đăng nhập.
  `[CONFIRM]` danh sách phần đã có.
- [ ] **FR-IAM-02** (P0 · Business) **Multi-tenant**: mọi bản ghi gắn `org_id`; mọi truy vấn phải qua lớp kiểm tra org (test tự động chứng minh không đọc chéo org).
- [ ] **FR-IAM-03** (P0 · Business) Vai trò tối thiểu: `owner`, `admin`, `security`, `developer` (xem finding + báo cáo), `viewer`; ma trận quyền được ghi trong tài liệu và có test.
- [ ] **FR-IAM-04** (P1 · Business) **MFA** (TOTP) cho người dùng của nền tảng; bắt buộc được cho `owner/admin` theo chính sách org.
- [ ] **FR-IAM-05** (P1 · Business) **Audit log** bất biến: đăng nhập, thay đổi target/quyền/auth profile, bắt đầu/hủy scan, xuất báo cáo, thay đổi trạng thái finding; xuất được cho khách.
- [ ] **FR-IAM-06** (P2 · Enterprise) **SSO** (SAML 2.0/OIDC), SCIM provisioning, ánh xạ nhóm IdP → vai trò.
- [ ] **FR-IAM-07** (P2 · Enterprise) Vai trò tùy biến, phân quyền theo nhóm target, chính sách IP allowlist, thời gian hết phiên cấu hình được.

### E17. Tích hợp và thông báo

- [ ] **FR-INT-01** (P1 · Business) Thông báo email và **Slack/Microsoft Teams** (webhook) khi scan xong/finding mới.
- [ ] **FR-INT-02** (P1 · Business) **Jira** (Cloud/Server), GitHub Issues, GitLab Issues, Azure Boards: tạo issue từ finding với mẫu nội dung, gắn link ngược về nền tảng.
- [ ] **FR-INT-03** (P1 · Business) Tích hợp **Git provider** (GitHub/GitLab App) để đăng kết quả lên PR và code scanning (SARIF).
- [ ] **FR-INT-04** (P2 · Enterprise) Xuất dữ liệu sang **SIEM** (syslog/CEF/JSON), **Splunk/Elastic** ở mức webhook/định dạng chuẩn.
- [ ] **FR-INT-05** (P2 · Enterprise) API công khai ổn định (versioning, chính sách deprecate, SDK Python/JS ở mức mẫu).

### E18. Gói dịch vụ, thanh toán, quota

- [ ] **FR-BILL-01** (P0 · all) **Entitlements**: mỗi org có gói với giới hạn (số target/FQDN, số scan/tháng, số user, tính năng bật/tắt – active scan, API scan, SSO, PDF...). Kiểm tra ở một điểm duy nhất (service `entitlements`) và có test.
- [ ] **FR-BILL-02** (P0 · Business) Tích hợp nhà cung cấp thanh toán (Stripe hoặc tương đương): checkout, subscription, nâng/hạ gói, hủy, hóa đơn; **không lưu dữ liệu thẻ**. `[CONFIRM]` nhà cung cấp và quy định hóa đơn điện tử tại Việt Nam.
- [ ] **FR-BILL-03** (P0 · Business) Dùng thử (trial) có giới hạn (target đã xác minh, số scan, hết hạn); chống lạm dụng (một org/miền một lần trial, giới hạn tạo tài khoản).
- [ ] **FR-BILL-04** (P1 · Business) **Metering**: đếm target/scan/request thực tế, hiển thị mức dùng và cảnh báo sắp chạm giới hạn; hành vi khi vượt (chặn mềm, mua thêm add-on).
- [ ] **FR-BILL-05** (P1 · Business) *(D11, Sprint 20)* Quản lý **license key** cho bản CLI Pro/on-premise (ký số, kiểm tra offline, thời hạn, số máy/target); không làm tool ngừng hoạt động bất ngờ trên pipeline khách (cơ chế grace period). Mô hình gói và giá: `docs/DECISIONS-S14-S20.md` mục 6.1 `[CONFIRM]` + duyệt thương mại.
- [ ] **FR-BILL-05a** (P0) Định dạng license: file `license.toml` (dữ liệu + chữ ký **Ed25519**): `license_id`, `customer_id`, `plan`, `max_targets`, `domains` (tùy chọn, Enterprise), `features`, `issued_at`, `expires_at`, `grace_days`.
- [ ] **FR-BILL-05b** (P0) Tool nhúng **khóa công khai**; kiểm tra chữ ký **offline**, không gọi về máy chủ.
  AC: sửa 1 byte dữ liệu → chữ ký sai → chạy chế độ Free + cảnh báo; test license hợp lệ/hết hạn/sai chữ ký/sai định dạng.
- [ ] **FR-BILL-05c** (P0) Công cụ phát hành license **nội bộ** (`tools/issue_license.py`) dùng khóa bí mật lưu **ngoài repo**. Khóa bí mật không bao giờ nằm trong repo, image, CI log.
- [ ] **FR-BILL-05d** (P0) Hết hạn: `grace_days` 14-30 ngày `[CONFIRM]`, sau đó quay về Free + cảnh báo rõ. **Không bao giờ** làm hỏng pipeline của khách; `--fail-on`/exit code chạy như bình thường.
- [ ] **FR-BILL-05e** (P0) Entitlement: một điểm kiểm tra duy nhất (`entitlements.py`) quyết định tính năng/số target theo license; check và reporter chỉ hỏi qua module này.
- [ ] **FR-BILL-05f** (P1) Thu hồi license: danh sách thu hồi đi kèm bản cập nhật tool/snapshot dữ liệu (không cần online).
- [ ] **FR-BILL-05g** (P2) Token online: dịch vụ kích hoạt đếm lượt quét; chỉ làm khi có khách cần.
  Giới hạn chấp nhận `[REC]`: Python có thể bị sửa mã để bỏ qua license; chống lạm dụng dựa vào hợp đồng, không đầu tư obfuscation. Dependency `cryptography` (Apache-2.0/BSD) → `pyproject.toml`, `THIRD_PARTY_LICENSES`, pip-audit.
- [ ] **FR-BILL-06** (P2 · Enterprise) Báo giá/hợp đồng thủ công: gói tùy chỉnh, hóa đơn theo PO, SLA hỗ trợ, thời hạn nhiều năm.

### E19. Bảo mật và quyền riêng tư của chính nền tảng

Đây là điểm khách doanh nghiệp soi kỹ nhất, vì nền tảng nắm credential và danh sách lỗ hổng của họ.

- [ ] **FR-SEC-01** (P0 · Business) **Mã hóa dữ liệu nhạy cảm**: credential/auth profile bằng AES-GCM (envelope encryption, khóa từ secret manager/KMS, không hard-code); TLS cho mọi kết nối; mã hóa ổ đĩa/DB ở tầng hạ tầng.
- [ ] **FR-SEC-02** (P0 · Business) **Cách ly dữ liệu giữa các khách hàng** (xem FR-IAM-02) và giữa các job (worker không giữ trạng thái/tệp của job trước).
- [ ] **FR-SEC-03** (P0 · Business) **Chính sách lưu giữ & xóa dữ liệu**: thời hạn lưu evidence/báo cáo cấu hình theo org, xóa vĩnh viễn khi hủy tài khoản/yêu cầu, ghi rõ trong chính sách quyền riêng tư `[CONFIRM]`.
- [ ] **FR-SEC-04** (P0 · Business) Evidence luôn qua `redact()` **trước khi** ghi DB/log; không lưu toàn bộ body response, chỉ trích đoạn cần thiết và giới hạn kích thước.
- [ ] **FR-SEC-05** (P0 · Business) Bảo vệ ứng dụng: kiểm tra đầu vào, chống CSRF/XSS/SQLi/SSRF/IDOR cho chính nền tảng, header bảo mật, giới hạn tốc độ API, quản lý phụ thuộc (quét SCA + SAST định kỳ), không bật debug ở production.
- [ ] **FR-SEC-06** (P1 · Business) **Data residency**: cho phép chọn vùng lưu dữ liệu (nếu vận hành đa vùng) hoặc triển khai on-premise; công bố rõ vị trí lưu dữ liệu `[CONFIRM]`.
- [ ] **FR-SEC-07** (P1 · Business) Không gửi dữ liệu khách hàng (finding, evidence, cấu hình) sang dịch vụ AI công cộng; nếu dùng AI để giải thích/tóm tắt finding thì chỉ khi có lựa chọn rõ ràng của khách, mô hình/đường truyền được phê duyệt, dữ liệu đã che, không dùng để huấn luyện `[CONFIRM]`.
- [ ] **FR-SEC-08** (P1 · Enterprise) Chương trình tuân thủ của chính đơn vị vận hành: SOC 2 hoặc ISO 27001 (lộ trình), pentest độc lập định kỳ, chính sách công bố lỗ hổng (`security.txt` cho chính nền tảng), quy trình xử lý sự cố + thông báo khách hàng.
- [ ] **FR-SEC-09** (P1 · Business) Chuỗi cung ứng: khóa phiên bản phụ thuộc, SBOM cho từng bản phát hành, ký image/gói phát hành.
- [x] **FR-SEC-10** (P0 · all) *(xong ở Sprint 9: `THIRD_PARTY_LICENSES.md`, không thêm công cụ quét license, `tests/test_licenses.py` đối chiếu với `pyproject.toml`; SRS AT-58. `certifi` là MPL-2.0, đã ghi `[CONFIRM]` cần rà lại trước khi thương mại hóa)* Rà **giấy phép** (license) của toàn bộ phụ thuộc và bộ luật/dữ liệu đi kèm trước khi thương mại hóa; lưu bản kiểm kê (`THIRD_PARTY_LICENSES`).

### E20. Quan sát và vận hành

- [ ] **FR-OPS-01** (P0 · Business) Log có cấu trúc (JSON) có `request_id`/`scan_id`/`org_id`; **không** chứa secret/PII; mức log cấu hình được.
- [ ] **FR-OPS-02** (P1 · Business) Metrics (số scan, thời lượng, tỷ lệ lỗi, độ dài hàng đợi, số finding theo severity) + health check (`/healthz`, `/readyz`).
- [ ] **FR-OPS-03** (P1 · Business) Cảnh báo vận hành (worker chết, hàng đợi kẹt, tỷ lệ lỗi tăng); runbook xử lý sự cố.
- [ ] **FR-OPS-04** (P1 · Business) Sao lưu DB định kỳ + thử khôi phục; kế hoạch nâng cấp không mất dữ liệu.
- [ ] **FR-OPS-05** (P1 · Business) Theo dõi **chi phí** cho mỗi scan/org (thời gian worker, lưu trữ) để kiểm chứng mô hình giá.
- [ ] **FR-OPS-06** (P2 · Enterprise) SLA/độ sẵn sàng mục tiêu và trang trạng thái công khai `[CONFIRM]` cam kết với khách.

### E21. Chất lượng, kiểm thử và benchmark

- [x] **FR-QA-01** (P0 · all) *(xong ở Sprint 6: đo trên cả suite, 47/47 finding ID trong catalog được test tạo ra (trước đó 33/47); mọi rule path chạy qua HTTP; SRS AT-49. FR mới phải kèm test như cũ)* Bộ kiểm thử tự động chạy **offline** bằng mock server (headers, cookies, TLS giả lập, redirect, CORS, path, directory listing, soft-404, robots); bao phủ tất cả FR đang có + FR mới.
- [x] **FR-QA-02** (P0 · all) *(test không-lộ-secret có từ Sprint 3; golden file JSON/SARIF/HTML ở Sprint 6: `tests/golden/`, SRS AT-48)* Test **golden file** cho JSON/SARIF/HTML (snapshot) và test không-lộ-secret (FR-AUTH-02).
- [ ] **FR-QA-03** (P1 · Pro) *(D6, Sprint 14)* **Benchmark độ chính xác** trên ứng dụng cố ý dễ tổn thương chạy **local/nội bộ** trong Docker, ghim theo digest: mock server + Juice Shop (MIT) + VAmPI (MIT) + badssl.com (Apache-2.0) bắt buộc; crAPI (Apache-2.0) để sau; DVWA (GPL-3.0) tùy chọn, chỉ chạy làm mục tiêu quét (không vendor mã) để không phát sinh nghĩa vụ GPL. Đo precision/recall theo từng loại lỗi, lưu kết quả theo phiên bản scanner để phát hiện hồi quy.
- [ ] **FR-QA-03a** (P1) `benchmarks/docker-compose.yml` dựng Juice Shop, VAmPI, badssl trên network nội bộ; image ghim theo digest (`image: name@sha256:...`).
  AC: `docker compose up` không publish cổng ra host ngoài `127.0.0.1`; README ghi lệnh chạy.
- [ ] **FR-QA-03b** (P1) File ground truth cho từng app: `benchmarks/expected/<app>@<digest>.toml` liệt kê finding ID + instance_key mong đợi, và danh sách "không được báo".
  AC: đổi digest mà chưa cập nhật expected → job báo lỗi rõ ràng, không im lặng.
- [ ] **FR-QA-03c** (P1) Script `benchmarks/run.py`: chạy scanner trên từng app, so với expected, tính precision/recall theo nhóm check, xuất `benchmarks/results/<date>.json` + bảng Markdown.
- [ ] **FR-QA-03d** (P1) CI: mỗi PR chỉ test mock server (đã có); workflow theo lịch + `workflow_dispatch` chạy benchmark Docker, lưu artifact, **fail khi precision hoặc recall giảm** so với lần trước (ngưỡng `[CONFIRM]`); trước release chạy thủ công, người phụ trách duyệt.
- [ ] **FR-QA-03e** (P2) Thêm DVWA/crAPI khi cần; ghi license vào `benchmarks/README.md`.
- [ ] **FR-QA-04** (P1 · Pro) **Corpus false positive**: mỗi false positive khách báo → thêm test hồi quy; mục tiêu độ chính xác đặt sau khi có số đo baseline `[CONFIRM]` (không hứa con số khi chưa đo).
- [x] **FR-QA-05** (P1 · Pro) *(xong ở Sprint 11: đo trên mock server theo thời điểm request đến nơi — tốc độ trung bình và không cửa sổ 1 giây nào vượt mức, cho cả nhóm tuần tự và nhóm chạy 5 luồng; AT-63)* Kiểm thử tải/an toàn: chứng minh scanner tuân thủ giới hạn tốc độ và không gây tải bất thường lên mock server.
- [ ] **FR-QA-08** (P1 · all) *(mở ở đợt audit 2026-10-04)* Giữ cho "mọi finding id đều được test sinh ra" (FR-QA-01) luôn đúng bằng máy, không bằng phép đo thủ công: thu thập id của mọi `Finding` mà suite tạo ra trong một lần chạy đầy đủ rồi đối chiếu với `catalog.FINDING_CATALOG`. Hiện AT-49 ghi 47/47 theo số đo ngày 2026-09-30 và con số đó sẽ âm thầm sai khi thêm finding mới. Cần chạy có điều kiện (chỉ khi chạy toàn bộ suite) để `pytest <một file>` không fail oan.
  AC: thêm finding id mới mà không có test sinh ra nó thì CI fail; chạy một file lẻ thì bỏ qua kiểm tra này chứ không fail; AT-49 trỏ tới test mới.
- [ ] **FR-QA-06** (P1 · Business) Kiểm thử phân quyền/đa tenant tự động (không đọc chéo org, chống IDOR trên chính API của nền tảng).
- [ ] **FR-QA-07** (P0 · all) *(cấu hình xong ở Sprint 3; workflow `.github/workflows/ci.yml` ở Sprint 6, SRS AT-47. CI xanh trên GitHub ngày 2026-09-30. Chưa tick: còn chờ admin bật branch protection cho `main`, xem README "Branch protection for main")* CI cho repo: `ruff check` + `ruff format --check`, `pytest` (offline), quét phụ thuộc (ví dụ `pip-audit`), quét secret; ma trận Python 3.9 và bản mới nhất; chặn merge khi fail. Type-check (mypy/pyright) và build image thêm sau.
  AC: cấu hình ruff trong `pyproject.toml`; workflow CI chạy được trên nhánh mẫu; README ghi lệnh chạy cục bộ.

### E22. Tài liệu và tài sản đưa ra thị trường

- [x] **FR-DOC-01** (P0 · all) *(xong ở Sprint 9: rà lại toàn bộ README — link `THIRD_PARTY_LICENSES.md`, mục Docker, số AT cập nhật, danh sách branch protection khớp `ci.yml`; hai test đối chiếu tự động `tests/test_readme.py` chặn README lệch với SRS/`ci.yml` sau này)* README nêu rõ **phạm vi và giới hạn** (không phải DAST toàn diện ở giai đoạn 1; không thay thế pentest), hướng dẫn cài đặt/chạy/CI.
- [ ] **FR-DOC-02** (P0 · Business) Tài liệu pháp lý cần có (do pháp lý soạn/duyệt `[CONFIRM]`): Điều khoản sử dụng, Chính sách sử dụng chấp nhận được (AUP), Chính sách quyền riêng tư, DPA (nếu xử lý dữ liệu cá nhân), SLA.
- [ ] **FR-DOC-03** (P1 · Business) Tài liệu bảo mật cho khách (security overview): cách bảo vệ dữ liệu, mã hóa, cách ly, retention, quy trình xử lý sự cố; bộ trả lời bảng câu hỏi bảo mật (security questionnaire) mẫu.
- [ ] **FR-DOC-04** (P1 · Pro) Tài liệu người dùng: bắt đầu nhanh, danh mục check (mỗi check: mô tả, vì sao quan trọng, cách sửa), FAQ false positive, cách cấu hình auth/exclusion.
- [ ] **FR-DOC-05** (P1 · Business) Changelog + chính sách phiên bản (SemVer) + thông báo thay đổi schema.
- [ ] **FR-DOC-06** (P1 · Pro) Tài liệu **catalog check** tự sinh từ rules (ID, severity mặc định, OWASP/CWE, tier).
- [ ] **FR-DOC-07** (P0) *(D11, Sprint 20)* Mẫu văn bản ủy quyền quét (scope: domain/IP, khung giờ, loại check, đầu mối khẩn cấp, chữ ký) – `[CONFIRM-LEGAL]`.
- [ ] **FR-DOC-08** (P0) Mẫu thỏa thuận pilot (thời hạn, giá, xử lý dữ liệu, giới hạn trách nhiệm) – `[CONFIRM-LEGAL]`.
- [ ] **FR-DOC-09** (P1) Biểu mẫu phản hồi pilot + bảng theo dõi chỉ số pilot (tỷ lệ false positive, thời gian khách sửa lỗi, tính năng dùng nhiều nhất, mức giá sẵn sàng trả). 3-5 khách thử nghiệm: dogfooding TECHVIFY (1) + khách hiện có (1-2, văn bản ủy quyền, không vi phạm NDA) + SME qua mạng lưới (1-2); chi tiết `docs/DECISIONS-S14-S20.md` mục 6.3.

---

## 6. Mô hình dữ liệu (mức khái niệm, cho Stage 2)

```text
Organization(id, name, plan_id, created_at)
User(id, org_id, email, role, mfa_enabled, ...)
Target(id, org_id, url, type[web|api], verified_at, verify_method, scope_json, exclusions_json)
AuthProfile(id, org_id, name, type, secret_ref /*mã hóa, không plaintext*/, ...)
ScanProfile(id, org_id, name, mode[config|crawl|active], limits_json, schedule_cron, auth_profile_id)
Scan(id, org_id, target_id, profile_id, status, started_at, finished_at, scanner_version, rules_version, errors_json)
Finding(id, org_id, scan_id, target_id, rule_id, fingerprint, instance_key, severity, confidence,
        owasp, cwe, title, description, evidence_redacted, recommendation, url, first_seen, last_seen)
FindingState(finding_fingerprint, org_id, status, assignee_id, reason, expires_at, updated_by, updated_at)
Report(id, org_id, scan_id, format, created_at, storage_ref)
Integration(id, org_id, type, config_ref, enabled)
ApiKey(id, org_id, hash, scopes, created_at, last_used_at, revoked_at)
AuditLog(id, org_id, actor_id, action, object_type, object_id, at, meta_json /*đã redact*/)
Plan(id, limits_json, features_json)  Usage(org_id, period, metric, value)
```

Nguyên tắc: `fingerprint` là khóa xuyên các lần quét; `FindingState` tách khỏi `Finding` để trạng thái (false positive, accepted risk) tồn tại qua các lần scan; secret chỉ lưu tham chiếu/mã hóa.

## 7. Phác thảo REST API (Stage 2)

| Nhóm | Endpoint (gợi ý) |
|---|---|
| Target | `POST /targets`, `POST /targets/{id}/verify`, `GET /targets` |
| Scan | `POST /scans`, `GET /scans/{id}`, `POST /scans/{id}/cancel`, `GET /scans/{id}/report?format=html\|pdf\|sarif\|json` |
| Finding | `GET /findings?target=&severity=&status=`, `PATCH /findings/{fingerprint}` (đổi trạng thái) |
| Schedule | `POST /schedules`, `GET/PATCH/DELETE /schedules/{id}` |
| Admin | `/users`, `/api-keys`, `/integrations`, `/audit-logs` |

Mọi endpoint: xác thực, kiểm tra org, rate limit, ghi audit khi thay đổi dữ liệu, trả lỗi không lộ chi tiết nội bộ.

## 8. Yêu cầu phi chức năng bổ sung

| ID | Yêu cầu |
|---|---|
| NFR-COM-01 | Không có thành phần nào bị cấm thương mại hóa theo license (FR-SEC-10). |
| NFR-COM-02 | Mọi tuyên bố trong tài liệu marketing/báo cáo phải kiểm chứng được (không nói "phát hiện 100%", "đảm bảo an toàn"). |
| NFR-PERF-04 | Thời gian quét mục tiêu và mức tải tối đa lên target được **đo và công bố** sau khi có benchmark; không cam kết trước khi đo `[CONFIRM]`. |
| NFR-SCALE-01 | Thiết kế worker stateless để tăng số worker ngang; chưa dùng Kubernetes cho đến khi có nhu cầu rõ ràng và người duyệt kiến trúc. |
| NFR-REL-03 | Job có thể phục hồi/thử lại an toàn (idempotent); một target hỏng không làm hỏng job của target khác. |
| NFR-PRIV-01 | Tuân thủ quy định quyền riêng tư áp dụng (ví dụ luật/nghị định bảo vệ dữ liệu cá nhân của Việt Nam, GDPR nếu có khách EU) `[CONFIRM]` với pháp lý. |
| NFR-I18N-01 | API trả mã ổn định (`finding id`, mã lỗi) kèm chuỗi mặc định; việc bản địa hóa hiển thị do UI hiện có đảm nhiệm. |

## 9. Lộ trình theo giai đoạn (không kèm ước lượng thời gian)

### 9.1 Thứ tự sprint cho Phase A (theo feedback review trong VS Code)

Thứ tự dựa trên phụ thuộc: `redact()` và `fingerprint`/`schema_version` là nền cho baseline CI, so sánh và SARIF, nên làm trước.

| Sprint | Nội dung | FR | Trạng thái |
|---|---|---|---|
| 1 | Chốt 3 câu hỏi: UI, redact cookie, mức CORS | D1, D2, D3 (mục 1.4) | Xong |
| 2 | Thêm `CLAUDE.md`, đưa backlog + SRS vào `docs/`; SRS v1.2; sửa FIX-01/02/04/08 và README | FR-FIX-01/02/04/08 | Xong trên branch `docs/sprint-2-srs-v1.2`, chờ review |
| 3 | Cấu hình `ruff` + `pyproject.toml`; `redact()` + mô hình finding (fingerprint, `schema_version`) + Web UI dùng chung đầu ra; CORS theo D3 | FR-QA-07 (phần cấu hình), FR-AUTH-02, FR-MODEL-01, FR-MODEL-02, FR-WEB-01, FR-FIX-07 | Xong (v1.2.0) trên branch `feat/sprint-3`, chờ review |
| 3b | Scope khi theo redirect (D4); redirect check luôn chạy; header/HSTS xét trên response cuối; bỏ chữ "Passive" trong code | FR-FIX-09, FR-FIX-10, FR-FIX-11 (+ FR-AUTHZ-03 phần D4) | Xong (v1.3.0) trên branch `feat/sprint-3b`, chờ review |
| 4 | Kiểm tra nội dung file nhạy cảm + confidence | FR-DET-01, FR-DET-02, FR-DET-03 (+ FR-DET-16, FR-EXP-01 dạng rules, đọc body có giới hạn) | Xong (v1.4.0) trên branch `feat/sprint-4`, chờ review |
| 5 | `--ca-bundle` (gỡ B1), `--fail-on`, SARIF, `--html`, template CI | FR-CI-10, FR-CI-01 (+ exit code 3), FR-RPT-02, FR-RPT-09, FR-CI-03 | Xong (v1.5.0) trên branch `feat/sprint-5`, chờ review |
| 6 | Lint (ruff) + CI cho repo | FR-QA-07 (+ FR-QA-01/02) | Xong (v1.5.1) trên branch `feat/sprint-6`, chờ review; CI xanh trên GitHub ngày 2026-09-30 |
| 7 | README tiếng Anh + hướng dẫn CI/CD và branch protection; Python ≥ 3.12; sửa lỗi từ code review (redact, TLS cũ, cookie, giới hạn đọc, Web UI 500, IPv6); refactor gate/severity | FR-DOC-01 (một phần), NFR-PORT-01, NFR-SEC-04, FR-TLS-01, FR-COOKIE-01, NFR-PERF-04, FR-UI-05 | Xong (v1.6.0) trên branch `feat/sprint-7`, chờ review; CI xanh trên GitHub |
| 8 | Nhóm mục tiêu kiểm thử: chọn nhóm khi quét (CLI `--checks`, Web UI), kết quả và báo cáo HTML nhóm theo test target / OWASP Top 10 | SRS 4.11 (FR-GRP-01…03), FR-UI-07, FR-UI-10, FR-UI-11 (yêu cầu của chủ sản phẩm ngày 2026-09-30) | Xong (v1.7.0) trên branch `feat/sprint-8`, chờ review |
| 9 | Đóng Phase A: Web UI bắt buộc token khi bind ra ngoài, phạm vi & giới hạn trong mọi báo cáo, kiểm kê license, image Docker chính thức, rà lại README | FR-WEB-02, FR-RPT-08, FR-SEC-10, FR-CI-04, FR-DOC-01 | Xong (v1.8.0) trên branch `feat/sprint-9`, chờ review |
| 10 | Điểm số CVSS v3.1 ước tính theo loại finding; báo cáo HTML đầy đủ (top issues, điểm rủi ro, cách tái hiện); Web UI hiện cùng điểm đó; sửa bảng vector theo review ngày 2026-10-01 và đưa điểm vào SARIF | FR-MODEL-03, FR-RPT-01, FR-RPT-10, FR-DET-17, SRS FR-UI-12 | Xong (v1.13.0) trên branch `feat/sprint-10`, chờ review |
| 11 | Kiểm soát quét an toàn: giới hạn tốc độ/số request/thời lượng, tự giảm tốc khi target đẩy lùi, phạm vi khai báo nhiều host, loại trừ URL, header scan id | FR-AUTHZ-05, FR-AUTHZ-03, FR-AUTHZ-06, FR-AUTHZ-09, FR-QA-05 | Xong (v1.14.0) trên branch `feat/sprint-11`, chờ review; CI xanh trên GitHub |
| 12 | CI với nợ cũ: baseline (chỉ fail vì finding mới), so sánh hai lần quét, suppression có hạn, CSV và JUnit; sửa fingerprint không ổn định | FR-CI-02, FR-RPT-06, FR-MODEL-06, FR-RPT-03, FR-MODEL-07 | Xong (v1.15.0) trên branch `feat/sprint-12`, chờ review; CI xanh trên GitHub |
| 13 | File cấu hình, nhiều target, tham số vận hành (proxy, header, cookie, User-Agent, quiet/verbose) | FR-CI-06, FR-CI-05, FR-CI-07 (+ mở FR-CI-11) | Xong (v1.16.0) trên branch `feat/sprint-13`, chờ review; CI xanh trên GitHub |
| 13b | Audit chất lượng toàn hệ thống (không thêm tính năng): 4 lỗi ở v1.17.0; rà độ chặt assertion của AT-02…AT-77 và đối chiếu từng mục `[x]` của backlog ở v1.18.0, kèm mutation test 18/18 bất biến lõi | — | Xong (v1.18.0) trên branch `feat/sprint-13`, chờ review |

**Đợt kế tiếp – sprint 14-20 (quyết định D6-D11, chốt 2026-10-04; không trùng với "Phase A/B/C/D" ở mục 9.2, vốn là các giai đoạn lộ trình rộng hơn).** Số sprint dưới đây là nhãn chủ đề kế thừa từ `docs/DECISIONS-S14-S20.md`, không phải thứ tự chạy. **Thứ tự chạy thật:** 16 → 14 → 15 → 17 → 18 → 20 (bảng liệt kê đúng theo thứ tự chạy này).

| Thứ tự | Sprint | Nội dung | FR | Trạng thái |
|---|---|---|---|---|
| 1 | 16 | Web UI không nhận credential (D8): `/api/scan` từ chối mọi trường credential | FR-WEB-07 (+ FR-WEB-08 tùy chọn) | Chưa làm |
| 2 | 14 | Benchmark độ chính xác (D6): Juice Shop/VAmPI/badssl trong Docker, ground truth, precision/recall, CI theo lịch | FR-QA-03a…e | Chưa làm |
| 3 | 15 | Dò chủ động phiên bản TLS và cipher (D7): tự viết, không sslyze/testssl.sh; giới hạn số handshake | FR-DET-04a…e | Chưa làm |
| 4 | 17 | Parse OpenAPI/Swagger bằng PyYAML + tự resolve `$ref` nội bộ, chặn SSRF/path traversal/bomb (D9) | FR-API-01a…d | Chưa làm |
| 5 | 18 | Dữ liệu lỗ hổng NVD/OSV/KEV: attribution, loại nguồn CC-BY-SA, không nhúng API key (D10) | FR-CVE-05…10 | Chưa làm |
| 6 | 20 | Gói/giá, license key Ed25519 offline, khách thử nghiệm (D11) | FR-BILL-05a…g, FR-DOC-07…09 | Chưa làm |

Ghi chú `[REC]`: có thể đưa phần cấu hình ruff của Sprint 6 lên làm ngay đầu Sprint 3 (rẻ, giúp mọi code mới sạch từ đầu); workflow CI đầy đủ giữ ở Sprint 6. FR-WEB-02 (an toàn server cục bộ) nên làm ngay sau Sprint 6 nếu Web UI sẽ được giao cho khách.

### 9.2 Các phase

> Ước lượng công sức/thời gian và giá bán thuộc quyết định thương mại, cần người có thẩm quyền xác nhận sau khi có thông tin về đội ngũ và thị trường.

| Giai đoạn | Nội dung chính | Điều kiện hoàn thành (exit criteria) |
|---|---|---|
| **Phase A – Củng cố** | Sprint 1–6 (mục 9.1), rồi phần P0 còn lại của E0, E1, E2, E3, E4, E12a, E21, E22 | Không còn lỗi tài liệu đã biết; false positive path/TLS được xử lý và có test; HTML + SARIF + JSON hợp lệ; template CI chạy được trên repo mẫu; secret không rò rỉ trong output |
| **Phase B – Sản phẩm CLI bán được (MSP-1)** | E5 (P0), E6 (P0/P1), E7 (P0), E8 (P0), E10 (P1), E4 còn lại, E18 (license key/entitlement cho CLI) | Scan được web nhiều trang + API (OpenAPI) + xác thực đơn giản; xác minh domain; benchmark trên app thử nghiệm local có số đo baseline; tài liệu người dùng + pháp lý (ToS/AUP) đã được duyệt; khách thử nghiệm đầu tiên |
| **Phase C – Nền tảng dịch vụ (chỉ khi chọn SaaS – D1)** | E12, E13, E14, E16 (P0), E17, E18 (thanh toán), E19 (P0), E20 | Multi-tenant có test không đọc chéo org; lịch quét, lịch sử, finding lifecycle; thanh toán + quota hoạt động; SSRF guard + mã hóa credential được security review độc lập |
| **Phase D – Chiều sâu & enterprise** | E9, E11, E16 (SSO/SCIM), E19 (P1/P2), E14 (P2), E12 (on-premise) | Active checks có kiểm soát và được review pháp lý/bảo mật; SSO; audit log; roadmap SOC 2/ISO 27001 khởi động |

Điều chỉnh so với SRS v1.0 mục 11 `[REC]`: nâng **Multi-target** từ Thấp lên P1; thêm **API scan** và **authenticated scan** (chưa có trong SRS); kéo **báo cáo HTML** và **CI/CD mẫu** vào Phase A.

## 10. Ngoài phạm vi ở giai đoạn này (non-goals)

- SAST/SCA cho mã nguồn khách, ASPM, bug bounty, IAST – thị trường đông đối thủ mạnh, làm loãng sản phẩm.
- Brute-force đăng nhập thật, DoS/stress test, khai thác thực tế (exploitation) hoặc post-exploitation.
- Quét cổng/dịch vụ mạng ngoài web/API (network scanner) trừ khi có quyết định riêng.
- Microservices, Kubernetes, vector DB, AI agent – chưa có lý do rõ ràng (xem mục 3, nguyên tắc số 5).
- Cam kết chứng nhận tuân thủ (PCI/ISO/SOC 2) thay khách hàng; sản phẩm chỉ hỗ trợ bằng chứng/ánh xạ.

## 11. Rủi ro chính và câu hỏi mở

| # | Rủi ro / câu hỏi | Giảm thiểu / hành động |
|---|---|---|
| R1 | Quét nhầm/không phép gây hậu quả pháp lý hoặc gián đoạn dịch vụ | FR-AUTHZ-01..10, ToS/AUP, kill switch, safe mode; pháp lý duyệt |
| R2 | False positive làm mất niềm tin | FR-DET-01..03, FR-QA-03/04, FR-FM-02 |
| R3 | Nền tảng bị tấn công (giữ credential + lỗ hổng của khách) | E19, pentest độc lập, cách ly worker, mã hóa |
| R4 | SSRF/lạm dụng scanner để tấn công bên thứ ba | FR-AUTHZ-01, FR-AUTHZ-04, giới hạn tốc độ, audit |
| R5 | License của engine/dữ liệu bên ngoài không cho thương mại hóa | FR-SEC-10; kiểm tra trước khi nhúng |
| R6 | Cạnh tranh với công cụ miễn phí/đã có thương hiệu | Tập trung khách/nhu cầu cụ thể (câu hỏi Q1); giá trị ở độ chính xác + quy trình |
| R7 | Đội phát triển quá tải khi làm hết các epic | Làm theo phase; chỉ P0 trước khi thu tiền |
| Q1 | Khách mục tiêu là ai (SMB, doanh nghiệp tuân thủ, dev/CI)? | Phỏng vấn khách tiềm năng trước Phase B `[CONFIRM]` |
| Q2 | Bán dạng CLI, SaaS hay on-premise trước? | Quyết định sau Q1; ảnh hưởng thứ tự Phase C/D |
| Q3 | Mô hình tính phí (target/user/gói) và giá | Thử nghiệm với khách thật `[CONFIRM]` |
| Q4 | Tự viết engine hay tích hợp mã nguồn mở? | ADR + kiểm tra license + PoC so sánh độ chính xác |

---

## Phụ lục A – Bản đồ trả lời "vì sao khách trả tiền" → epic

| Lý do khách trả tiền | Epic liên quan |
|---|---|
| Xác minh quyền sở hữu, an toàn pháp lý | E5 |
| Scan web (crawl, SPA, Top 10) | E1, E6, E9 |
| Scan API | E7 |
| Scan có xác thực | E8 |
| Ít false positive | E1, E14 (FM-02), E21 |
| Báo cáo | E3 |
| Quản lý finding, lịch sử, so sánh | E13, E14 |
| Nhiều người dùng, phân quyền, SSO | E16 |
| Lịch quét, retest | E13 |
| CI/CD | E4, E17 |
| Ánh xạ tuân thủ | E2 (MODEL-04), E3 (RPT-07) |
| Khám phá tài sản | E11 |
| Kiểm soát quét an toàn | E5 |
| Nền tảng đáng tin (mã hóa, cách ly, retention) | E19 |
| Thanh toán, gói dịch vụ | E18 |

## Phụ lục B – Bảng theo dõi tiến độ (điền khi làm)

| Epic | P0 xong | P1 xong | P2 xong | Ghi chú |
|---|---|---|---|---|
| E0 | ☑ | ☑ | – | FIX-01…11 xong (Sprint 2–3b) |
| E1 | ☐ | ☐ | ☐ | DET-01, 02, 03 (P0) và DET-16 (P1) xong ở Sprint 4; DET-17 (P1) xong ở Sprint 10; còn DET-04 (P0) |
| E2 | ☑ | ☐ | – | MODEL-01, 02 xong (Sprint 3); MODEL-03 (P1) xong (Sprint 10); MODEL-06 (P1), MODEL-07 (P0) xong (Sprint 12); MODEL-05 một phần |
| E3 | ☑ | ☐ | ☐ | RPT-02, RPT-09 xong (Sprint 5); RPT-08 xong (Sprint 9); RPT-01, RPT-10 xong (Sprint 10); RPT-03, RPT-06 xong (Sprint 12) |
| E4 | ☑ | ☑ | ☐ | CI-01, CI-03, CI-10 xong (Sprint 5); CI-04 xong (Sprint 9); CI-02 xong (Sprint 12); CI-05, 06, 07 xong (Sprint 13); còn CI-08, CI-11 (cả hai P2) |
| E5 | ☐ | ☐ | – | AUTHZ-03 (D4 ở Sprint 3b, phần còn lại ở Sprint 11), AUTHZ-05, AUTHZ-06, AUTHZ-09 xong (Sprint 11); còn AUTHZ-01, 02, 04, 07, 08, 10 |
| E6 | ☐ | ☐ | ☐ | |
| E7 | ☐ | ☐ | ☐ | |
| E8 | ☐ | ☐ | ☐ | AUTH-02 xong (Sprint 3) |
| E9 | – | ☐ | ☐ | |
| E10 | – | ☐ | ☐ | |
| E11 | – | ☐ | ☐ | |
| E12a | ☑ | ☐ | – | Web UI cục bộ; WEB-01 xong (Sprint 3), WEB-02 xong (Sprint 9) |
| E12–E14, E16–E20 | ☐ | ☐ | ☐ | E15 (UI) đã loại; E12 chỉ khi SaaS |
| E21–E22 | ☐ | ☐ | – | QA-01, QA-02 xong (Sprint 6); QA-05 xong (Sprint 11); QA-07 chờ branch protection; README tiếng Anh (Sprint 7); DOC-01 xong (Sprint 9) |

*Tài liệu này là backlog định hướng, không phải cam kết với khách hàng. Mọi quyết định về giá, thời gian, SLA, pháp lý và kiến trúc lớn cần con người có thẩm quyền xem xét trước khi thực hiện.*

