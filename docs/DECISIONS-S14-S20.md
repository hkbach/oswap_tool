# DECISIONS D6–D11 – Quyết định và việc cần làm cho các gói việc tiếp theo

> Tên file giữ `S14-S20` vì lý do lịch sử. **Tài liệu này gọi các gói việc theo tên quyết định (D6…D11), không theo số sprint**, vì `docs/PHASE-B-ROADMAP.md` đã dùng Sprint 14–20 theo nghĩa khác (14 crawler, 15 chiều sâu check thụ động, 16 quét có đăng nhập, 17 quét API, 18 A06).

> Dùng khi vibe-code cùng Claude trong VS Code: `@docs/DECISIONS-S14-S20.md @docs/PRODUCT-BACKLOG.md @CLAUDE.md`.
> Nối tiếp quyết định D1–D5 trong `docs/PRODUCT-BACKLOG.md` mục 1.4 (D1–D5 đã chốt ngày 2026-09-30; D6–D11 dưới đây chốt ngày 2026-10-04). Ngày lập: 2026-10-04.
> Thông tin license/điều khoản tra cứu ngày 2026-10-04. **Không phải tư vấn pháp lý** – các mục gắn `[CONFIRM-LEGAL]` cần pháp lý xác nhận theo đúng phiên bản sử dụng trước khi phát hành thương mại.

**Nhãn:** `[FACT]` đã tra cứu · `[REC]` khuyến nghị · `[CONFIRM]` chủ sản phẩm chốt · `[CONFIRM-LEGAL]` pháp lý chốt.

**Thứ tự thực hiện đã chốt (2026-10-04):** D8 → D6 → D7 → D9 → D10 → D11 (xem mục 7 và `docs/PRODUCT-BACKLOG.md` mục 9.1). Bản nháp đầu gọi các gói này là Sprint 16 → 14 → 15 → 17 → 18 → 20.

---

## 0. Bảng quyết định

| ID | Thứ tự chạy | Câu hỏi | Quyết định đề xuất | Trạng thái |
|---|---|---|---|---|
| **D6** | 2 | Benchmark dùng app nào, chạy ở đâu? | Mock server + Juice Shop + VAmPI + badssl.com (tự host); crAPI để sau; DVWA tùy chọn. PR chạy mock; benchmark Docker chạy theo lịch + thủ công trước release. | `[CONFIRM]` |
| **D7** | 3 | Dò chủ động phiên bản TLS còn "non-intrusive"? | **Có**, nếu chỉ dùng handshake chuẩn, số kết nối có giới hạn, không gửi bản tin dị dạng. Tự viết bộ dò, **không** dùng sslyze (AGPL-3.0). | `[CONFIRM]` |
| **D8** | 1 | Web UI có nhận credential? | **Không.** Quét có đăng nhập chỉ ở CLI/CI; secret chỉ qua biến môi trường/config. | Đã đồng ý |
| **D9** | 4 | Parse OpenAPI bằng thư viện hay tự viết? | PyYAML (`safe_load`) + `json` chuẩn + tự xử lý `$ref` nội bộ. Không dùng prance. Chặn `$ref` ra ngoài. | `[CONFIRM]` |
| **D10** | 5 | Điều khoản NVD/OSV/KEV? | Dùng được, kèm nghĩa vụ ghi chú/attribution; không nhúng API key NVD vào bản cài; loại nguồn OSV CC-BY-SA. | `[CONFIRM-LEGAL]` |
| **D11** | 6 | Gói/giá, license key, khách thử nghiệm? | 2 dòng sản phẩm; license file ký Ed25519 kiểm tra offline; token chỉ cho khách kích hoạt online; 3–5 khách thử nghiệm có ủy quyền bằng văn bản. | `[CONFIRM]` + duyệt thương mại |

---

## 1. Gói D6 – Benchmark độ chính xác

### 1.1 App benchmark `[FACT – license tra ngày 2026-10-04]`

| App | License | Đo gì | Ưu tiên |
|---|---|---|---|
| Mock server trong repo | Của mình | Kết quả mong đợi tuyệt đối, nhanh, ổn định | Bắt buộc |
| OWASP Juice Shop | MIT | Header, cookie, file lộ, SPA crawl | Bắt buộc |
| VAmPI | MIT | Quét API (có OpenAPI 3 + Postman) – dùng cho gói D9 | Bắt buộc |
| badssl.com (tự host Docker) | Apache-2.0 | TLS/chứng chỉ: hết hạn, tự ký, cipher yếu | Bắt buộc |
| OWASP crAPI | Apache-2.0 | OWASP API Top 10 (nhiều container, nặng) | Sau |
| DVWA | GPL-3.0 | Ứng dụng PHP cổ điển | Tùy chọn |

**Quy tắc license:** chỉ chạy app làm mục tiêu quét → không phát sinh nghĩa vụ GPL. **Không** copy mã/vendor các app này vào repo hay gói sản phẩm; chỉ tham chiếu image upstream, ghim theo digest.

**Quy tắc an toàn:** mọi app benchmark chỉ chạy trong mạng Docker nội bộ của máy/runner (DVWA ghi rõ không được đưa ra internet). Không publish cổng ra ngoài.

### 1.2 Việc cần làm

- [ ] **FR-QA-03a** (P1) `benchmarks/docker-compose.yml` dựng Juice Shop, VAmPI, badssl trên network nội bộ; image ghim theo digest (`image: name@sha256:...`).
  AC: `docker compose up` không publish cổng ra host ngoài `127.0.0.1`; README ghi lệnh chạy.
- [ ] **FR-QA-03b** (P1) File kết quả đúng (ground truth) cho từng app: `benchmarks/expected/<app>@<digest>.toml` liệt kê finding ID + instance_key mong đợi, và danh sách "không được báo".
  AC: đổi digest mà chưa cập nhật expected → job báo lỗi rõ ràng, không im lặng.
- [ ] **FR-QA-03c** (P1) Script `benchmarks/run.py`: chạy scanner trên từng app, so với expected, tính precision/recall theo nhóm check, xuất `benchmarks/results/<date>.json` + bảng Markdown.
- [ ] **FR-QA-03d** (P1) CI:
  - Mỗi PR: chỉ test với mock server (đã có).
  - Workflow theo lịch (hằng đêm hoặc hằng tuần) + `workflow_dispatch`: chạy benchmark Docker, lưu kết quả làm artifact, **fail khi precision hoặc recall giảm** so với lần chạy trước (ngưỡng `[CONFIRM]`).
  - Trước release: chạy thủ công, người phụ trách duyệt kết quả.
- [ ] **FR-QA-03e** (P2) Thêm DVWA/crAPI khi cần; ghi license vào `benchmarks/README.md`.

---

## 2. Gói D7 – Dò chủ động phiên bản TLS

### 2.1 Định nghĩa "non-intrusive" mới (cập nhật SRS mục 1.2 và NFR-SEC-01)

> Tool không gửi payload khai thác, không gửi request làm thay đổi dữ liệu, không gửi bản tin giao thức dị dạng; chỉ gửi một số lượng **có giới hạn** request HTTP thông thường và **handshake TLS chuẩn**.

| Được làm (non-intrusive) | Không làm ở chế độ mặc định (thuộc E9 – active) |
|---|---|
| Handshake chuẩn để dò SSLv3/TLS1.0/1.1/1.2/1.3 | Heartbleed, ROBOT, CCS injection |
| Dò **nhóm** cipher yếu (RC4, 3DES, NULL, EXPORT, CBC cũ) | Renegotiation DoS, compression (CRIME) |
| Số kết nối có giới hạn và rate limit | Liệt kê toàn bộ hàng trăm cipher |

### 2.2 Ràng buộc license `[FACT]`

- **sslyze: AGPL-3.0** → không nhúng vào sản phẩm đóng/SaaS.
- **testssl.sh: GPL-2.0** → không đóng gói kèm sản phẩm.
- Quyết định: **tự viết** bộ dò tối thiểu.

### 2.3 Việc cần làm

- [ ] **FR-DET-04a** (P0) Module `checks/tls_probe.py`: với mỗi phiên bản, gửi ClientHello chuẩn và đọc phiên bản trong ServerHello (hoặc alert). Không hoàn tất trao đổi dữ liệu ứng dụng.
  Lưu ý kỹ thuật: OpenSSL 3 trong Python mặc định không bắt tay SSLv3/TLS1.0 qua module `ssl` → cần tự dựng ClientHello tối thiểu bằng `socket` + `struct` (ưu tiên, không phụ thuộc OpenSSL), hoặc chứng minh cấu hình `SECLEVEL=0` hoạt động trên các nền tảng hỗ trợ.
  AC: phát hiện đúng phiên bản bật/tắt trên badssl tự host và mock TLS server; nếu không dò được một phiên bản thì ghi vào `errors` là "không kiểm tra được", không im lặng.
- [ ] **FR-DET-04b** (P0) Dò nhóm cipher yếu với danh sách khai báo (dữ liệu, không hard-code); mỗi nhóm tối đa 1 kết nối.
- [ ] **FR-DET-04c** (P0) Giới hạn tổng số handshake mỗi target (hằng số cấu hình, mặc định ≤ 30) + khoảng nghỉ giữa các kết nối; tôn trọng `--rate-limit`.
  AC: test đếm số kết nối tới mock TLS server không vượt giới hạn.
- [ ] **FR-DET-04d** (P0) Cập nhật mô tả `CheckGroup("tls")` (hiện ghi "2 TLS handshakes") thành con số tối đa mới; cập nhật consent banner và SRS mục 1.2, 4.5, NFR-SEC-01.
- [ ] **FR-DET-04e** (P1) README/tài liệu khách: ghi rõ IDS/WAF có thể ghi log các handshake phiên bản cũ.
- [ ] Cập nhật `THIRD_PARTY_LICENSES` / ADR: ghi lý do không dùng sslyze/testssl.sh.

---

## 3. Gói D8 – Web UI không nhận credential

### 3.1 Quyết định

Web UI **không** nhận, không hiển thị, không lưu credential dưới bất kỳ hình thức nào. Quét có đăng nhập (E8) là tính năng **CLI/CI** (gói Pro). Kênh website online (SaaS) sau này là thiết kế riêng, có mã hóa và cách ly dữ liệu (E19), **không** dùng lại Web UI local.

### 3.2 Việc cần làm

- [ ] **FR-WEB-07** (P0) `POST /api/scan` từ chối (HTTP 400, mã lỗi rõ ràng) mọi body có trường thuộc nhóm credential: `auth`, `auth_profile_value`, `password`, `token`, `cookie`, `headers`, `authorization`, `api_key`, `show_secrets` (danh sách khai báo).
  AC: test cho từng trường; log không in giá trị của trường bị từ chối.
- [ ] **FR-WEB-08** (P1, tùy chọn sau) Cho phép chọn **tên** auth profile đã khai báo trong config khởi động server (`--auth-profiles scanner.toml`); giá trị bí mật đọc từ biến môi trường; UI chỉ thấy tên.
  AC: response API và HTML không chứa giá trị secret; test quét toàn bộ output.
- [ ] Cập nhật `CLAUDE.md` (mục Web UI) và SRS mục 3.3: "Web UI không nhận credential (D8)".

---

## 4. Gói D9 – Parse OpenAPI

### 4.1 Lựa chọn thư viện `[FACT – license từ metadata PyPI 2026-10-04]`

| Lựa chọn | License | Quyết định |
|---|---|---|
| **PyYAML** | MIT | **Dùng**, chỉ `yaml.safe_load` |
| `json` (stdlib) | PSF | **Dùng** |
| openapi-spec-validator | Apache-2.0 | Chưa dùng (kéo ~10 dependency: jsonschema, pydantic...). Xem lại nếu cần kiểm tra spec chặt. |
| prance | MITNFA | **Không dùng** (license biến thể, nhiều dependency, tự resolve `$ref` từ xa) |

### 4.2 Việc cần làm

- [ ] **FR-API-01a** (P0) `api/spec_loader.py`: nhận file `.json`/`.yaml`/`.yml`; YAML dùng `yaml.safe_load` (test: tag `!!python/object` bị từ chối).
- [ ] **FR-API-01b** (P0) Tự resolve `$ref` **nội bộ** (`#/components/...`) và file tương đối **trong cùng thư mục spec**.
  **Cấm:** `$ref` tới URL (`http://`, `https://`, `file://`), đường dẫn tuyệt đối, hoặc `..` thoát khỏi thư mục spec → báo lỗi rõ ràng (chống SSRF và đọc file trái phép).
  AC: test với `$ref` trỏ `http://169.254.169.254/`, `/etc/passwd`, `../../secret.yaml` → đều bị từ chối, không có request mạng.
- [ ] **FR-API-01c** (P0) Giới hạn an toàn: kích thước file (ví dụ ≤ 5 MB), độ sâu lồng/`$ref` (ví dụ ≤ 32), phát hiện `$ref` vòng lặp, số endpoint tối đa (cấu hình).
  AC: test YAML "billion laughs"/alias bomb và `$ref` vòng tròn → lỗi có kiểm soát, không treo.
- [ ] **FR-API-01d** (P0) Hỗ trợ OpenAPI 3.0/3.1 và Swagger 2.0 ở mức đủ để liệt kê server, path, method, tham số, security scheme; lỗi spec không làm crash tool.
  AC: parse thành công spec của VAmPI (benchmark gói D6).
- [ ] Thêm PyYAML vào `pyproject.toml`, `THIRD_PARTY_LICENSES`, pip-audit.
- [ ] Web UI: nếu cho tải spec lên thì áp dụng cùng giới hạn; không nhận URL spec từ xa ở Web UI (giữ đơn giản).

---

## 5. Gói D10 – Dữ liệu lỗ hổng NVD / OSV / KEV

### 5.1 Điều khoản `[FACT – tra ngày 2026-10-04]` `[CONFIRM-LEGAL]`

| Nguồn | Điều khoản chính | Nghĩa vụ của mình |
|---|---|---|
| **NVD API** | Được dùng để xây dịch vụ tra cứu/hiển thị/phân tích dữ liệu NVD. Bắt buộc hiển thị: *"This product uses the NVD API but is not endorsed or certified by the NVD."* Không dùng tên NVD để ngụ ý chứng nhận. API key là của người đăng ký, không chia sẻ. | Hiển thị câu thông báo nguyên văn. **Không nhúng API key của mình vào bản cài cho khách.** |
| **OSV** | Tổng hợp nhiều nguồn, mỗi nguồn license riêng: GitHub, PyPI, Go, OSS-Fuzz, PSF, Erlang = CC-BY 4.0; Rust, Haskell, GSD, opam = CC0; Drupal, AlmaLinux = MIT; Bitnami, OpenSSF Malicious, RConsortium = Apache-2.0; Rocky = BSD; **Ubuntu = CC-BY-SA 4.0**. | Lưu nguồn gốc từng bản ghi; trang attribution; **loại nguồn CC-BY-SA** trừ khi pháp lý đồng ý. |
| **CISA KEV** | CC0 (public domain). | Dùng tự do; ghi nguồn là thực hành tốt. |
| Nội dung mô tả CVE (CVE Program) | Chưa tra cứu trong đợt này. | `[CONFIRM-LEGAL]` trước khi đưa mô tả CVE nguyên văn vào báo cáo thương mại. |

### 5.2 Việc cần làm

- [ ] **FR-CVE-06** (P0) Module `vulndb/` với một lớp nguồn dữ liệu duy nhất; mỗi bản ghi lưu `source`, `source_license`, `retrieved_at`.
- [ ] **FR-CVE-07** (P0) Danh sách nguồn OSV được phép là **dữ liệu khai báo** (allowlist theo license); mặc định loại `CC-BY-SA-4.0`.
  AC: test bản ghi từ nguồn bị loại không bao giờ xuất hiện trong finding/report.
- [ ] **FR-CVE-08** (P0) Attribution:
  - Báo cáo HTML/PDF + README + `--version`/About: câu thông báo NVD nguyên văn, danh sách nguồn OSV đã dùng kèm license, ghi nguồn KEV.
  - File `docs/DATA_SOURCES.md` liệt kê nguồn, license, link.
  AC: test báo cáo có câu thông báo NVD khi có dùng dữ liệu NVD.
- [ ] **FR-CVE-09** (P0) API key NVD: đọc từ biến môi trường `NVD_API_KEY` của **chính khách**; không có key → chạy theo giới hạn công khai hoặc dùng snapshot offline. Không có key nào trong repo, image, gói phát hành (secret scan trong CI).
- [ ] **FR-CVE-10** (P1) Snapshot dữ liệu offline cho bản Enterprise/không internet: lệnh `vulndb update` tạo gói dữ liệu có ngày, chữ ký, và metadata license; tool cảnh báo khi snapshot quá cũ (ngưỡng cấu hình).
- [ ] **FR-CVE-11** (P1) Dùng OSV chủ yếu cho thư viện JavaScript phát hiện ở trang (FR-CVE-04); dùng NVD/CPE cho phần mềm máy chủ (nginx, Apache, PHP...). Finding ghi rõ phiên bản là **suy đoán** từ banner, confidence tương ứng.
- [ ] Kiểm tra lại điều khoản từng nguồn tại thời điểm tích hợp và ghi ngày kiểm tra vào `docs/DATA_SOURCES.md`.

---

## 6. Gói D11 – Gói, giá, license key, khách thử nghiệm

### 6.1 Mô hình gói khi ra mắt `[CONFIRM]` – cần người có thẩm quyền duyệt giá

| Dòng sản phẩm | Gói | Giá đề xuất | Ghi chú |
|---|---|---|---|
| **License tự triển khai** (CLI + Web UI local + CI/CD) | Free | 0đ | Check thụ động, 1 target, không PDF |
| | Team | 12–18 triệu đ/năm | 10 target, quét không giới hạn, SARIF, baseline |
| | Business | 40–60 triệu đ/năm | 50 target, hỗ trợ ưu tiên |
| | Enterprise (offline) | Báo giá, gợi ý từ ~120 triệu đ/năm | Danh sách domain, snapshot dữ liệu offline, hỗ trợ |
| | Gói token (chỉ khi kích hoạt online) | 50 token 1,5 tr · 200 token 4,5 tr · 1.000 token 15 tr | 1 token = 1 lần quét 1 target; hạn 12 tháng |
| **Website online** | Free | 0đ | Chỉ check thụ động, không cần xác minh domain |
| | Báo cáo lẻ | 149.000–199.000đ | Cần xác minh domain |
| | Thuê bao | Làm sau | Khi đã có server, xác minh domain, thanh toán |

**Quy tắc token:** khách offline không đếm được token → khách offline chỉ mua license năm theo số target.

### 6.2 Cơ chế license key

- [ ] **FR-BILL-05a** (P0) Định dạng license: file `license.toml` gồm phần dữ liệu + chữ ký **Ed25519**.
  Trường dữ liệu: `license_id`, `customer_id`, `plan`, `max_targets`, `domains` (tùy chọn, Enterprise), `features` (danh sách), `issued_at`, `expires_at`, `grace_days`.
- [ ] **FR-BILL-05b** (P0) Tool nhúng **khóa công khai**; kiểm tra chữ ký **offline**, không cần gọi về máy chủ.
  AC: sửa 1 byte dữ liệu → chữ ký sai → chạy chế độ Free + cảnh báo; test với license hợp lệ/hết hạn/sai chữ ký/sai định dạng.
- [ ] **FR-BILL-05c** (P0) Công cụ phát hành license **nội bộ** (`tools/issue_license.py`) dùng khóa bí mật lưu **ngoài repo** (secret manager hoặc máy offline). Khóa bí mật không bao giờ nằm trong repo, image, CI log.
- [ ] **FR-BILL-05d** (P0) Hết hạn: `grace_days` 14–30 ngày `[CONFIRM]`, sau đó quay về tính năng Free + cảnh báo rõ trên console/HTML. **Không bao giờ** làm hỏng pipeline của khách; logic `--fail-on`/exit code vẫn chạy như bình thường.
- [ ] **FR-BILL-05e** (P0) Entitlement: một điểm kiểm tra duy nhất (`entitlements.py`) quyết định tính năng/số target theo license; check và reporter chỉ hỏi qua module này.
- [ ] **FR-BILL-05f** (P1) Thu hồi license: danh sách thu hồi đi kèm bản cập nhật tool/snapshot dữ liệu (không cần online).
- [ ] **FR-BILL-05g** (P2) Token online: dịch vụ kích hoạt đếm lượt quét; chỉ làm khi có khách cần.
- [ ] Dependency: `cryptography` (Apache-2.0/BSD) → `pyproject.toml`, `THIRD_PARTY_LICENSES`, pip-audit.
- **Giới hạn cần chấp nhận** `[REC]`: tool viết bằng Python nên có thể bị sửa mã để bỏ qua license; license key phục vụ quản lý khách trung thực, việc chống lạm dụng dựa vào hợp đồng. Không đầu tư obfuscation.

### 6.3 Khách thử nghiệm (pilot) `[CONFIRM]`

| Nhóm | Số lượng | Điều kiện |
|---|---|---|
| Hệ thống của chính TECHVIFY (dogfooding) | 1 | Ủy quyền nội bộ bằng văn bản |
| Khách hiện có của TECHVIFY | 1–2 | Văn bản ủy quyền quét (phạm vi, khung giờ, đầu mối) và không vi phạm NDA/hợp đồng hiện tại |
| Doanh nghiệp vừa và nhỏ qua mạng lưới | 1–2 | Như trên |

**Điều khoản pilot:** miễn phí hoặc giảm giá 60–90 ngày.
**Đo:** tỷ lệ báo sai (finding bị đánh dấu false positive / tổng), thời gian khách sửa lỗi, tính năng được dùng nhiều nhất, mức giá khách sẵn sàng trả; phỏng vấn khi kết thúc.

- [ ] **FR-DOC-07** (P0) Mẫu văn bản ủy quyền quét (scope: domain/IP, khung giờ, loại check, đầu mối khẩn cấp, chữ ký) – `[CONFIRM-LEGAL]`.
- [ ] **FR-DOC-08** (P0) Mẫu thỏa thuận pilot (thời hạn, giá, xử lý dữ liệu, giới hạn trách nhiệm) – `[CONFIRM-LEGAL]`.
- [ ] **FR-DOC-09** (P1) Biểu mẫu phản hồi pilot + bảng theo dõi chỉ số pilot.

---

## 7. Thứ tự làm và mẫu prompt

Thứ tự chạy: D8 (nhỏ, chặn rủi ro) → D6 (cần benchmark trước khi đo D7/D9) → D7 → D9 → D10 → D11.

```text
@docs/DECISIONS-S14-S20.md @CLAUDE.md
Làm gói D8 (FR-WEB-07). Lập kế hoạch trước: file sẽ sửa, test sẽ viết. Chờ tôi duyệt.
```

```text
@docs/DECISIONS-S14-S20.md
Làm gói D6 (FR-QA-03a..d). Chỉ dùng image upstream ghim theo digest, không vendor mã các app.
Mọi container chỉ trên network nội bộ. Viết expected cho VAmPI trước. Chưa động vào scanner.
```

```text
@docs/DECISIONS-S14-S20.md @websec_scanner/checks/tls_check.py
Làm gói D7 (FR-DET-04a..d). Không thêm sslyze/testssl.sh. Tự dựng ClientHello tối thiểu.
Viết test với mock TLS server, chứng minh số handshake không vượt giới hạn.
```

```text
@docs/DECISIONS-S14-S20.md
Làm gói D9 (FR-API-01a..d). Viết test chặn $ref ra ngoài, YAML bomb và $ref vòng lặp trước khi code.
```

## 8. Definition of Done chung

- [ ] `ruff check`, `ruff format --check`, `pytest` sạch; test chạy offline.
- [ ] Dependency mới đã ghi `pyproject.toml`, `THIRD_PARTY_LICENSES`, có trong pip-audit.
- [ ] Không có secret/API key/khóa bí mật trong repo, image, log (secret scan xanh).
- [ ] SRS và `docs/PRODUCT-BACKLOG.md` cập nhật (thêm D6–D11 vào mục 1.4; tick FR).
- [ ] Mục `[CONFIRM-LEGAL]` đã có xác nhận của pháp lý trước khi phát hành thương mại; giá và hợp đồng pilot đã được người có thẩm quyền duyệt.

## 9. Nguồn tra cứu

- NVD API Terms of Use: https://nvd.nist.gov/developers/terms-of-use (bản trích: https://scancode-licensedb.aboutcode.org/nist-nvd-api-tou.html)
- OSV data sources: https://google.github.io/osv.dev/data/
- GitHub Advisory Database (CC-BY 4.0): https://github.com/github/advisory-database
- CISA KEV data (CC0): https://github.com/cisagov/kev-data
- OWASP Juice Shop (MIT): https://github.com/juice-shop/juice-shop
- VAmPI (MIT): https://github.com/erev0s/VAmPI
- badssl.com (Apache-2.0): https://github.com/chromium/badssl.com
- OWASP crAPI (Apache-2.0): https://github.com/OWASP/crAPI
- DVWA (GPL-3.0): https://github.com/digininja/DVWA
- sslyze (AGPL-3.0): metadata gói PyPI `sslyze` 6.3.1
- PyYAML (MIT), openapi-spec-validator (Apache-2.0), prance (MITNFA): metadata gói PyPI ngày 2026-10-04
