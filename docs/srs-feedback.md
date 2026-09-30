# Phản hồi SRS 1.1 sau khi kiểm thử baseline v1.1.0

| | |
|---|---|
| **Gửi** | Chủ SRS – OWASP-Aligned Passive Web Security Scanner |
| **Ngày** | 2026-09-23 |
| **Branch** | `feat/baseline-v1.1.0` |
| **Cơ sở** | Mã nguồn v1.1.0 nguyên trạng (commit baseline) + bộ pytest offline mới cho AT-01…AT-18 |

Bộ test chạy trên Python 3.12 và 3.14 (Windows), toàn bộ trên `127.0.0.1`, không có request nào ra internet. Kết quả trên mã v1.1.0 **chưa sửa**: 65 pass, 10 fail. Sau khi sửa: 76/76 pass.

## Trạng thái xử lý (cập nhật 2026-09-30)

File này là bản ghi review ngày 2026-09-23, giữ lại để truy vết. Requirement hiện hành nằm ở `docs/SRS-owasp-scanner.md` v1.2 và `docs/PRODUCT-BACKLOG.md`.

| Mục | Trạng thái | Nằm ở đâu |
|---|---|---|
| A1–A5 | Đã sửa trong code, đã đưa vào SRS v1.2 | FR-CLI-01, FR-CLI-03, FR-COOKIE-01, FR-EXP-06, FR-REPORT-05; AT-19…AT-23 |
| A6 | Đã sửa trong code; không đổi hành vi nên không cần FR | — |
| B1 | Đã làm ở Sprint 5 (v1.5.0). Đính chính 2026-09-30: thành phần chặn TLS là Avast Web/Mail Shield trên máy dev, không phải proxy mạng TECHVIFY | SRS FR-CLI-06, mục 10; backlog FR-CI-10, FR-DET-16 |
| B2 | Đã làm ở Sprint 5 (v1.5.0): exit code `3` | SRS FR-CLI-04, 7.3 |
| B3 | Đã làm ở Sprint 3b (FIX-09 + D4) | SRS FR-CLI-05, FR-REDIR-01, NFR-SEC-05 |
| B4 | Đã làm ở Sprint 3b (FIX-10 + D5) | SRS FR-HDR-01, FR-HDR-11, mục 6.2 |
| B5 | Đã giải quyết bằng D1 | SRS mục 3.3, 4.10 |
| C (User-Agent `/1.0`) | Đã làm ở Sprint 3b | Backlog FR-FIX-11; SRS NFR-SEC-03 |
| C (các mục còn lại) | Ghi nhận; `--json` không tự tạo thư mục cha đã ghi ở SRS mục 7.2 | — |

## A. Đã sửa trong mã để khớp SRS 1.1 — cần cập nhật câu chữ SRS

| # | Vấn đề (có test chứng minh) | Sửa trong mã | Đề xuất sửa SRS |
|---|---|---|---|
| A1 | **AT-10 và AT-15 fail khi chạy qua CLI.** GET baseline dùng `requests` với xác thực chứng chỉ bật, nên cert hết hạn/tự ký làm baseline lỗi → `run_scan` dừng sớm → không chạy TLS check → 0 finding, exit `0`. Kết quả "đã xác minh bằng TLS thật" ở mục 4.5 chỉ đúng khi gọi thẳng `check_tls()`. | Nếu baseline lỗi **ở tầng TLS** (`requests.exceptions.SSLError`), vẫn chạy TLS check rồi mới dừng. Lỗi kết nối thường (DNS, port đóng) giữ nguyên hành vi AT-11 (0 finding). | Mục 3.2 bước 4 và FR-CLI-03: bổ sung ngoại lệ "nếu baseline thất bại do lỗi TLS, vẫn chạy nhóm 4.5". Mục 4.5: ghi rõ đã xác minh ở mức CLI end-to-end. |
| A2 | Một check ném exception làm crash cả lần quét (vi phạm FR-REPORT-05, NFR-REL-01). | Mỗi check chạy trong `try/except`; lỗi ghi vào `errors` dạng `Check '<tên>' failed: ...`, các check sau vẫn chạy. | Không cần sửa. |
| A3 | Cookie được đặt ở các bước redirect trước trang cuối bị bỏ sót (false negative). | Đọc `Set-Cookie` của response cuối **và** mọi bước redirect; bỏ nhánh dự phòng dùng cookie jar (nhánh này không bao giờ chạy tới). | FR-COOKIE-01: "mỗi `Set-Cookie` của baseline response, bao gồm các response redirect trung gian". |
| A4 | FR-CLI-01 lỗi với dạng `host:port` không có scheme (`example.com:8443`, `localhost:8080`), và gắn `/` sau query string (`...?q=1/`). | Nhận diện scheme bằng `://`; chỉ thêm `/` vào phần path. | FR-CLI-01: nêu rõ hỗ trợ `host:port`, và `/` được thêm vào path, không phải cuối chuỗi. |
| A5 | Khi có soft-404, `security.txt` vẫn bị báo "có mặt" (INFO) dù server trả 200 cho mọi path. | Áp dụng điều kiện soft-404 cho cả `security.txt`. | FR-EXP-06: thêm "và không phát hiện soft-404". |
| A6 | `datetime.utcnow()` deprecated từ Python 3.12. | Dùng `datetime.now(timezone.utc)`, định dạng output giữ nguyên (`...Z`). | Không cần sửa. |

## B. Cần chủ SRS quyết định (chưa sửa)

| # | Vấn đề | Tác động | Đề xuất |
|---|---|---|---|
| B1 | **Hai kho chứng chỉ khác nhau.** `requests` dùng `certifi`, còn TLS check dùng kho chứng chỉ của hệ điều hành. Trên mạng có TLS inspection (quan sát ngày 2026-09-23; *đính chính 2026-09-30:* thành phần chặn TLS là Avast Web/Mail Shield chạy trên máy dev, không phải mạng TECHVIFY), `requests` từ chối **mọi** site HTTPS, trong khi `ssl` chấp nhận. | Tool không quét được target HTTPS nào trong mạng công ty. Báo cáo chỉ có 1 lỗi "Could not fetch", 0 finding, exit `0`. Rủi ro ở mục 10 đang đánh giá thấp vấn đề này. | Thống nhất dùng một kho chứng chỉ: (a) thêm tuỳ chọn `--ca-bundle PATH` dùng chung cho cả `requests` và `ssl`; hoặc (b) dùng kho chứng chỉ của hệ điều hành cho `requests` (thư viện `truststore` cần Python ≥ 3.10, xung đột với NFR-PORT-01 ≥ 3.9). |
| B2 | **Exit code `0` khi quét không hoàn tất.** Theo đúng FR-CLI-04, target không kết nối được (DNS sai, server sập, hoặc B1) vẫn trả `0`. | Pipeline CI sẽ "xanh" dù không quét được gì. | Thêm exit code `3` = "quét không hoàn tất" (baseline thất bại hoặc có check lỗi). Đây là thay đổi hợp đồng CLI nên cần chủ SRS duyệt. |
| B3 | FR-REDIR-01 ghi "chỉ chạy khi đã xác nhận TLS hoạt động", nhưng mã luôn chạy redirect check cho target `https://`. | Nhỏ: có thể báo `TLS-NO-HTTPS-REDIRECT` cho site mà TLS đang hỏng. | Chọn một trong hai: bỏ điều kiện trong SRS, hoặc thêm điều kiện vào mã. |
| B4 | FR-HDR-01 xét `https` theo URL gốc, không theo URL cuối sau redirect. | Nhỏ: target `https://` bị redirect về `http://` vẫn bị yêu cầu HSTS trên response HTTP. | Làm rõ "baseline request" là URL gốc hay URL cuối. |

| B5 | **Giao diện web local** (branch `feat/web-ui`, 2026-09-30) được thêm theo yêu cầu, trong khi SRS mục 2.4 xếp "Giao diện web/GUI" vào phần ngoài phạm vi. | Tài liệu và mã lệch nhau. Chưa có FR/AT cho UI. | Cập nhật mục 2.4 và mục 11. Thêm nhóm FR-UI: chỉ bind loopback theo mặc định; phải tick xác nhận quyền quét (tương đương FR-CONSENT); chặn Host/Origin lạ; mỗi lúc 1 lần quét; kết quả dùng cùng JSON schema mục 6.2. |

## C. Ghi nhận nhỏ, không chặn

- `USER_AGENT` vẫn ghi `TECHVIFY-OWASP-Scanner/1.0` trong khi phiên bản là 1.1.0.
- `--json PATH` không tự tạo thư mục cha nếu chưa có.
- Màu ANSI có thể không hiển thị đúng trên console Windows đời cũ (liên quan NFR-PORT-01). Windows Terminal hiển thị bình thường.
- README ghi "sửa 6 vấn đề", SRS mục 0 ghi 8 (2 điểm chênh là thay đổi chỉ trong tài liệu).
- Trên máy dev Windows có Application Control, lần đầu nạp DLL native của `cryptography` (`_cffi_backend`) bị chặn, các lần sau thì chạy được. Nếu gặp trên máy CI hoặc máy khác, cần IT allowlist.
