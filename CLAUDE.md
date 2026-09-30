# CLAUDE.md – OWASP Scanner

Quy tắc cho Claude khi làm việc trong repo này. Đọc kèm:

- `docs/PRODUCT-BACKLOG.md`: backlog, quyết định D1–D3 (mục 1.4), thứ tự sprint (mục 9.1).
- `docs/SRS-owasp-scanner.md`: đặc tả hành vi hiện có. Không đổi hành vi đã đặc tả nếu không có FR tương ứng.

## Sản phẩm trong một đoạn

Scanner cấu hình bảo mật web không xâm lấn (non-intrusive), viết bằng Python. Có hai lối vào dùng chung một lõi:

- CLI: `python -m owasp_scanner <target>`
- Web UI cục bộ: `python -m owasp_scanner.web`. Chạy `http.server` tại `127.0.0.1:8765`, file tĩnh nằm ở `owasp_scanner/static/`. `POST /api/scan` gọi thẳng `run_scan()` trong `cli.py`, `GET /api/report/<id>.html` dùng `render_html()`.

Không có server hay service riêng (quyết định D1). Không thêm FastAPI, DB, queue hay framework web nếu FR không yêu cầu.

## Lệnh

```bash
pip install -r requirements-dev.txt   # pyproject.toml sẽ có ở FR-QA-07 (Sprint 3)
ruff check . && ruff format --check . # chưa cấu hình; bắt buộc từ Sprint 3 (FR-QA-07)
python -m pytest -q                   # phải chạy offline, không gọi mạng ngoài
python -m owasp_scanner --help
python -m owasp_scanner.web
```

## Cách làm việc

1. Mỗi lần chỉ làm một FR hoặc một nhóm nhỏ trong sprint hiện tại (backlog mục 9.1).
2. Lập kế hoạch trước khi code: file sẽ sửa, test sẽ viết, rủi ro. Chờ người duyệt.
3. Viết test trước, code sau. Test dùng mock server cục bộ, không bao giờ quét host thật.
4. Mỗi thay đổi nhỏ, commit message có ID, ví dụ `feat(FR-AUTH-02): add redact()`.
5. Hành vi thay đổi thì cập nhật SRS và tick backlog trong cùng thay đổi.

## Quy tắc bắt buộc

**Kiến trúc**

- Python ≥ 3.9, code mới bắt buộc có type hints.
- CLI và Web UI phải cho ra cùng JSON. Mọi xử lý đầu ra (redact, sort, `schema_version`, `fingerprint`, gate theo `--fail-on`) nằm ở một chỗ và được cả hai dùng chung.
- Mỗi check là hàm thuần trong `checks/`: nhận session/response, trả `list[Finding]`, không giữ state toàn cục.
- Danh sách header, path, chữ ký nội dung là dữ liệu khai báo (dict/list/YAML), không hard-code trong logic.

**An toàn khi quét**

- Chế độ mặc định không gửi payload khai thác. Chỉ dùng GET/HEAD/OPTIONS, không có method thay đổi dữ liệu.
- Không quét host nào ngoài mock server hoặc app thử nghiệm chạy local.

**Secret và evidence (D2)**

- Mọi evidence phải qua `redact()` trước khi in, ghi file hoặc trả qua API.
- Cờ `--show-secrets` chỉ có ở CLI. Web UI không được nhận hay bật cờ này dưới bất kỳ hình thức nào.
- Không log hay commit secret, cookie thật, token hoặc dữ liệu khách hàng. Fixture chỉ dùng giá trị giả rõ ràng.

**Severity CORS (D3)**

| Tổ hợp | Severity |
|---|---|
| `*` + credentials | MEDIUM |
| Phản xạ origin + credentials | HIGH |
| Phản xạ origin, không credentials | MEDIUM |
| `*` đơn lẻ | INFO |

**Finding và output**

- Finding mới phải có: `id` ổn định, `severity`, `owasp_category`, `cwe`, `confidence`, `description`, `evidence`, `recommendation`, `url`.
- Không chắc thì hạ `confidence`, không nâng severity.
- Không phá JSON schema hay exit code hiện có. Nếu buộc phải đổi thì nâng `schema_version` và ghi changelog.

**Web UI cục bộ**

- Giữ bind `127.0.0.1` mặc định.
- Giữ các kiểm tra Host/Origin/Content-Type/kích thước body. Không nới lỏng các kiểm tra này.

**Ngôn ngữ**

- Mọi text của sản phẩm dùng tiếng Anh: UI, báo cáo HTML, output CLI, thông báo lỗi API, nội dung finding (SRS NFR-USA-03). Test `test_ui_text_is_english` chặn chữ tiếng Việt trong file tĩnh của UI.
- Tài liệu dự án (SRS, backlog, README, CLAUDE.md) viết tiếng Việt.

**Chất lượng và dependency**

- Code phải qua `ruff`. Không tắt rule bằng `noqa` nếu không ghi lý do.
- Không thêm dependency khi chưa nêu lý do và chưa kiểm tra license có cho phép thương mại hóa.
- Không viết "đảm bảo an toàn" hay "phát hiện 100%" trong báo cáo, README hay output.

## Việc Claude không tự làm

Các việc sau cần người duyệt:

- Push, tạo release, deploy.
- Xóa file ngoài phạm vi FR.
- Thêm active check (backlog E9).
- Đổi kiến trúc (thêm server, DB, queue).
- Thay đổi quyết định D1–D3.
