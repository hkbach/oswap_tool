# Official image for the CLI (FR-CI-04): `docker run --rm websec-scanner https://example.com --yes`
#
# Two stages so the final image carries only the installed package (no compiler, no source
# tree, no pip cache): pip install --prefix=/install lands site-packages and the console
# scripts exactly where python:3.12-slim's own Python already looks (/usr/local), so copying
# that prefix into the final stage is enough to make `websec-scanner`/`websec-scanner-web` work.
FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md ./
COPY websec_scanner ./websec_scanner
RUN pip install --no-cache-dir --prefix=/install .

FROM python:3.12-slim
COPY --from=build /install /usr/local

# Never run as root (FR-CI-04 AC). --create-home gives a writable CWD for relative
# --json/--sarif/--html paths; mount a volume (-v "$PWD":/data -w /data) to keep reports
# on the host instead.
RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin scanner
USER scanner
WORKDIR /home/scanner

ENTRYPOINT ["python", "-m", "websec_scanner"]
