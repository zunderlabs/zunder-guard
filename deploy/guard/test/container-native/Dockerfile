# Synthetic lifecycle fixture only, never a Guard release image. No venue or order path.
FROM python:3.13-slim-bookworm@sha256:a1165e272e578941b84abc79e4ab38a0305cd12803a5c4247979ac7655f4d641
COPY fake_guard.py /fixture.py
USER 65532:65532
WORKDIR /data
ENTRYPOINT ["python3", "/fixture.py"]
