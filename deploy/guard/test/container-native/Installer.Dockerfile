FROM python:3.13-slim-bookworm@sha256:a1165e272e578941b84abc79e4ab38a0305cd12803a5c4247979ac7655f4d641
COPY installer-fixture.py /fixture.py
# Plain COPY + RUN also works with the guest's legacy builder.
COPY installer-volume-root/ /data/
RUN chown -R 65532:65532 /data && chmod 0700 /data
USER 65532:65532
WORKDIR /data
ENTRYPOINT ["python3", "-I", "/fixture.py"]
