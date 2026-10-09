# syntax=mirror.gcr.io/docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
# Zunder Guard container image (deploy/guard/README.md, "Docker"). Build context: the
# repository root. Static musl binary, distroless runtime, non-root, no shell, no package manager.
#
#   docker build -f deploy/guard/Dockerfile -t zunder-guard .
#   docker buildx build -f deploy/guard/Dockerfile --platform linux/amd64,linux/arm64 -o type=oci,dest=guard.tar .
#
# Release builds use GUARD_SOURCE=prebuilt: the image then holds the very binaries the release
# workflow built, checksummed and signed (dist/linux-<arch>/zunder-guard in the context),
# instead of compiling a second time.
#
# `run` is paper mode unless ZUNDER_GUARD_NETWORK (or --network) names testnet, and that must be
# the mode `init` recorded: `docker run … -e ZUNDER_GUARD_NETWORK=testnet …` after a testnet init.
#
# Default: listens on 127.0.0.1 INSIDE the container, so even a careless `-p 8547:8547` reaches
# nothing. compose.yaml listens on the container's own interface and publishes the port on the
# host's 127.0.0.1 only. Nothing is ever published on a public interface by default.

ARG GUARD_SOURCE=build

# ---------------------------------------------------------------- compile (native per platform)
FROM public.ecr.aws/docker/library/rust:1.97.0-alpine3.22@sha256:3ab54ebc56cb9b6544edfbbb9f171d1576ecf86f5a0a37a231b0e32ff3b48e0c AS build
ARG GUARD_PACKAGE=zunder-guard
# The image's toolchain must be the one rust-toolchain.toml pins; no download during the build.
ENV RUSTUP_TOOLCHAIN=1.97.0 CARGO_INCREMENTAL=0 CARGO_TERM_COLOR=never
WORKDIR /src
COPY . .
RUN grep -qx 'channel = "1.97.0"' rust-toolchain.toml \
 || { echo "rust-toolchain.toml and the builder image disagree; bump both together" >&2; exit 1; }
# Paths are remapped and symbols stripped so the binary does not depend on where it was built.
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    RUSTFLAGS="--remap-path-prefix=/src=/build --remap-path-prefix=/usr/local/cargo=/cargo -C strip=symbols" \
    cargo build --release --locked -p "$GUARD_PACKAGE" --bin zunder-guard \
 && install -D -m 0755 target/release/zunder-guard /out/zunder-guard \
 && /out/zunder-guard --version

FROM scratch AS bin-build
COPY --from=build /out/zunder-guard /zunder-guard

FROM scratch AS bin-prebuilt
ARG TARGETARCH
COPY dist/linux-${TARGETARCH}/zunder-guard /zunder-guard

# Only the stage GUARD_SOURCE names is built. (A stage of this file, not an image: no tag.)
# hadolint ignore=DL3006
FROM bin-${GUARD_SOURCE} AS bin

# ---------------------------------------------------------------- runtime
# distroless/static: CA certificates, /etc/passwd with uid 65532 "nonroot", nothing else.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
LABEL org.opencontainers.image.title="zunder-guard" \
      org.opencontainers.image.description="Zunder Guard: a self-hosted risk firewall between trading bots and Hyperliquid" \
      org.opencontainers.image.source="https://github.com/zunderlabs/zunder-guard" \
      org.opencontainers.image.licenses="Elastic-2.0" \
      org.opencontainers.image.vendor="Orcastrate UG (haftungsbeschränkt)"
COPY --from=bin --chmod=0755 /zunder-guard /usr/local/bin/zunder-guard
COPY --chmod=0644 LICENSE NOTICE THIRD_PARTY_LICENSES.md /usr/share/licenses/zunder-guard/
USER 65532:65532
# The journal, the configuration and (only if the user chose the file fallback) the key live
# here. Mount a volume: losing it loses the daily-loss and drawdown state.
COPY --chown=65532:65532 --chmod=0700 deploy/guard/container/volume-root/ /data/
WORKDIR /data
ENV ZUNDER_GUARD_HOME=/data \
    ZUNDER_GUARD_LISTEN=127.0.0.1:8547
EXPOSE 8547
# No shell and no curl in the image: the binary checks its own /healthz.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --start-interval=2s --retries=3 \
  CMD ["/usr/local/bin/zunder-guard", "health"]
ENTRYPOINT ["/usr/local/bin/zunder-guard"]
CMD ["run"]
