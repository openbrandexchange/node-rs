# One small image: the static-ish node-rs binary on distroless (non-root).
FROM rust:1.91-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked && cp target/release/node-rs /node-rs && mkdir /data

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /node-rs /usr/local/bin/node-rs
COPY --from=build --chown=65532:65532 /data /data
ENV OBX_DATA_DIR=/data PORT=8080 OBX_LOG_FORMAT=json
VOLUME /data
EXPOSE 8080
USER nonroot
ENTRYPOINT ["/usr/local/bin/node-rs"]
CMD ["serve"]
