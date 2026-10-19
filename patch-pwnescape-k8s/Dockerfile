FROM scratch

COPY target/aarch64-unknown-linux-musl/release/patch-pwnescape-k8s /patch-pwnescape-k8s

ENTRYPOINT ["/patch-pwnescape-k8s"]
CMD ["--mode", "enforce"]
