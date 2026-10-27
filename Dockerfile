# 固定Goで検証サーバーをビルドし、実行時は非rootの最小イメージを使う。
FROM golang:1.27.3-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY internal ./internal
COPY cmd ./cmd
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/oimobbs ./cmd/oimobbs \
    && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/oimoedge ./cmd/oimoedge \
    && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/oimoseal ./cmd/oimoseal

FROM alpine:3.23 AS public-edge
RUN addgroup -g 10001 bbs && adduser -D -H -u 10001 -G bbs bbs
COPY --from=build /out/oimoedge /usr/local/bin/oimoedge
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/oimoedge"]

FROM build AS update-check
RUN go test -timeout=5m ./internal/adminauth ./internal/webui ./internal/publicedge ./internal/selfupdate \
    && go vet ./cmd/... ./internal/...

FROM alpine:3.23 AS runtime
RUN addgroup -g 10001 bbs && adduser -D -H -u 10001 -G bbs bbs \
    && mkdir -p /data /etc/oimobbs && chown 10001:10001 /data && chmod 700 /data
COPY --from=build /out/oimobbs /usr/local/bin/oimobbs
COPY --from=build /out/oimoedge /usr/local/bin/oimoedge
COPY --from=build /out/oimoseal /usr/local/bin/oimoseal
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY third_party/argon2 /usr/share/licenses/oimobbs/argon2
COPY third_party/go-modules /usr/share/licenses/oimobbs/go-modules
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/oimobbs"]
