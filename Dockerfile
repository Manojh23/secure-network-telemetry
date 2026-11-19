FROM golang:1.27.4-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /gateway ./cmd/gateway

FROM scratch
COPY --from=build /gateway /gateway
USER 65532:65532
ENV LISTEN_ADDR=0.0.0.0:9443 DATA_FILE=/data/reports.jsonl KEY_FILE=/run/config/keys.json TLS_CERT=/run/config/server.crt TLS_KEY=/run/config/server.key
EXPOSE 9443
ENTRYPOINT ["/gateway"]
