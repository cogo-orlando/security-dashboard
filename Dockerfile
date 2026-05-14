# ══════════════════════════════════════════
#  STAGE 1 — Build
# ══════════════════════════════════════════
FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w" \
    -trimpath \
    -o main .

# ══════════════════════════════════════════
#  STAGE 2 — Runtime
# ══════════════════════════════════════════
FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /app/main /main
COPY --from=builder /app/web /web

EXPOSE 8081

USER 1001

ENV PORT=8081 \
    TZ=Europe/Paris

ENTRYPOINT ["/main"]