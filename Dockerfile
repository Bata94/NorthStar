# Copyright (c) 2026 bata94
# SPDX-License-Identifier: MIT WITH Commons-Clause

# --- Production --- #

FROM golang:1.26-alpine AS builder
ARG VERSION
WORKDIR /app
COPY go.mod go.sum vendor ./
COPY . .
RUN if [ -z "$VERSION" ]; then VERSION=$(cat VERSION 2>/dev/null || echo dev); fi && \
    CGO_ENABLED=0 go build -mod=vendor -ldflags="-s -w -X main.Version=${VERSION}" -o /northstar .

FROM gcr.io/distroless/static-debian12:nonroot AS prod
COPY --from=builder /northstar /northstar
ENTRYPOINT ["/northstar"]

# --- Development --- #

FROM golang:1.26-alpine AS dev
ARG VERSION
RUN go install github.com/air-verse/air@latest
WORKDIR /app
COPY go.mod go.sum vendor ./
COPY . .
CMD ["air"]
