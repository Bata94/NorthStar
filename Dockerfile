# Copyright (c) 2026 bata94
# SPDX-License-Identifier: MIT WITH Commons-Clause

ARG VERSION=dev

FROM golang:1.26-alpine AS builder
ARG VERSION
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w -X main.Version=${VERSION}" -o /northstar .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /northstar /northstar
EXPOSE 53/udp
ENTRYPOINT ["/northstar"]
