FROM golang:1.26.6-alpine AS builder
ENV CGO_ENABLED=0
WORKDIR /app
COPY go.mod go.sum ./
COPY api-spec/go.mod api-spec/go.sum ./api-spec/
COPY pkg/template/go.mod pkg/template/go.sum ./pkg/template/
RUN go mod download
COPY . .
ARG VERSION=docker
RUN go build -o /delegateed -ldflags "-s -w -X main.Version=$VERSION" ./cmd/delegateed

FROM alpine:3.22
RUN apk --no-cache upgrade && apk --no-cache add ca-certificates && adduser -D delegatee
COPY --from=builder /delegateed /usr/local/bin/delegateed
USER delegatee
EXPOSE 7080 7081
ENTRYPOINT ["/usr/local/bin/delegateed"]
