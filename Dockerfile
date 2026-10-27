FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go test ./... \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /qr-service .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /qr-service /qr-service
ENV ADDR=:8080 \
    GOMEMLIMIT=32MiB
EXPOSE 8080
USER nonroot:nonroot
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 CMD ["/qr-service", "-healthcheck"]
ENTRYPOINT ["/qr-service"]
