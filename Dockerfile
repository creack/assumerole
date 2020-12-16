FROM golang:1.15-alpine AS builder

# Disable CGO to get a static binary.
ENV CGO_ENABLED=0
# Disable DWARF and symbol table to reduce the binary size.
ENV GOFLAGS="-ldflags=-w -ldflags=-s"

WORKDIR /app

# Pre-compile the stdlib.
RUN go build -a std

# Add the vendors and pre-compile them.
ADD go.mod go.sum ./
ADD vendor ./vendor
RUN go build ./vendor/...

# Add out code and build it.
ADD main.go .
RUN go build -v -o /assumerole

# Extract the binary to a scratch image.
FROM scratch

ENTRYPOINT ["/assumerole"]
COPY --from=builder /etc/ssl /etc/ssl
COPY --from=builder /assumerole /assumerole
