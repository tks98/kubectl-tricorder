# Build stage
FROM golang:1.19-alpine AS builder

WORKDIR /app

# Install required dependencies
RUN apk add --no-cache git

# Copy go.mod and go.sum first to leverage Docker cache
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -o kubectl-tricorder -ldflags="-w -s" .

# Runtime stage
FROM alpine:3.16

# Install kubectl
RUN apk add --no-cache curl && \
    curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" && \
    chmod +x kubectl && \
    mv kubectl /usr/local/bin/

WORKDIR /root/

# Copy only the binary from the build stage
COPY --from=builder /app/kubectl-tricorder /usr/local/bin/kubectl-tricorder

ENTRYPOINT ["kubectl-tricorder"] 