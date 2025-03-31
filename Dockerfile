# Stage 1: Build the Go application
FROM golang:1.23-alpine AS builder

WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./
# Download dependencies
RUN go mod download

# Copy the rest of the application source code
COPY . .

# Build the Go app
# Statically link the binary to avoid C library dependencies in the final image
# Use CGO_ENABLED=0 for static linking
# Use -ldflags="-s -w" to strip debug symbols and reduce binary size
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /goserver .

# Stage 2: Create the final lightweight image
FROM debian:stable-slim

# Copy the static binary from the builder stage
COPY --from=builder /goserver /goserver

# Expose port (assuming default 8080, adjust if needed)
EXPOSE 8080

# Set default port environment variable
ENV PORT=8080

# Set the entrypoint command
CMD ["/goserver"]