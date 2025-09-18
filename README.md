# Sample MCP Server

A comprehensive demonstration of Model Context Protocol (MCP) server implementations using the [mcp-go](https://github.com/mark3labs/mcp-go) library. This repository showcases different transport methods, authentication mechanisms, and typed tool implementations.

## Overview

This project demonstrates various MCP server configurations:

- **Multiple Transport Methods**: stdio, HTTP, and Server-Sent Events (SSE)
- **Production Features**: Health checks, metrics, logging, and error handling
- **Authentication**: OAuth 2.0 integration with Google
- **Typed Tools**: Complex JSON schema validation with nested objects and arrays
- **Client Examples**: SSE client for testing server implementations

## Architecture

### Core Components

The MCP server is built around a single **greeting tool** that demonstrates complex typed argument handling:

- **String validation**: Required name parameter
- **Numeric constraints**: Age with min/max validation (0-150)
- **Boolean defaults**: VIP status flag
- **Array handling**: List of spoken languages
- **Nested objects**: Metadata with location and timezone

### Server Implementations

| Command | Transport | Purpose |
|---------|-----------|---------|
| `cli` | stdio | Basic MCP server for direct CLI integration |
| `http-server` | HTTP | HTTP server with sampling support |
| `http-server-mux` | HTTP | Production HTTP server with health/metrics |
| `oauth-server` | HTTP | OAuth 2.0 authenticated HTTP server |
| `sse-server` | SSE | Server-Sent Events transport |
| `sse-server-mux` | SSE | Production SSE server with monitoring |
| `sse-client` | - | Test client for SSE servers |

### Running Servers

#### 1. CLI Server (stdio)
```bash
go run ./cmd/cli/main.go
```
Perfect for MCP clients that communicate over stdin/stdout.

#### 2. HTTP Server
```bash
go run ./cmd/http-server/main.go
```
Starts on `:8080` with endpoint `http://localhost:8080/mcp`

#### 3. Production HTTP Server
```bash
go run ./cmd/http-server-mux/main.go -listen=:8080
```
Includes health checks (`/healthz`), readiness (`/readiness`), and metrics (`/metrics`).

#### 4. OAuth HTTP Server
```bash
export OAUTH_CLIENT_ID="your-google-client-id"
export OAUTH_SECRET="your-google-client-secret"
export JWT_SECRET="your-jwt-secret-key"

go run ./cmd/oauth-server/main.go
```

#### 5. SSE Server
```bash
go run ./cmd/sse-server/main.go
```
Server-Sent Events transport on `http://localhost:8080/sse`

#### 6. Production SSE Server
```bash
go run ./cmd/sse-server-mux/main.go -listen=:8080
```

### Testing with SSE Client

```bash
# Test default server
go run ./cmd/sse-client/main.go

# Test custom server
go run ./cmd/sse-client/main.go -url=http://localhost:8080/mcp
```

## Usage Examples

### Basic Greeting Tool
```json
{
  "name": "greeting",
  "arguments": {
    "name": "Alice",
    "age": 30,
    "is_vip": true,
    "languages": ["English", "Spanish"],
    "metadata": {
      "location": "New York",
      "timezone": "EST"
    }
  }
}
```

### OAuth Authentication Setup

1. **Create Google OAuth Application**:
   - Go to [Google Cloud Console](https://console.cloud.google.com/)
   - Create OAuth 2.0 credentials
   - Set authorized redirect URI: `http://localhost:8080/callback`

2. **Environment Variables**:
   ```bash
   export OAUTH_CLIENT_ID="your-google-client-id"
   export OAUTH_SECRET="your-google-client-secret"
   export JWT_SECRET="your-jwt-signing-key"
   ```

3. **OAuth Flow**:
   - Server provides OAuth discovery endpoints
   - Handles Google OAuth authorization flow
   - Requires Authorization header for MCP requests

### Integrating with Claude

```bash
# Add HTTP server to Claude
claude mcp add sample http://localhost:8080/mcp/http

# Add OAuth server to Claude
claude mcp add -s project --transport http sample http://localhost:8080/mcp/http

# Check it is working
claude
> /mcp

# Use the greeting tool
claude
> Use the greeting tool to greet Alice, age 30, VIP status true
```

## Transport Comparison

| Transport | Use Case | Pros | Cons |
|-----------|----------|------|------|
| **stdio** | CLI integration | Simple, direct | Single session |
| **HTTP** | Web applications | Stateless, scalable | Polling required |
| **SSE** | Real-time apps | Bi-directional, efficient | Connection management |
