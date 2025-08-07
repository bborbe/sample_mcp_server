// Copyright (c) 2025 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"log"

	"github.com/mark3labs/mcp-go/server"

	"github.com/bborbe/sample_mcp_server/pkg"
)

func main() {
	mcpServer := pkg.NewMCPServer()

	// Create SSE server
	sseServer := server.NewSSEServer(mcpServer)

	log.Println("Starting SSE MCP server on :8080")
	log.Println("Endpoint: http://localhost:8080/sse")
	log.Println("")
	log.Println("This server uses Server-Sent Events (SSE) transport.")
	log.Println("Clients can connect using SSE for real-time communication.")
	log.Println("")
	log.Println("Available tools:")
	log.Println("- greeting: Generate a personalized greeting with complex parameters")

	// Start the server
	if err := sseServer.Start(":8080"); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
