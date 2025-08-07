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

	// Create HTTP server
	httpServer := server.NewStreamableHTTPServer(mcpServer)

	log.Println("Starting HTTP MCP server with sampling support on :8080")
	log.Println("Endpoint: http://localhost:8080/mcp")
	log.Println("")
	log.Println("This server supports sampling over HTTP transport.")
	log.Println("Clients must:")
	log.Println("1. Initialize with sampling capability")
	log.Println("2. Establish SSE connection for bidirectional communication")
	log.Println("3. Handle incoming sampling requests from the server")
	log.Println("4. Send responses back via HTTP POST")
	log.Println("")
	log.Println("Available tools:")
	log.Println("- ask_llm: Ask the LLM a question (requires sampling)")
	log.Println("- echo: Simple echo tool (no sampling required)")

	// Start the server
	if err := httpServer.Start(":8080"); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
