// Copyright (c) 2025 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/client/transport"
	"github.com/mark3labs/mcp-go/mcp"
)

const (
	defaultURL = "http://localhost:8080/sse"
)

func hasInputSchema(schema mcp.ToolInputSchema) bool {
	// Check if the schema has any meaningful content
	return len(schema.Properties) > 0 || schema.Type != ""
}

func main() {
	url := flag.String("url", defaultURL, "MCP server base URL")
	flag.Parse()

	// Create SSE transport
	sseTransport, err := transport.NewSSE(*url)
	if err != nil {
		log.Fatalf("Failed to create SSE transport: %v", err)
	}
	defer sseTransport.Close()

	// Create MCP client
	mcpClient := client.NewClient(sseTransport)

	// Start the client
	ctx := context.Background()
	err = mcpClient.Start(ctx)
	if err != nil {
		log.Fatalf("Failed to start client: %v", err)
	}

	// Initialize the MCP session
	initRequest := mcp.InitializeRequest{
		Params: mcp.InitializeParams{
			ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION,
			Capabilities:    mcp.ClientCapabilities{},
			ClientInfo: mcp.Implementation{
				Name:    "sse-test-client",
				Version: "1.0.0",
			},
		},
	}

	_, err = mcpClient.Initialize(ctx, initRequest)
	if err != nil {
		log.Fatalf("Failed to initialize MCP session: %v", err)
	}

	tools, err := mcpClient.ListTools(ctx, mcp.ListToolsRequest{})
	if err != nil {
		log.Fatalf("list tools failed: %v", err)
	}

	// Display tools in a formatted way
	fmt.Printf("🛠️  Available Tools (%d):\n", len(tools.Tools))
	fmt.Println("==========================================")

	if len(tools.Tools) == 0 {
		fmt.Println("❌ No tools available")
	} else {
		for i, tool := range tools.Tools {
			fmt.Printf("\n%d. 🔧 %s\n", i+1, tool.Name)
			if tool.Description != "" {
				fmt.Printf("   📝 Description: %s\n", tool.Description)
			}
			// Check if input schema has any properties
			if hasInputSchema(tool.InputSchema) {
				fmt.Printf("   📋 Input schema defined\n")
			}
		}
	}
	fmt.Println()
	_ = json.NewEncoder(os.Stdout).Encode(tools)
}
