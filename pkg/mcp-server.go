// Copyright (c) 2025 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkg

import (
	"github.com/mark3labs/mcp-go/server"
)

func NewMCPServer() *server.MCPServer {
	// Create a new MCP server
	s := server.NewMCPServer(
		"Typed Tools Demo 🚀",
		"1.0.0",
		server.WithToolCapabilities(true),
	)
	// Add tool handler using the typed handler
	s.AddTools(
		NewGreetingTool(),
	)
	return s
}
