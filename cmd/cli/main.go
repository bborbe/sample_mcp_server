// Copyright (c) 2025 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	"github.com/mark3labs/mcp-go/server"

	"github.com/bborbe/sample_mcp_server/pkg"
)

func main() {
	mcpServer := pkg.NewMCPServer()

	// Start the stdio server
	if err := server.ServeStdio(mcpServer); err != nil {
		fmt.Printf("Server error: %v\n", err)
	}
}
