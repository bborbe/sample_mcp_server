// Copyright (c) 2025 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkg

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func NewGreetingTool() server.ServerTool {

	type GreetingArgs struct {
		Name      string   `json:"name"`
		Age       int      `json:"age"`
		IsVIP     bool     `json:"is_vip"`
		Languages []string `json:"languages"`
		Metadata  struct {
			Location string `json:"location"`
			Timezone string `json:"timezone"`
		} `json:"metadata"`
	}

	tool := mcp.NewTool("greeting",
		mcp.WithDescription("Generate a personalized greeting"),
		mcp.WithString("name",
			mcp.Required(),
			mcp.Description("Name of the person to greet"),
		),
		mcp.WithNumber("age",
			mcp.Description("Age of the person"),
			mcp.Min(0),
			mcp.Max(150),
		),
		mcp.WithBoolean("is_vip",
			mcp.Description("Whether the person is a VIP"),
			mcp.DefaultBool(false),
		),
		mcp.WithArray("languages",
			mcp.Description("Languages the person speaks"),
			mcp.Items(map[string]any{"type": "string"}),
		),
		mcp.WithObject("metadata",
			mcp.Description("Additional information about the person"),
			mcp.Properties(map[string]any{
				"location": map[string]any{
					"type":        "string",
					"description": "Current location",
				},
				"timezone": map[string]any{
					"type":        "string",
					"description": "Timezone",
				},
			}),
		),
	)
	handler := mcp.NewTypedToolHandler(func(
		ctx context.Context,
		request mcp.CallToolRequest,
		args GreetingArgs,
	) (*mcp.CallToolResult, error) {
		if args.Name == "" {
			return mcp.NewToolResultError("name is required"), nil
		}

		// Build a personalized greeting based on the complex arguments
		greeting := fmt.Sprintf("Hello, %s!", args.Name)

		if args.Age > 0 {
			greeting += fmt.Sprintf(" You are %d years old.", args.Age)
		}

		if args.IsVIP {
			greeting += " Welcome back, valued VIP customer!"
		}

		if len(args.Languages) > 0 {
			greeting += fmt.Sprintf(
				" You speak %d languages: %v.",
				len(args.Languages),
				args.Languages,
			)
		}

		if args.Metadata.Location != "" {
			greeting += fmt.Sprintf(" I see you're from %s.", args.Metadata.Location)

			if args.Metadata.Timezone != "" {
				greeting += fmt.Sprintf(" Your timezone is %s.", args.Metadata.Timezone)
			}
		}

		return mcp.NewToolResultText(greeting), nil
	})
	return server.ServerTool{
		Tool:    tool,
		Handler: handler,
	}
}
