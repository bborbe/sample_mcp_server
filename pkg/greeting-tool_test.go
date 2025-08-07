// Copyright (c) 2025 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkg_test

import (
	"context"
	"encoding/json"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/bborbe/sample_mcp_server/pkg"
)

func getTextContent(content mcp.Content) string {
	textContent, ok := mcp.AsTextContent(content)
	if !ok {
		return ""
	}
	return textContent.Text
}

var _ = Describe("GreetingTool", func() {
	var ctx context.Context
	var tool server.ServerTool
	var request mcp.CallToolRequest
	var result *mcp.CallToolResult
	var err error

	BeforeEach(func() {
		ctx = context.Background()
		tool = pkg.NewGreetingTool()
	})

	Context("NewGreetingTool", func() {
		It("creates tool with correct name", func() {
			Expect(tool.Tool.Name).To(Equal("greeting"))
		})

		It("creates tool with correct description", func() {
			Expect(tool.Tool.Description).To(Equal("Generate a personalized greeting"))
		})

		It("creates tool with handler", func() {
			Expect(tool.Handler).NotTo(BeNil())
		})
	})

	Context("tool execution", func() {
		JustBeforeEach(func() {
			result, err = tool.Handler(ctx, request)
		})

		Context("with missing name", func() {
			BeforeEach(func() {
				request = mcp.CallToolRequest{
					Params: mcp.CallToolParams{
						Name:      "greeting",
						Arguments: map[string]interface{}{},
					},
				}
			})

			It("returns no error", func() {
				Expect(err).To(BeNil())
			})

			It("returns error result", func() {
				Expect(result.IsError).To(BeTrue())
			})

			It("returns correct error message", func() {
				Expect(result.Content).To(HaveLen(1))
				Expect(getTextContent(result.Content[0])).To(Equal("name is required"))
			})
		})

		Context("with empty name", func() {
			BeforeEach(func() {
				request = mcp.CallToolRequest{
					Params: mcp.CallToolParams{
						Name: "greeting",
						Arguments: map[string]interface{}{
							"name": "",
						},
					},
				}
			})

			It("returns error result", func() {
				Expect(result.IsError).To(BeTrue())
			})

			It("returns correct error message", func() {
				Expect(getTextContent(result.Content[0])).To(Equal("name is required"))
			})
		})

		Context("with basic name only", func() {
			BeforeEach(func() {
				request = mcp.CallToolRequest{
					Params: mcp.CallToolParams{
						Name: "greeting",
						Arguments: map[string]interface{}{
							"name": "Alice",
						},
					},
				}
			})

			It("returns no error", func() {
				Expect(err).To(BeNil())
			})

			It("returns success result", func() {
				Expect(result.IsError).To(BeFalse())
			})

			It("returns correct greeting", func() {
				Expect(getTextContent(result.Content[0])).To(Equal("Hello, Alice!"))
			})
		})

		Context("with name and age", func() {
			BeforeEach(func() {
				request = mcp.CallToolRequest{
					Params: mcp.CallToolParams{
						Name: "greeting",
						Arguments: map[string]interface{}{
							"name": "Bob",
							"age":  30,
						},
					},
				}
			})

			It("includes age in greeting", func() {
				Expect(
					getTextContent(result.Content[0]),
				).To(Equal("Hello, Bob! You are 30 years old."))
			})
		})

		Context("with zero age", func() {
			BeforeEach(func() {
				request = mcp.CallToolRequest{
					Params: mcp.CallToolParams{
						Name: "greeting",
						Arguments: map[string]interface{}{
							"name": "Henry",
							"age":  0,
						},
					},
				}
			})

			It("does not include age in greeting", func() {
				Expect(getTextContent(result.Content[0])).To(Equal("Hello, Henry!"))
			})
		})

		Context("with VIP status", func() {
			BeforeEach(func() {
				request = mcp.CallToolRequest{
					Params: mcp.CallToolParams{
						Name: "greeting",
						Arguments: map[string]interface{}{
							"name":   "Charlie",
							"is_vip": true,
						},
					},
				}
			})

			It("includes VIP message", func() {
				Expect(
					getTextContent(result.Content[0]),
				).To(Equal("Hello, Charlie! Welcome back, valued VIP customer!"))
			})
		})

		Context("with languages", func() {
			BeforeEach(func() {
				request = mcp.CallToolRequest{
					Params: mcp.CallToolParams{
						Name: "greeting",
						Arguments: map[string]interface{}{
							"name":      "Diana",
							"languages": []interface{}{"English", "Spanish", "French"},
						},
					},
				}
			})

			It("includes language information", func() {
				Expect(
					getTextContent(result.Content[0]),
				).To(Equal("Hello, Diana! You speak 3 languages: [English Spanish French]."))
			})
		})

		Context("with empty languages", func() {
			BeforeEach(func() {
				request = mcp.CallToolRequest{
					Params: mcp.CallToolParams{
						Name: "greeting",
						Arguments: map[string]interface{}{
							"name":      "Iris",
							"languages": []interface{}{},
						},
					},
				}
			})

			It("does not include language information", func() {
				Expect(getTextContent(result.Content[0])).To(Equal("Hello, Iris!"))
			})
		})

		Context("with metadata", func() {
			Context("with location and timezone", func() {
				BeforeEach(func() {
					request = mcp.CallToolRequest{
						Params: mcp.CallToolParams{
							Name: "greeting",
							Arguments: map[string]interface{}{
								"name": "Eve",
								"metadata": map[string]interface{}{
									"location": "New York",
									"timezone": "EST",
								},
							},
						},
					}
				})

				It("includes location and timezone information", func() {
					Expect(
						getTextContent(result.Content[0]),
					).To(Equal("Hello, Eve! I see you're from New York. Your timezone is EST."))
				})
			})

			Context("with location only", func() {
				BeforeEach(func() {
					request = mcp.CallToolRequest{
						Params: mcp.CallToolParams{
							Name: "greeting",
							Arguments: map[string]interface{}{
								"name": "Frank",
								"metadata": map[string]interface{}{
									"location": "London",
								},
							},
						},
					}
				})

				It("includes location information only", func() {
					Expect(
						getTextContent(result.Content[0]),
					).To(Equal("Hello, Frank! I see you're from London."))
				})
			})
		})

		Context("complete example with all parameters", func() {
			BeforeEach(func() {
				request = mcp.CallToolRequest{
					Params: mcp.CallToolParams{
						Name: "greeting",
						Arguments: map[string]interface{}{
							"name":      "Grace",
							"age":       28,
							"is_vip":    true,
							"languages": []interface{}{"English", "German"},
							"metadata": map[string]interface{}{
								"location": "Berlin",
								"timezone": "CET",
							},
						},
					},
				}
			})

			It("includes all information in correct order", func() {
				expected := "Hello, Grace! You are 28 years old. Welcome back, valued VIP customer! You speak 2 languages: [English German]. I see you're from Berlin. Your timezone is CET."
				Expect(getTextContent(result.Content[0])).To(Equal(expected))
			})
		})
	})

	Context("JSON serialization", func() {
		var toolJSON []byte

		JustBeforeEach(func() {
			toolJSON, err = json.Marshal(tool.Tool)
		})

		It("marshals without error", func() {
			Expect(err).To(BeNil())
		})

		It("contains correct name and description", func() {
			var toolMap map[string]interface{}
			err := json.Unmarshal(toolJSON, &toolMap)
			Expect(err).To(BeNil())
			Expect(toolMap["name"]).To(Equal("greeting"))
			Expect(toolMap["description"]).To(Equal("Generate a personalized greeting"))
		})
	})
})
