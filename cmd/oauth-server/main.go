// Package main demonstrates an MCP server that passes authentication tokens
// through context, supporting both HTTP and stdio transports.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/bborbe/sample_mcp_server/pkg"
	"github.com/gin-gonic/gin"
	"github.com/mark3labs/mcp-go/client/transport"
	"github.com/mark3labs/mcp-go/server"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"time"
)

func main() {
	var addr string
	var clientID string
	var clientSecret string
	flag.StringVar(&clientID, "oauth-client-id", "", "OAuth 2.0 Client ID")
	flag.StringVar(&clientSecret, "oauth-secret", "", "OAuth 2.0 Client Secret")
	flag.StringVar(&addr, "listen", ":8095", "address to listen on")
	flag.Parse()

	if clientID == "" || clientSecret == "" {
		slog.Error("Client ID and Client Secret must be provided")
		os.Exit(1)
	}

	// Initialize provider (Google by default, GitHub optional)
	provider := &GoogleProvider{}
	slog.Info("Using Google OAuth provider")

	mcpServer := server.NewStreamableHTTPServer(pkg.NewMCPServer())
	router := gin.Default()

	// Middleware to check Authorization header
	authMiddleware := func(c *gin.Context) {
		if c.GetHeader("Authorization") == "" {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		c.Next()
	}

	// CORS middleware for handling preflight and actual requests
	corsMiddleware := func(allowedHeaders ...string) gin.HandlerFunc {
		headers := "Mcp-Protocol-Version, Authorization, Content-Type"
		if len(allowedHeaders) > 0 {
			headers = ""
			for i, h := range allowedHeaders {
				if i > 0 {
					headers += ", "
				}
				headers += h
			}
		}
		return func(c *gin.Context) {
			c.Header("Access-Control-Allow-Origin", "*")
			c.Header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			c.Header("Access-Control-Allow-Headers", headers)
			c.Header("Access-Control-Max-Age", "86400")
			if c.Request.Method == "OPTIONS" {
				c.AbortWithStatus(http.StatusNoContent)
				return
			}
			c.Next()
		}
	}

	router.Use(corsMiddleware())

	// Register POST, GET, DELETE methods for the /mcp path, all handled by MCPServer
	router.POST("/mcp/http", authMiddleware, gin.WrapH(mcpServer))
	router.GET("/mcp/http", authMiddleware, gin.WrapH(mcpServer))
	router.DELETE("/mcp/http", authMiddleware, gin.WrapH(mcpServer))

	router.GET("/.well-known/oauth-protected-resource",
		corsMiddleware(), func(c *gin.Context) {
			metadata := &transport.OAuthProtectedResource{
				AuthorizationServers: []string{"http://localhost" + addr + "/.well-known/oauth-authorization-server"},
				Resource:             "Example OAuth Protected Resource",
				ResourceName:         "Example OAuth Protected Resource",
			}
			c.JSON(http.StatusOK, metadata)
		})

	router.GET("/.well-known/oauth-authorization-server",
		corsMiddleware(), func(c *gin.Context) {
			metadata := transport.AuthServerMetadata{
				Issuer:                            "http://localhost" + addr,
				AuthorizationEndpoint:             "http://localhost" + addr + "/authorize",
				TokenEndpoint:                     "http://localhost" + addr + "/token",
				RegistrationEndpoint:              "http://localhost" + addr + "/register",
				ScopesSupported:                   []string{"openid", "profile", "email"},
				ResponseTypesSupported:            []string{"code"},
				GrantTypesSupported:               []string{"authorization_code", "refresh_token"},
				TokenEndpointAuthMethodsSupported: []string{"none", "client_secret_basic", "client_secret_post"},
				CodeChallengeMethodsSupported:     []string{"S256"}, // for inspector
			}
			c.JSON(http.StatusOK, metadata)
		})

	router.GET("/authorize", corsMiddleware("Authorization", "Content-Type"), func(c *gin.Context) {
		clientIDParam := c.Query("client_id")
		if clientIDParam == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "client_id is required"})
			return
		}
		state := c.Query("state")
		if state == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "state is required"})
			return
		}
		// optional: scopes, redirect_uri
		redirectURI := c.Query("redirect_uri")
		scopes := c.Query("scope")
		if scopes == "" {
			scopes = "openid email profile" // default Google
		}
		authURL, err := provider.GetAuthorizeURL(clientIDParam, state, redirectURI, scopes)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.Redirect(http.StatusFound, authURL)
	})

	router.POST("/token",
		corsMiddleware("Authorization", "Content-Type"), func(c *gin.Context) {
			grantType := c.PostForm("grant_type")
			code := c.PostForm("code")
			clientIDParam := c.PostForm("client_id")
			redirectURI := c.PostForm("redirect_uri")
			slog.Info("Token request received", "grant_type", grantType, "client_id", clientIDParam, "redirect_uri", redirectURI)
			if grantType != "authorization_code" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported grant_type"})
				return
			}
			if code == "" || clientIDParam == "" || redirectURI == "" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "code, client_id, and redirect_uri are required"})
				return
			}

			token, err := provider.ExchangeToken(clientIDParam, clientSecret, code, redirectURI)
			if err != nil {
				slog.Error("Token exchange failed", "error", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
			if token == nil {
				slog.Error("Token exchange returned nil token without error")
				c.JSON(http.StatusInternalServerError, gin.H{"error": "empty token response"})
				return
			}

			accessToken := token.AccessToken

			userInfo, userErr := provider.FetchUserInfo(accessToken)
			if userErr != nil {
				slog.Error("Failed to fetch user info", "error", userErr)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch user info", "details": userErr.Error()})
				return
			}

			slog.Info("Token response with user info",
				"email", userInfo["email"],
				"login", userInfo["login"],
			)

			c.JSON(http.StatusOK, token)
		})

	// Add /register endpoint: echoes back the JSON body
	router.POST("/register",
		corsMiddleware("Authorization", "Content-Type"), func(c *gin.Context) {
			var body map[string]interface{}
			if err := c.ShouldBindJSON(&body); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}
			body["client_id"] = clientID
			body["client_secret"] = clientSecret
			c.JSON(http.StatusOK, body)
		})

	// Output server startup message
	slog.Info("MCP HTTP server listening", "addr", addr)
	// Start the HTTP server, listening on the specified address
	srv := &http.Server{
		Addr:         addr,
		Handler:      router,
		ReadTimeout:  10 * time.Second, // 10 seconds
		WriteTimeout: 10 * time.Second, // 10 seconds
		IdleTimeout:  60 * time.Second, // 60 seconds
	}
	// Start the HTTP server, listening on the specified address
	if err := srv.ListenAndServe(); err != nil {
		slog.Error("Server error", "err", err)
		os.Exit(1)
	}
}

// Token represents a generic OAuth token response.
type Token struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"` // Optional, may not be present in all responses
	TokenType    string    `json:"token_type"`              // e.g., "Bearer"
	ExpiresIn    int64     `json:"expires_in,omitempty"`    // Duration in seconds
	Scope        string    `json:"scope,omitempty"`
	ExpiresAt    time.Time `json:"expires_at,omitempty"`
}

// OAuthProvider defines the methods for any OAuth provider.
type OAuthProvider interface {
	GetAuthorizeURL(clientID, state, redirectURI, scopes string) (string, error)
	ExchangeToken(clientID, clientSecret, code, redirectURI string) (*Token, error)
	FetchUserInfo(accessToken string) (map[string]interface{}, error)
}

// GoogleProvider implements OAuthProvider for Google.
type GoogleProvider struct{}

func (g *GoogleProvider) GetAuthorizeURL(clientID, state, redirectURI, scopes string) (string, error) {
	u, err := url.Parse("https://accounts.google.com/o/oauth2/v2/auth")
	if err != nil {
		return "", err
	}
	values := url.Values{}
	values.Set("client_id", clientID)
	values.Set("state", state)
	values.Set("response_type", "code")
	values.Set("access_type", "online")
	if redirectURI != "" {
		values.Set("redirect_uri", redirectURI)
	}
	if scopes != "" {
		values.Set("scope", scopes)
	} else {
		values.Set("scope", "openid email profile") // default Google scopes
	}
	u.RawQuery = values.Encode()
	return u.String(), nil
}

func (g *GoogleProvider) ExchangeToken(clientID, clientSecret, code, redirectURI string) (*Token, error) {
	tokenEndpoint := "https://oauth2.googleapis.com/token"
	reqBody := map[string]string{
		"client_id":     clientID,
		"client_secret": clientSecret,
		"code":          code,
		"grant_type":    "authorization_code",
		"redirect_uri":  redirectURI,
	}
	jsonBody, _ := json.Marshal(reqBody)
	req, err := http.NewRequest("POST", tokenEndpoint, bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange failed: %s", string(body))
	}
	var tokenResp transport.Token
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, err
	}
	return &Token{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		TokenType:    tokenResp.TokenType,
		ExpiresIn:    tokenResp.ExpiresIn,
		Scope:        tokenResp.Scope,
		ExpiresAt:    tokenResp.ExpiresAt,
	}, nil
}

func (g *GoogleProvider) FetchUserInfo(accessToken string) (map[string]interface{}, error) {
	req, err := http.NewRequest("GET", "https://www.googleapis.com/oauth2/v2/userinfo", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to fetch user info: %s", string(body))
	}
	var user map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, err
	}
	return user, nil
}
