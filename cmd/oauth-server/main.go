// Copyright (c) 2025 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package main demonstrates an MCP server that passes authentication tokens
// through context, supporting both HTTP and stdio transports.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	libsentry "github.com/bborbe/sentry"
	"github.com/bborbe/service"
	"github.com/golang/glog"
	"github.com/gorilla/mux"
	"github.com/mark3labs/mcp-go/client/transport"
	"github.com/mark3labs/mcp-go/server"

	"github.com/bborbe/sample_mcp_server/pkg"
)

func main() {
	app := &application{}
	os.Exit(service.Main(context.Background(), app, &app.SentryDSN, &app.SentryProxy))
}

type application struct {
	SentryDSN    string `required:"false" arg:"sentry-dsn"      env:"SENTRY_DSN"      usage:"SentryDSN"               display:"length"`
	SentryProxy  string `required:"false" arg:"sentry-proxy"    env:"SENTRY_PROXY"    usage:"Sentry Proxy"`
	Listen       string `required:"false" arg:"listen"          env:"LISTEN"          usage:"address to listen to"                     default:":8095"`
	ClientID     string `required:"true"  arg:"oauth-client-id" env:"OAUTH_CLIENT_ID" usage:"OAuth 2.0 Client ID"`
	ClientSecret string `required:"true"  arg:"oauth-secret"    env:"OAUTH_SECRET"    usage:"OAuth 2.0 Client Secret" display:"length"`
}

func (a *application) Run(ctx context.Context, sentryClient libsentry.Client) error {

	// Initialize provider (Google by default, GitHub optional)
	provider := &GoogleProvider{}
	glog.Info("Using Google OAuth provider")

	mcpServer := server.NewStreamableHTTPServer(pkg.NewMCPServer())
	router := mux.NewRouter()

	// Middleware to check Authorization header
	authMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") == "" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}

	// CORS middleware for handling preflight and actual requests
	corsMiddleware := func(allowedHeaders ...string) func(http.Handler) http.Handler {
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
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Access-Control-Allow-Origin", "*")
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", headers)
				w.Header().Set("Access-Control-Max-Age", "86400")
				if r.Method == "OPTIONS" {
					w.WriteHeader(http.StatusNoContent)
					return
				}
				next.ServeHTTP(w, r)
			})
		}
	}

	router.Use(corsMiddleware())

	// Register POST, GET, DELETE methods for the /mcp path, all handled by MCPServer
	router.Handle("/mcp/http", authMiddleware(mcpServer)).Methods("POST", "GET", "DELETE")

	router.Handle("/.well-known/oauth-protected-resource", corsMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		metadata := &transport.OAuthProtectedResource{
			AuthorizationServers: []string{
				"http://localhost" + a.Listen + "/.well-known/oauth-authorization-server",
			},
			Resource:     "Example OAuth Protected Resource",
			ResourceName: "Example OAuth Protected Resource",
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(metadata); err != nil {
			glog.Errorf("Failed to encode metadata: %v", err)
		}
	}))).
		Methods("GET")

	router.Handle("/.well-known/oauth-authorization-server", corsMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		metadata := transport.AuthServerMetadata{
			Issuer:                 "http://localhost" + a.Listen,
			AuthorizationEndpoint:  "http://localhost" + a.Listen + "/authorize",
			TokenEndpoint:          "http://localhost" + a.Listen + "/token",
			RegistrationEndpoint:   "http://localhost" + a.Listen + "/register",
			ScopesSupported:        []string{"openid", "profile", "email"},
			ResponseTypesSupported: []string{"code"},
			GrantTypesSupported:    []string{"authorization_code", "refresh_token"},
			TokenEndpointAuthMethodsSupported: []string{
				"none",
				"client_secret_basic",
				"client_secret_post",
			},
			CodeChallengeMethodsSupported: []string{"S256"}, // for inspector
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(metadata); err != nil {
			glog.Errorf("Failed to encode metadata: %v", err)
		}
	}))).
		Methods("GET")

	router.Handle("/authorize", corsMiddleware("Authorization", "Content-Type")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		clientIDParam := q.Get("client_id")
		if clientIDParam == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			if err := json.NewEncoder(w).Encode(map[string]string{"error": "client_id is required"}); err != nil {
				glog.Errorf("Failed to encode error response: %v", err)
			}
			return
		}
		state := q.Get("state")
		if state == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			if err := json.NewEncoder(w).Encode(map[string]string{"error": "state is required"}); err != nil {
				glog.Errorf("Failed to encode error response: %v", err)
			}
			return
		}
		// optional: scopes, redirect_uri
		redirectURI := q.Get("redirect_uri")
		scopes := q.Get("scope")
		if scopes == "" {
			scopes = "openid email profile" // default Google
		}
		authURL, err := provider.GetAuthorizeURL(clientIDParam, state, redirectURI, scopes)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			if encErr := json.NewEncoder(w).Encode(map[string]string{"error": err.Error()}); encErr != nil {
				glog.Errorf("Failed to encode error response: %v", encErr)
			}
			return
		}
		http.Redirect(w, r, authURL, http.StatusFound)
	}))).
		Methods("GET")

	router.Handle("/token", corsMiddleware("Authorization", "Content-Type")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			if encErr := json.NewEncoder(w).Encode(map[string]string{"error": "invalid form data"}); encErr != nil {
				glog.Errorf("Failed to encode error response: %v", encErr)
			}
			return
		}
		grantType := r.FormValue("grant_type")
		code := r.FormValue("code")
		clientIDParam := r.FormValue("client_id")
		redirectURI := r.FormValue("redirect_uri")
		glog.Infof(
			"Token request received grant_type=%s client_id=%s redirect_uri=%s",
			grantType,
			clientIDParam,
			redirectURI,
		)
		if grantType != "authorization_code" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			if err := json.NewEncoder(w).Encode(map[string]string{"error": "unsupported grant_type"}); err != nil {
				glog.Errorf("Failed to encode error response: %v", err)
			}
			return
		}
		if code == "" || clientIDParam == "" || redirectURI == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			if err := json.NewEncoder(w).Encode(map[string]string{"error": "code, client_id, and redirect_uri are required"}); err != nil {
				glog.Errorf("Failed to encode error response: %v", err)
			}
			return
		}

		token, err := provider.ExchangeToken(clientIDParam, a.ClientSecret, code, redirectURI)
		if err != nil {
			glog.Errorf("Token exchange failed: %v", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			if encErr := json.NewEncoder(w).Encode(map[string]string{"error": err.Error()}); encErr != nil {
				glog.Errorf("Failed to encode error response: %v", encErr)
			}
			return
		}
		if token == nil {
			glog.Error("Token exchange returned nil token without error")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			if err := json.NewEncoder(w).Encode(map[string]string{"error": "empty token response"}); err != nil {
				glog.Errorf("Failed to encode error response: %v", err)
			}
			return
		}

		accessToken := token.AccessToken

		userInfo, userErr := provider.FetchUserInfo(accessToken)
		if userErr != nil {
			glog.Errorf("Failed to fetch user info: %v", userErr)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			if err := json.NewEncoder(w).Encode(map[string]interface{}{"error": "failed to fetch user info", "details": userErr.Error()}); err != nil {
				glog.Errorf("Failed to encode error response: %v", err)
			}
			return
		}

		glog.Infof(
			"Token response with user info email=%v login=%v",
			userInfo["email"],
			userInfo["login"],
		)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(token); err != nil {
			glog.Errorf("Failed to encode token response: %v", err)
		}
	}))).
		Methods("POST")

	// Add /register endpoint: echoes back the JSON body
	router.Handle("/register", corsMiddleware("Authorization", "Content-Type")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			if encErr := json.NewEncoder(w).Encode(map[string]string{"error": err.Error()}); encErr != nil {
				glog.Errorf("Failed to encode error response: %v", encErr)
			}
			return
		}
		body["client_id"] = a.ClientID
		body["client_secret"] = a.ClientSecret
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(body); err != nil {
			glog.Errorf("Failed to encode response body: %v", err)
		}
	}))).
		Methods("POST")

	// Output server startup message
	glog.Infof("MCP HTTP server listening on %s", a.Listen)
	// Start the HTTP server, listening on the specified address
	srv := &http.Server{
		Addr:         a.Listen,
		Handler:      router,
		ReadTimeout:  10 * time.Second, // 10 seconds
		WriteTimeout: 10 * time.Second, // 10 seconds
		IdleTimeout:  60 * time.Second, // 60 seconds
	}
	// Start the HTTP server, listening on the specified address
	return srv.ListenAndServe()
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

func (g *GoogleProvider) GetAuthorizeURL(
	clientID, state, redirectURI, scopes string,
) (string, error) {
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

func (g *GoogleProvider) ExchangeToken(
	clientID, clientSecret, code, redirectURI string,
) (*Token, error) {
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
