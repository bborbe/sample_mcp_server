// Copyright (c) 2023 Benjamin Borbe All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"

	libhttp "github.com/bborbe/http"
	libsentry "github.com/bborbe/sentry"
	"github.com/bborbe/service"
	"github.com/golang/glog"
	"github.com/gorilla/mux"
	"github.com/mark3labs/mcp-go/server"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/bborbe/sample_mcp_server/pkg"
)

func main() {
	app := &application{}
	os.Exit(service.Main(context.Background(), app, &app.SentryDSN, &app.SentryProxy))
}

type application struct {
	SentryDSN   string `required:"false" arg:"sentry-dsn"   env:"SENTRY_DSN"   usage:"SentryDSN"            display:"length"`
	SentryProxy string `required:"false" arg:"sentry-proxy" env:"SENTRY_PROXY" usage:"Sentry Proxy"`
	Listen      string `required:"true"  arg:"listen"       env:"LISTEN"       usage:"address to listen to"`
}

func (a *application) Run(ctx context.Context, sentryClient libsentry.Client) error {
	router := mux.NewRouter()
	router.Path("/healthz").Handler(libhttp.NewPrintHandler("OK"))
	router.Path("/readiness").Handler(libhttp.NewPrintHandler("OK"))
	router.Path("/metrics").Handler(promhttp.Handler())

	router.Use(func(handler http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, _ := io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewReader(c))
			glog.Infof("%s %s %s", r.Method, r.URL, string(c))
			handler.ServeHTTP(w, r)
		})
	})

	router.PathPrefix("/mcp/http").Handler(server.NewStreamableHTTPServer(pkg.NewMCPServer()))

	return libhttp.NewServer(a.Listen, router).Run(ctx)
}
