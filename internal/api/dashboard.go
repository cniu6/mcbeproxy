package api

import (
	"embed"
	"io/fs"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

//go:embed dist/*
var distFS embed.FS

// getEntryPath returns the current entry path from config
func (a *APIServer) getEntryPath() string {
	if a.globalConfig != nil && a.globalConfig.APIEntryPath != "" {
		return a.globalConfig.APIEntryPath
	}
	return "/mcpe-admin"
}

// dynamicDashboardHandler handles dynamic routing based on config
func (a *APIServer) dynamicDashboardHandler() gin.HandlerFunc {
	subFS, _ := fs.Sub(distFS, "dist")

	return func(c *gin.Context) {
		path := c.Request.URL.Path
		entryPath := a.getEntryPath()

		// Check if path matches entry path without trailing slash - redirect to add slash
		if path == entryPath {
			c.Redirect(http.StatusMovedPermanently, entryPath+"/")
			return
		}

		// Check if path matches entry path with trailing slash (dashboard)
		if path == entryPath+"/" {
			a.serveDashboardHTML(c)
			return
		}

		// Check if path is under entry path
		if strings.HasPrefix(path, entryPath+"/") {
			subPath := strings.TrimPrefix(path, entryPath)

			// Handle assets
			if strings.HasPrefix(subPath, "/assets/") {
				filepath := strings.TrimPrefix(subPath, "/assets")
				a.serveAsset(c, subFS, filepath)
				return
			}

			// Other sub-paths serve dashboard (SPA routing)
			a.serveDashboardHTML(c)
			return
		}

		// Return 404 for all other paths
		c.String(http.StatusNotFound, "Not Found")
	}
}

func (a *APIServer) serveDashboard(c *gin.Context) {
	a.serveDashboardHTML(c)
}

func (a *APIServer) serveDashboardHTML(c *gin.Context) {
	data, err := distFS.ReadFile("dist/index.html")
	if err != nil {
		c.String(http.StatusInternalServerError, "Dashboard not found")
		return
	}
	// index.html 不缓存，确保前端发布后能立刻拿到新版
	c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
	c.Data(http.StatusOK, "text/html; charset=utf-8", data)
}

// pickPrecompressed selects the best precompressed variant available based on
// the client's Accept-Encoding header. It returns the encoding name ("br" or
// "gzip") and the data to serve, or an empty encoding if no variant exists or
// the client doesn't accept compression. Each variant is matched as a separate
// embedded file (e.g. "assets/index-abc.js.br" / ".gz").
func pickPrecompressed(subFS fs.FS, assetPath string, acceptEncoding string) (encoding string, data []byte) {
	// Prefer Brotli when the client supports it (better ratio for text assets).
	if encodingAccepted(acceptEncoding, "br") {
		if b, err := fs.ReadFile(subFS, "assets"+assetPath+".br"); err == nil {
			return "br", b
		}
	}
	if encodingAccepted(acceptEncoding, "gzip") {
		if b, err := fs.ReadFile(subFS, "assets"+assetPath+".gz"); err == nil {
			return "gzip", b
		}
	}
	return "", nil
}

// encodingAccepted reports whether the client accepts the given content coding
// according to its Accept-Encoding header. It parses the comma-separated list
// of codings and honours q-values, so a coding explicitly disabled with "q=0"
// (e.g. "br;q=0") is treated as not accepted. A "*" wildcard is respected as a
// fallback. Matching the bare coding token avoids the substring false positives
// of strings.Contains (e.g. serving Brotli to a client that sent "br;q=0").
func encodingAccepted(acceptEncoding, coding string) bool {
	coding = strings.ToLower(strings.TrimSpace(coding))
	if coding == "" {
		return false
	}

	wildcardSeen := false
	wildcardAccepted := false
	for _, part := range strings.Split(acceptEncoding, ",") {
		token := strings.TrimSpace(strings.ToLower(part))
		if token == "" {
			continue
		}

		name := token
		q := 1.0
		if idx := strings.Index(token, ";"); idx >= 0 {
			name = strings.TrimSpace(token[:idx])
			for _, param := range strings.Split(token[idx+1:], ";") {
				param = strings.TrimSpace(param)
				if strings.HasPrefix(param, "q=") {
					if v, err := strconv.ParseFloat(strings.TrimSpace(param[2:]), 64); err == nil {
						q = v
					}
				}
			}
		}

		switch name {
		case coding:
			return q > 0
		case "*":
			wildcardSeen = true
			wildcardAccepted = q > 0
		}
	}

	if wildcardSeen {
		return wildcardAccepted
	}
	return false
}

func contentTypeForPath(filepath string) string {
	switch {
	case strings.HasSuffix(filepath, ".js"), strings.HasSuffix(filepath, ".mjs"):
		return "application/javascript; charset=utf-8"
	case strings.HasSuffix(filepath, ".css"):
		return "text/css; charset=utf-8"
	case strings.HasSuffix(filepath, ".svg"):
		return "image/svg+xml"
	case strings.HasSuffix(filepath, ".png"):
		return "image/png"
	case strings.HasSuffix(filepath, ".ico"):
		return "image/x-icon"
	case strings.HasSuffix(filepath, ".json"):
		return "application/json; charset=utf-8"
	case strings.HasSuffix(filepath, ".woff2"):
		return "font/woff2"
	case strings.HasSuffix(filepath, ".woff"):
		return "font/woff"
	}
	return ""
}

func (a *APIServer) serveAsset(c *gin.Context, subFS fs.FS, filepath string) {
	// Hashed assets (Vite outputs `name-[hash].ext`) are immutable. Long-cache
	// them so repeat visits don't redownload the bundle on every page load.
	cacheControl := "public, max-age=31536000, immutable"
	contentType := contentTypeForPath(filepath)

	// Try precompressed variants first (built by vite-plugin-compression2).
	if enc, data := pickPrecompressed(subFS, filepath, c.GetHeader("Accept-Encoding")); enc != "" {
		if contentType == "" {
			contentType = http.DetectContentType(data)
		}
		c.Header("Content-Encoding", enc)
		c.Header("Vary", "Accept-Encoding")
		c.Header("Cache-Control", cacheControl)
		c.Header("Content-Length", strconv.Itoa(len(data)))
		c.Header("Content-Type", contentType)
		c.Status(http.StatusOK)
		_, _ = c.Writer.Write(data)
		return
	}

	// Fallback to the uncompressed file.
	data, err := fs.ReadFile(subFS, "assets"+filepath)
	if err != nil {
		c.String(http.StatusNotFound, "File not found")
		return
	}
	if contentType == "" {
		contentType = http.DetectContentType(data)
	}
	c.Header("Cache-Control", cacheControl)
	c.Header("Vary", "Accept-Encoding")
	c.Data(http.StatusOK, contentType, data)
}

func (a *APIServer) serveStaticFiles() gin.HandlerFunc {
	subFS, _ := fs.Sub(distFS, "dist")

	return func(c *gin.Context) {
		filepath := c.Param("filepath")
		a.serveAsset(c, subFS, filepath)
	}
}
