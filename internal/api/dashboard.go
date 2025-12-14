package api

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

//go:embed dist
var distFS embed.FS

// getEntryPath returns the current entry path from config
func (a *APIServer) getEntryPath() string {
	if a.globalConfig != nil && a.globalConfig.APIEntryPath != "" {
		return a.globalConfig.APIEntryPath
	}
	return "/mc_admin_114514"
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
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.String(http.StatusOK, string(data))
}

func (a *APIServer) serveAsset(c *gin.Context, subFS fs.FS, filepath string) {
	data, err := fs.ReadFile(subFS, "assets"+filepath)
	if err != nil {
		c.String(http.StatusNotFound, "File not found")
		return
	}

	// Set correct Content-Type
	if strings.HasSuffix(filepath, ".js") {
		c.Header("Content-Type", "application/javascript")
	} else if strings.HasSuffix(filepath, ".css") {
		c.Header("Content-Type", "text/css")
	} else if strings.HasSuffix(filepath, ".svg") {
		c.Header("Content-Type", "image/svg+xml")
	} else if strings.HasSuffix(filepath, ".png") {
		c.Header("Content-Type", "image/png")
	} else if strings.HasSuffix(filepath, ".ico") {
		c.Header("Content-Type", "image/x-icon")
	}
	c.String(http.StatusOK, string(data))
}

func (a *APIServer) serveStaticFiles() gin.HandlerFunc {
	subFS, _ := fs.Sub(distFS, "dist")

	return func(c *gin.Context) {
		filepath := c.Param("filepath")
		a.serveAsset(c, subFS, filepath)
	}
}
