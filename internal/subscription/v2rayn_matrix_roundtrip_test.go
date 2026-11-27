package subscription

import (
	"encoding/json"
	"os"
	"testing"

	"mcpeserverproxy/internal/config"
)

// This is a local-parser regression check, not the native v2rayN oracle.
// Reuse the optional, gitignored production-export cases sent to ServiceLib.
func TestV2rayNExportMatrixLocalRoundTrip(t *testing.T) {
	raw, err := os.ReadFile("../../tools/v2rayn-interop/go-export-cases.json")
	if os.IsNotExist(err) {
		t.Skip("local v2rayN fixtures are not present; generate with go run ./tools/v2rayn-fixtures -out tools/v2rayn-interop/go-export-cases.json from the repository root")
	}
	if err != nil {
		t.Fatal(err)
	}
	var matrix struct {
		Cases []struct {
			ID     string                `json:"id"`
			Input  string                `json:"input"`
			Source *config.ProxyOutbound `json:"source"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &matrix); err != nil {
		t.Fatal(err)
	}
	for _, c := range matrix.Cases {
		if c.Source == nil {
			continue
		}
		t.Run(c.ID, func(t *testing.T) {
			link, err := config.ExportShareLink(c.Source)
			if err != nil {
				t.Fatal(err)
			}
			if link != c.Input {
				t.Fatal("native fixture is stale; regenerate with go run ./tools/v2rayn-fixtures")
			}
			parsed, ok := parseLink(link)
			if !ok || parsed.Outbound == nil {
				t.Fatal("local parser rejected exported link")
			}
			got, want := parsed.Outbound, c.Source
			if got.Type != want.Type || got.Server != want.Server || got.Port != want.Port || got.Name != want.Name {
				t.Fatalf("identity changed: got %s/%s/%s:%d, want %s/%s/%s:%d", got.Name, got.Type, got.Server, got.Port, want.Name, want.Type, want.Server, want.Port)
			}
			fields := []struct{ name, got, want string }{
				{"username", got.Username, want.Username}, {"uuid", got.UUID, want.UUID},
				{"alpn", got.ALPN, want.ALPN}, {"fingerprint", got.Fingerprint, want.Fingerprint},
				{"ws_path", got.WSPath, want.WSPath}, {"ws_host", got.WSHost, want.WSHost},
				{"grpc_service_name", got.GRPCServiceName, want.GRPCServiceName}, {"grpc_authority", got.GRPCAuthority, want.GRPCAuthority},
				{"xhttp_mode", got.XHTTPMode, want.XHTTPMode}, {"obfs_password", got.ObfsPassword, want.ObfsPassword},
				{"cert_fingerprint", got.CertFingerprint, want.CertFingerprint}, {"flow", got.Flow, want.Flow},
				{"reality_public_key", got.RealityPublicKey, want.RealityPublicKey}, {"reality_short_id", got.RealityShortID, want.RealityShortID},
				{"reality_spider_x", got.RealitySpiderX, want.RealitySpiderX},
			}
			for _, f := range fields {
				if f.want != "" && f.got != f.want {
					t.Errorf("%s changed: got %q, want %q", f.name, f.got, f.want)
				}
			}
			if want.Password != "" && got.Password != want.Password {
				t.Error("password changed")
			}
			if got.Reality != want.Reality || got.Insecure != want.Insecure {
				t.Error("security state changed")
			}
			for _, key := range []string{"fingerprint", "name-cert-verify", "encryption", "congestion-controller"} {
				if value, exists := want.ProviderOptions[key]; exists && got.ProviderOptions[key] != value {
					t.Errorf("provider option %s changed", key)
				}
			}
		})
	}
}
