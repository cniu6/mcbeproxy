package proxy

import "testing"

func TestMergeMOTDCompatibilityUsesUpstreamProtocol(t *testing.T) {
	custom := []byte("MCPE;Proxy;712;1.21.50;0;100;1;Proxy;Survival;1;50103;50103;")
	upstream := []byte("MCPE;Target;2193;1.26.50;12;100;2;Target;Survival;1;19132;19133;")

	got := string(mergeMOTDCompatibility(custom, upstream))
	want := "MCPE;Proxy;2193;1.26.50;0;100;1;Proxy;Survival;1;50103;50103;"
	if got != want {
		t.Fatalf("merged MOTD = %q, want %q", got, want)
	}
}

func TestMergeMOTDCompatibilityFallsBackToUpstreamWhenCustomIsInvalid(t *testing.T) {
	upstream := []byte("MCPE;Target;2193;1.26.50;12;100;2;Target;Survival;1;19132;19133;")
	got := string(mergeMOTDCompatibility([]byte("Proxy"), upstream))
	if got != string(upstream) {
		t.Fatalf("invalid custom MOTD = %q, want upstream %q", got, upstream)
	}
}
