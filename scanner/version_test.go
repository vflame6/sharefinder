package scanner

import "testing"

func TestBuildWindowsVersionString(t *testing.T) {
	tests := []struct {
		name           string
		productName    string
		displayVersion string
		releaseID      string
		currentVersion string
		build          string
		ubr            uint32
		fallback       string
		want           string
	}{
		{
			name:           "product display version and ubr",
			productName:    "Windows 11 Pro",
			displayVersion: "23H2",
			build:          "22631",
			ubr:            3447,
			fallback:       "Windows NT 10.0 Build 22631",
			want:           "Windows 11 Pro 23H2 Build 22631.3447",
		},
		{
			name:        "release id fallback",
			productName: "Windows 10 Enterprise",
			releaseID:   "22H2",
			build:       "19045",
			fallback:    "Windows NT 10.0 Build 19045",
			want:        "Windows 10 Enterprise 22H2 Build 19045",
		},
		{
			name:           "registry incomplete falls back to smb guess",
			currentVersion: "10.0",
			fallback:       "Windows NT 10.0 Build 20348",
			want:           "Windows NT 10.0 Build 20348",
		},
		{
			name: "unknown when nothing available",
			want: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildWindowsVersionString(tt.productName, tt.displayVersion, tt.releaseID, tt.currentVersion, tt.build, tt.ubr, tt.fallback)
			if got != tt.want {
				t.Fatalf("buildWindowsVersionString() = %q, want %q", got, tt.want)
			}
		})
	}
}
