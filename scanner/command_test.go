package scanner

import (
	"reflect"
	"testing"
)

func TestMaskCredentials(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{
			name: "no credentials",
			in:   []string{"hunt", "--list", "192.168.0.1"},
			want: []string{"hunt", "--list", "192.168.0.1"},
		},
		{
			name: "short password flag",
			in:   []string{"auth", "-u", "north\\hodor", "-p", "hodor", "1.2.3.4"},
			want: []string{"auth", "-u", "north\\hodor", "-p", "***", "1.2.3.4"},
		},
		{
			name: "long password flag",
			in:   []string{"hunt", "-u", "u", "--password", "secret", "1.2.3.4"},
			want: []string{"hunt", "-u", "u", "--password", "***", "1.2.3.4"},
		},
		{
			name: "long password with equals",
			in:   []string{"hunt", "--password=secret", "1.2.3.4"},
			want: []string{"hunt", "--password=***", "1.2.3.4"},
		},
		{
			name: "short hash flag",
			in:   []string{"auth", "-H", "deadbeef", "1.2.3.4"},
			want: []string{"auth", "-H", "***", "1.2.3.4"},
		},
		{
			name: "long hash with equals",
			in:   []string{"auth", "--hashes=deadbeef", "1.2.3.4"},
			want: []string{"auth", "--hashes=***", "1.2.3.4"},
		},
		{
			name: "value containing equals is unaffected",
			in:   []string{"hunt", "--username=DOMAIN\\u=ser", "-p", "x"},
			want: []string{"hunt", "--username=DOMAIN\\u=ser", "-p", "***"},
		},
		{
			name: "trailing flag without value gets masked placeholder",
			in:   []string{"auth", "-p"},
			want: []string{"auth", "-p", "***"},
		},
		{
			name: "idempotent on already-masked",
			in:   []string{"auth", "-p", "***", "-H", "***"},
			want: []string{"auth", "-p", "***", "-H", "***"},
		},
		{
			name: "positional containing -p is not treated as flag",
			in:   []string{"auth", "1.2.3.4", "-pa", "value"},
			want: []string{"auth", "1.2.3.4", "-pa", "value"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MaskCredentials(tt.in)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("MaskCredentials(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
