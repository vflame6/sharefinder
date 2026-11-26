package scanner

import (
	"reflect"
	"testing"
)

func TestFileTags(t *testing.T) {
	tests := []struct {
		name string
		want []string
	}{
		{"web.config", []string{"config"}},
		{"App.Config", []string{"config"}},
		{"settings.ini", []string{"config"}},
		{"unattend.xml", []string{"secret"}},
		{"Groups.xml", []string{"secret"}},
		{"id_rsa", []string{"secret"}},
		{"backup.kdbx", []string{"secret"}},
		{"server.pfx", []string{"secret"}},
		{"deploy.ps1", []string{"script"}},
		{"logon.bat", []string{"script"}},
		{"db.mdf", []string{"database"}},
		{"site.bak", []string{"backup"}},
		{"disk.vhdx", []string{"backup"}},
		{"readme.txt", nil},
		{"photo.jpg", nil},
	}
	for _, tt := range tests {
		if got := FileTags(tt.name); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("FileTags(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}
