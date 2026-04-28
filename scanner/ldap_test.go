package scanner

import (
	"fmt"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

func TestIsLDAPReferral(t *testing.T) {
	if isLDAPReferral(nil) {
		t.Fatal("nil should not be treated as a referral")
	}
	if isLDAPReferral(fmt.Errorf("plain error")) {
		t.Fatal("non-LDAP error should not be a referral")
	}

	refErr := &ldap.Error{ResultCode: ldap.LDAPResultReferral, Err: fmt.Errorf("ref")}
	if !isLDAPReferral(refErr) {
		t.Fatal("LDAPResultReferral should be detected")
	}

	other := &ldap.Error{ResultCode: ldap.LDAPResultOperationsError, Err: fmt.Errorf("other")}
	if isLDAPReferral(other) {
		t.Fatal("non-referral LDAP error should return false")
	}

	wrapped := fmt.Errorf("context: %w", refErr)
	if !isLDAPReferral(wrapped) {
		t.Fatal("wrapped referral should be detected via errors.As")
	}
}

func TestGetBaseDN(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		want   string
	}{
		{name: "single label", domain: "corp", want: "dc=corp"},
		{name: "two labels", domain: "corp.local", want: "dc=corp,dc=local"},
		{name: "three labels", domain: "child.corp.local", want: "dc=child,dc=corp,dc=local"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetBaseDN(tt.domain); got != tt.want {
				t.Fatalf("GetBaseDN(%q) = %q, want %q", tt.domain, got, tt.want)
			}
		})
	}
}

func TestExtractDomainPartitions(t *testing.T) {
	entries := []*ldap.Entry{
		{
			Attributes: []*ldap.EntryAttribute{
				{Name: "dnsRoot", Values: []string{"corp.local"}},
				{Name: "nCName", Values: []string{"DC=corp,DC=local"}},
			},
		},
		{
			Attributes: []*ldap.EntryAttribute{
				{Name: "dnsRoot", Values: []string{"CHILD.corp.local"}},
				{Name: "nCName", Values: []string{"DC=child,DC=corp,DC=local"}},
			},
		},
		{
			Attributes: []*ldap.EntryAttribute{
				{Name: "dnsRoot", Values: []string{"corp.local"}},
				{Name: "nCName", Values: []string{"DC=corp,DC=local"}},
			},
		},
		{
			Attributes: []*ldap.EntryAttribute{
				{Name: "dnsRoot", Values: []string{""}},
				{Name: "nCName", Values: []string{"DC=ignored,DC=local"}},
			},
		},
	}

	got, err := extractDomainPartitions(entries)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(got) != 2 {
		t.Fatalf("expected 2 partitions after filtering/dedup, got %d", len(got))
	}
	if got[0].Name != "corp.local" || got[0].BaseDN != "DC=corp,DC=local" {
		t.Fatalf("unexpected first partition: %#v", got[0])
	}
	if got[1].Name != "child.corp.local" || got[1].BaseDN != "DC=child,DC=corp,DC=local" {
		t.Fatalf("unexpected second partition: %#v", got[1])
	}
}

func TestExtractDomainPartitions_NoUsableDomains(t *testing.T) {
	_, err := extractDomainPartitions([]*ldap.Entry{{
		Attributes: []*ldap.EntryAttribute{{Name: "dnsRoot", Values: []string{""}}},
	}})
	if err == nil {
		t.Fatal("expected error when no valid forest domains are present")
	}
}
