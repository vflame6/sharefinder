package scanner

import (
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

// fakeBinder records the bind calls bindLDAP makes.
type fakeBinder struct {
	gssErr, ntlmErr, bindErr error
	calls                    []string
}

func (f *fakeBinder) GSSAPIBind(c ldap.GSSAPIClient, spn, authzid string) error {
	f.calls = append(f.calls, "gssapi:"+spn)
	return f.gssErr
}

func (f *fakeBinder) NTLMBindWithHash(domain, user, hash string) error {
	f.calls = append(f.calls, "ntlm:"+domain+`\`+user)
	return f.ntlmErr
}

func (f *fakeBinder) Bind(user, password string) error {
	f.calls = append(f.calls, "simple:"+user)
	return f.bindErr
}

func TestChooseBind(t *testing.T) {
	kerberos := LDAPOptions{Kerberos: true, Username: "u", Password: "p"}
	hash := LDAPOptions{Username: "u", Hash: "31d6cfe0d16ae931b73c59d7e0c089c0"}
	password := LDAPOptions{Username: "u", Password: "p"}
	allowed := LDAPOptions{Username: "u", Password: "p", AllowPlaintext: true}

	tests := []struct {
		name    string
		o       LDAPOptions
		t       ldapTransport
		want    bindMethod
		wantErr bool
	}{
		{"kerberos over LDAPS", kerberos, transportLDAPS, bindGSSAPI, false},
		{"kerberos over plain", kerberos, transportPlain, bindGSSAPI, false},
		{"hash over plain", hash, transportPlain, bindNTLMHash, false},
		{"password over LDAPS", password, transportLDAPS, bindSimple, false},
		{"password over StartTLS", password, transportStartTLS, bindSimple, false},
		{"password over plain refused", password, transportPlain, 0, true},
		{"password over plain allowed", allowed, transportPlain, bindSimple, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := chooseBind(tt.o, tt.t)
			if tt.wantErr {
				if err == nil || !strings.Contains(err.Error(), "--allow-plaintext-ldap") {
					t.Fatalf("expected an error naming --allow-plaintext-ldap, got %v", err)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("chooseBind = %v, %v; want %v", got, err, tt.want)
			}
		})
	}
}

func TestBindLDAP_KerberosFailureNoFallback(t *testing.T) {
	gssErr := errors.New("KDC_ERR_PREAUTH_FAILED")
	b := &fakeBinder{gssErr: gssErr}
	o := LDAPOptions{Kerberos: true, DCHostname: "DC01.corp.local", Username: "u", Password: "p", Domain: "corp.local"}
	err := bindLDAP(b, o, transportLDAPS, nil)
	if !errors.Is(err, gssErr) {
		t.Fatalf("bindLDAP returned %v, want the Kerberos error", err)
	}
	if !reflect.DeepEqual(b.calls, []string{"gssapi:ldap/dc01.corp.local"}) {
		t.Fatalf("a failed Kerberos bind must not fall back, calls: %v", b.calls)
	}
}

func TestBindLDAP_PlainRefused(t *testing.T) {
	b := &fakeBinder{}
	o := LDAPOptions{Host: net.ParseIP("10.0.0.1"), Username: "u", Password: "p", Domain: "corp.local"}
	err := bindLDAP(b, o, transportPlain, nil)
	if err == nil || !strings.Contains(err.Error(), "--allow-plaintext-ldap") {
		t.Fatalf("expected a refusal naming --allow-plaintext-ldap, got %v", err)
	}
	if len(b.calls) != 0 {
		t.Fatalf("no bind may be sent over plain LDAP, calls: %v", b.calls)
	}
}

func TestBindLDAP_SimpleUsesUPN(t *testing.T) {
	b := &fakeBinder{}
	o := LDAPOptions{Username: "jdoe", Password: "p", Domain: "corp.local"}
	if err := bindLDAP(b, o, transportStartTLS, nil); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(b.calls, []string{"simple:jdoe@corp.local"}) {
		t.Fatalf("calls: %v", b.calls)
	}
}

func TestBindLDAP_HashOverPlain(t *testing.T) {
	b := &fakeBinder{}
	o := LDAPOptions{Username: "jdoe", Hash: "31d6cfe0d16ae931b73c59d7e0c089c0", Domain: "corp.local"}
	if err := bindLDAP(b, o, transportPlain, nil); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(b.calls, []string{`ntlm:corp.local\jdoe`}) {
		t.Fatalf("calls: %v", b.calls)
	}
}

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
