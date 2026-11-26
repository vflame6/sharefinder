package scanner

import (
	"bytes"
	"testing"

	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/types"
)

func TestAESKeytab(t *testing.T) {
	aes128 := bytes.Repeat([]byte{0x11}, 16)
	aes256 := bytes.Repeat([]byte{0x22}, 32)
	for _, tc := range []struct {
		key   []byte
		etype int32
	}{
		{aes128, etypeID.AES128_CTS_HMAC_SHA1_96},
		{aes256, etypeID.AES256_CTS_HMAC_SHA1_96},
	} {
		kt, err := aesKeytab("jdoe", "CORP.LOCAL", tc.key)
		if err != nil {
			t.Fatal(err)
		}
		// as the AS exchange looks the key up: any version, the KDC's etype
		key, _, err := kt.GetEncryptionKey(types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "jdoe"), "CORP.LOCAL", 0, tc.etype)
		if err != nil {
			t.Fatalf("etype %d: %v", tc.etype, err)
		}
		if key.KeyType != tc.etype || !bytes.Equal(key.KeyValue, tc.key) {
			t.Fatalf("keytab holds type %d %x, want %d %x", key.KeyType, key.KeyValue, tc.etype, tc.key)
		}
	}
	if _, err := aesKeytab("jdoe", "CORP.LOCAL", []byte{1, 2, 3}); err == nil {
		t.Fatal("a key that is neither AES128 nor AES256 must be refused")
	}
}
