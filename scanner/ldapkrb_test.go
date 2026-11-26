package scanner

import (
	"bytes"
	"encoding/asn1"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jfjallid/gokrb5/v9/asn1tools"
	"github.com/jfjallid/gokrb5/v9/crypto"
	"github.com/jfjallid/gokrb5/v9/gssapi"
	"github.com/jfjallid/gokrb5/v9/iana/asnAppTag"
	"github.com/jfjallid/gokrb5/v9/iana/chksumtype"
	"github.com/jfjallid/gokrb5/v9/iana/errorcode"
	"github.com/jfjallid/gokrb5/v9/iana/etypeID"
	"github.com/jfjallid/gokrb5/v9/iana/flags"
	"github.com/jfjallid/gokrb5/v9/iana/keyusage"
	"github.com/jfjallid/gokrb5/v9/iana/msgtype"
	"github.com/jfjallid/gokrb5/v9/iana/nametype"
	"github.com/jfjallid/gokrb5/v9/messages"
	"github.com/jfjallid/gokrb5/v9/types"
)

// socksRecorder is a SOCKS5 proxy that records the address of every CONNECT
// it is asked for and refuses it.
func socksRecorder(t *testing.T) (addr string, connects <-chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	ch := make(chan string, 16)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				// greeting: VER NMETHODS METHODS...
				greeting := make([]byte, 2)
				if _, err := io.ReadFull(c, greeting); err != nil {
					return
				}
				if _, err := io.ReadFull(c, make([]byte, greeting[1])); err != nil {
					return
				}
				_, _ = c.Write([]byte{5, 0}) // no authentication
				// request: VER CMD RSV ATYP ADDR PORT
				req := make([]byte, 4)
				if _, err := io.ReadFull(c, req); err != nil {
					return
				}
				var host string
				switch req[3] {
				case 1, 4:
					ip := make([]byte, map[byte]int{1: 4, 4: 16}[req[3]])
					if _, err := io.ReadFull(c, ip); err != nil {
						return
					}
					host = net.IP(ip).String()
				case 3:
					n := make([]byte, 1)
					if _, err := io.ReadFull(c, n); err != nil {
						return
					}
					name := make([]byte, n[0])
					if _, err := io.ReadFull(c, name); err != nil {
						return
					}
					host = string(name)
				default:
					return
				}
				port := make([]byte, 2)
				if _, err := io.ReadFull(c, port); err != nil {
					return
				}
				ch <- net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port))))
				_, _ = c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0}) // connection refused
			}(c)
		}
	}()
	return ln.Addr().String(), ch
}

// Through --proxy the Kerberos exchange of the LDAP bind goes through the
// proxy too: the KDC is usually reachable only from inside the network.
func TestGSSAPIClient_KDCThroughProxy(t *testing.T) {
	proxyAddr, connects := socksRecorder(t)
	d, err := NewDialer(proxyAddr, 2*time.Second, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer d.CloseAll()
	gc, err := newGSSAPIClient(LDAPOptions{
		Host:       net.ParseIP("192.0.2.10"),
		Username:   "jdoe",
		Password:   "secret",
		Domain:     "corp.local",
		DCHostname: "dc01",
		Kerberos:   true,
		Dialer:     d,
	})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, _, err := gc.InitSecContext("ldap/dc01", nil)
		done <- err
	}()
	select {
	case got := <-connects:
		if got != "192.0.2.10:88" {
			t.Errorf("the proxy was asked for %s, want the KDC 192.0.2.10:88", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the Kerberos exchange did not go through the proxy")
	}
	if err := <-done; err == nil {
		t.Error("no KDC answered, yet the Kerberos logon succeeded")
	}
}

// KDC traffic goes over TCP only: UDP cannot go through the SOCKS proxy, and
// Active Directory's replies, which carry a PAC, are too big for UDP anyway.
func TestKrb5Config_TCPOnly(t *testing.T) {
	for _, key := range [][]byte{nil, bytes.Repeat([]byte{1}, 16), bytes.Repeat([]byte{1}, 32)} {
		cfg, err := newKrb5Config("CORP.LOCAL", "10.0.0.1", key)
		if err != nil {
			t.Fatal(err)
		}
		if got := cfg.LibDefaults.UDPPreferenceLimit; got != 1 {
			t.Errorf("%d-byte key: udp_preference_limit = %d, want 1 (TCP only)", len(key), got)
		}
	}
}

// With an AES key, the AS exchange may only ask for that key's etype: a KDC
// may otherwise answer with the AES256 key of an account that has both,
// which an AES128 --aes-key cannot open.
func TestKrb5Config_AESKeyEtype(t *testing.T) {
	for _, tc := range []struct {
		key  []byte
		want int32
	}{
		{bytes.Repeat([]byte{1}, 16), etypeID.AES128_CTS_HMAC_SHA1_96},
		{bytes.Repeat([]byte{1}, 32), etypeID.AES256_CTS_HMAC_SHA1_96},
	} {
		cfg, err := newKrb5Config("CORP.LOCAL", "10.0.0.1", tc.key)
		if err != nil {
			t.Fatal(err)
		}
		if got := cfg.LibDefaults.DefaultTktEnctypeIDs; len(got) != 1 || got[0] != tc.want {
			t.Errorf("%d-byte key: AS-REQ etypes %v, want [%d]", len(tc.key), got, tc.want)
		}
	}
	cfg, err := newKrb5Config("CORP.LOCAL", "10.0.0.1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.LibDefaults.DefaultTktEnctypeIDs) < 2 {
		t.Errorf("without a key the default etypes stay: %v", cfg.LibDefaults.DefaultTktEnctypeIDs)
	}
}

func testKey(b byte) types.EncryptionKey {
	return types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: bytes.Repeat([]byte{b}, 32)}
}

// krb5Token frames msg as a Kerberos GSS-API context token.
func krb5Token(t *testing.T, tokID, msg []byte) []byte {
	t.Helper()
	oid, err := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 113554, 1, 2, 2})
	if err != nil {
		t.Fatal(err)
	}
	inner := append(append(oid, tokID...), msg...)
	b, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassApplication, IsCompound: true, Tag: 0, Bytes: inner})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// apRepToken is the server's AP-REP for the session key, carrying subkey.
func apRepToken(t *testing.T, key, subkey types.EncryptionKey) []byte {
	t.Helper()
	plain, err := asn1.Marshal(messages.EncAPRepPart{
		CTime:          time.Now().UTC().Truncate(time.Second),
		Subkey:         subkey,
		SequenceNumber: 42,
	})
	if err != nil {
		t.Fatal(err)
	}
	enc, err := crypto.GetEncryptedData(asn1tools.AddASNAppTag(plain, asnAppTag.EncAPRepPart), key, keyusage.AP_REP_ENCPART, 0)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := asn1.Marshal(messages.APRep{PVNO: 5, MsgType: msgtype.KRB_AP_REP, EncPart: enc})
	if err != nil {
		t.Fatal(err)
	}
	return krb5Token(t, []byte{2, 0}, asn1tools.AddASNAppTag(rep, asnAppTag.APREP))
}

// The first token of the bind is the Kerberos initial context token (RFC 4121
// section 4.1): the AP-REQ for the LDAP ticket, whose authenticator asks for
// integrity, confidentiality and mutual authentication.
func TestAPReqToken(t *testing.T) {
	key := testKey(7)
	tkt := messages.Ticket{
		TktVNO:  5,
		Realm:   "CORP.LOCAL",
		SName:   types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "ldap/dc01"),
		EncPart: types.EncryptedData{EType: etypeID.AES256_CTS_HMAC_SHA1_96, KVNO: 2, Cipher: []byte("opaque")},
	}
	token, err := apReqToken("CORP.LOCAL", types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "jdoe"), tkt, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	var oid asn1.ObjectIdentifier
	rest, err := asn1.UnmarshalWithParams(token, &oid, "application,explicit,tag:0")
	if err != nil {
		t.Fatal(err)
	}
	if !oid.Equal(asn1.ObjectIdentifier{1, 2, 840, 113554, 1, 2, 2}) {
		t.Fatalf("mechanism %v, want Kerberos 1.2.840.113554.1.2.2", oid)
	}
	if len(rest) < 2 || rest[0] != 1 || rest[1] != 0 {
		t.Fatalf("token ID % x, want 01 00 (AP-REQ)", rest[:2])
	}
	var req messages.APReq
	if err := req.Unmarshal(rest[2:]); err != nil {
		t.Fatal(err)
	}
	if req.Ticket.SName.PrincipalNameString() != "ldap/dc01" {
		t.Errorf("AP-REQ for %s, want the ticket for ldap/dc01", req.Ticket.SName.PrincipalNameString())
	}
	// Active Directory refuses a request for mutual authentication without
	// it (AcceptSecurityContext error, data 57)
	if !types.IsFlagSet(&req.APOptions, flags.APOptionMutualRequired) {
		t.Error("the AP-REQ asks for mutual authentication without the MUTUAL-REQUIRED option")
	}
	if err := req.DecryptAuthenticator(key); err != nil {
		t.Fatal(err)
	}
	auth := req.Authenticator
	if auth.CRealm != "CORP.LOCAL" || auth.CName.PrincipalNameString() != "jdoe" {
		t.Errorf("authenticator for %s@%s, want jdoe@CORP.LOCAL", auth.CName.PrincipalNameString(), auth.CRealm)
	}
	if auth.Cksum.CksumType != chksumtype.GSSAPI || len(auth.Cksum.Checksum) < 24 {
		t.Fatalf("authenticator checksum type %d, %d bytes; want the 24-byte GSS-API checksum", auth.Cksum.CksumType, len(auth.Cksum.Checksum))
	}
	if n := binary.LittleEndian.Uint32(auth.Cksum.Checksum[0:4]); n != 16 {
		t.Errorf("channel binding length %d, want 16", n)
	}
	want := uint32(gssapi.ContextFlagInteg | gssapi.ContextFlagConf | gssapi.ContextFlagMutual)
	if flags := binary.LittleEndian.Uint32(auth.Cksum.Checksum[20:24]); flags != want {
		t.Errorf("context flags %#x, want %#x (integrity, confidentiality, mutual)", flags, want)
	}
}

// The server's reply proves it holds the LDAP service key: only it can make
// an AP-REP that opens with the session key. It carries the acceptor subkey.
func TestAPRepSubkey(t *testing.T) {
	key, subkey := testKey(7), testKey(9)
	got, err := apRepSubkey(apRepToken(t, key, subkey), key)
	if err != nil {
		t.Fatal(err)
	}
	if got.KeyType != subkey.KeyType || !bytes.Equal(got.KeyValue, subkey.KeyValue) {
		t.Errorf("acceptor subkey %d %x, want %d %x", got.KeyType, got.KeyValue, subkey.KeyType, subkey.KeyValue)
	}
	if _, err := apRepSubkey(apRepToken(t, testKey(8), subkey), key); err == nil {
		t.Error("an AP-REP that does not open with the session key was accepted")
	}

	krbErr := messages.NewKRBError(types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "ldap/dc01"), "CORP.LOCAL", errorcode.KRB_AP_ERR_MODIFIED, "")
	b, err := krbErr.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := apRepSubkey(krb5Token(t, []byte{3, 0}, b), key); err == nil || !strings.Contains(err.Error(), "KRB_AP_ERR_MODIFIED") {
		t.Errorf("a KRB-ERROR from the server gave %v, want its error code", err)
	}

	for name, token := range map[string][]byte{
		"empty":         nil,
		"not a token":   []byte("garbage"),
		"OID only":      krb5Token(t, nil, nil),
		"unknown ID":    krb5Token(t, []byte{9, 9}, []byte{1}),
		"truncated rep": apRepToken(t, key, subkey)[:40],
	} {
		if _, err := apRepSubkey(token, key); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// serverWrapToken is the server's last bind token (RFC 4752 section 3.1): a
// wrap token offering the security layers in offer, its payload and checksum
// rotated right by rrc as Windows sends them.
func serverWrapToken(t *testing.T, key types.EncryptionKey, flags, offer byte, rrc int) []byte {
	t.Helper()
	wt := gssapi.WrapToken{Flags: flags, EC: 12, SndSeqNum: 5, Payload: []byte{offer, 0x00, 0x10, 0x00}}
	if err := wt.SetCheckSum(key, keyusage.GSSAPI_ACCEPTOR_SEAL); err != nil {
		t.Fatal(err)
	}
	b, err := wt.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	data := b[gssapi.HdrLen:]
	n := rrc % len(data)
	out := append([]byte{}, b[:gssapi.HdrLen]...)
	binary.BigEndian.PutUint16(out[6:8], uint16(rrc))
	out = append(out, data[len(data)-n:]...)
	return append(out, data[:len(data)-n]...)
}

// The client answers the server's offer choosing no security layer (RFC 4752
// section 3.1), in a wrap token the server can verify.
func TestNegotiateSaslAuth(t *testing.T) {
	ekey, subkey := testKey(7), testKey(9)
	for _, tc := range []struct {
		name   string
		c      *gssapiClient
		flags  byte // of the server's token
		key    types.EncryptionKey
		rrc    int
		subkey bool // the reply says it is protected with the acceptor subkey
	}{
		{"acceptor subkey", &gssapiClient{ekey: ekey, subkey: subkey}, 0x05, subkey, 0, true},
		{"rotated by the checksum length", &gssapiClient{ekey: ekey, subkey: subkey}, 0x05, subkey, 12, true},
		{"rotated past the token length", &gssapiClient{ekey: ekey, subkey: subkey}, 0x05, subkey, 12 + 16, true},
		{"session key", &gssapiClient{ekey: ekey}, 0x01, ekey, 0, false},
	} {
		reply, err := tc.c.NegotiateSaslAuth(serverWrapToken(t, tc.key, tc.flags, 0x07, tc.rrc), "")
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		var wt gssapi.WrapToken
		if err := wt.Unmarshal(reply, false); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if ok, err := wt.Verify(tc.key, keyusage.GSSAPI_INITIATOR_SEAL); !ok {
			t.Errorf("%s: the server cannot verify the reply: %v", tc.name, err)
		}
		if !bytes.Equal(wt.Payload, []byte{1, 0, 0, 0}) {
			t.Errorf("%s: reply payload % x, want 01 00 00 00 (no security layer)", tc.name, wt.Payload)
		}
		if got := wt.Flags&0x04 != 0; got != tc.subkey {
			t.Errorf("%s: AcceptorSubkey flag %v, want %v", tc.name, got, tc.subkey)
		}
	}
}

func TestNegotiateSaslAuth_Refuses(t *testing.T) {
	ekey, subkey := testKey(7), testKey(9)
	c := &gssapiClient{ekey: ekey, subkey: subkey}
	long := serverWrapToken(t, subkey, 0x05, 0x07, 0)
	binary.BigEndian.PutUint16(long[4:6], 0xfff0)
	for name, token := range map[string][]byte{
		"signed with another key": serverWrapToken(t, testKey(8), 0x05, 0x07, 0),
		"not from the server":     serverWrapToken(t, subkey, 0x04, 0x07, 0),
		"sealed":                  serverWrapToken(t, subkey, 0x07, 0x07, 0),
		"empty":                   nil,
		"truncated":               serverWrapToken(t, subkey, 0x05, 0x07, 0)[:10],
		"checksum past the end":   long,
	} {
		if _, err := c.NegotiateSaslAuth(token, ""); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := (&gssapiClient{ekey: ekey}).NegotiateSaslAuth(serverWrapToken(t, subkey, 0x05, 0x07, 0), ""); err == nil {
		t.Error("a token protected with an acceptor subkey the server never sent was accepted")
	}
	// a server that insists on signing or sealing the connection
	if _, err := c.NegotiateSaslAuth(serverWrapToken(t, subkey, 0x05, 0x06, 0), ""); err == nil || !strings.Contains(err.Error(), "security layer") {
		t.Errorf("a server without the no-security-layer option gave %v", err)
	}
}
