package scanner

// Kerberos for the LDAP bind: a SASL GSSAPI client (RFC 4752) built on the
// jfjallid/gokrb5 fork that go-smb uses, whose KDC exchanges go through
// --proxy. It is adapted from go-ldap's gssapi.Client, which is built on
// jcmturner/gokrb5 and always dials the KDC directly:
//
//	Copyright (c) 2011-2015 Michael Mitton (mmitton@gmail.com)
//	Portions copyright (c) 2015-2024 go-ldap Authors
//
//	Permission is hereby granted, free of charge, to any person obtaining a copy
//	of this software and associated documentation files (the "Software"), to deal
//	in the Software without restriction, including without limitation the rights
//	to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//	copies of the Software, and to permit persons to whom the Software is
//	furnished to do so, subject to the following conditions:
//
//	The above copyright notice and this permission notice shall be included in all
//	copies or substantial portions of the Software.
//
//	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//	SOFTWARE.

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/jfjallid/gokrb5/v9/client"
	"github.com/jfjallid/gokrb5/v9/crypto"
	"github.com/jfjallid/gokrb5/v9/gssapi"
	"github.com/jfjallid/gokrb5/v9/iana/chksumtype"
	"github.com/jfjallid/gokrb5/v9/iana/etypeID"
	"github.com/jfjallid/gokrb5/v9/iana/flags"
	"github.com/jfjallid/gokrb5/v9/iana/keyusage"
	"github.com/jfjallid/gokrb5/v9/messages"
	"github.com/jfjallid/gokrb5/v9/types"
)

// oidKRB5 is the Kerberos V5 GSS-API mechanism (RFC 1964).
var oidKRB5 = asn1.ObjectIdentifier{1, 2, 840, 113554, 1, 2, 2}

// IDs of the Kerberos context tokens (RFC 4121 section 4.1).
var (
	tokIDAPReq    = []byte{0x01, 0x00}
	tokIDAPRep    = []byte{0x02, 0x00}
	tokIDKRBError = []byte{0x03, 0x00}
)

// Flags of a wrap token (RFC 4121 section 4.2.2). The third, SentByAcceptor,
// is checked by gssapi.WrapToken.Unmarshal.
const (
	wrapSealed         = 0x02
	wrapAcceptorSubkey = 0x04
)

// saslNoSecurityLayer is the "no security layer" bit of the SASL GSSAPI
// layer bitmask (RFC 4752 section 3.3).
const saslNoSecurityLayer = 0x01

// gssapiClient implements ldap.GSSAPIClient.
type gssapiClient struct {
	krb    *client.Client
	ekey   types.EncryptionKey // session key of the LDAP service ticket
	subkey types.EncryptionKey // acceptor subkey from the server's AP-REP
}

// InitSecContext starts or continues the GSS-API context with target, the
// LDAP service principal.
func (c *gssapiClient) InitSecContext(target string, input []byte) ([]byte, bool, error) {
	return c.InitSecContextWithOptions(target, input, nil)
}

// InitSecContextWithOptions sends the AP-REQ for target first, then checks
// the server's AP-REP (RFC 4752 section 3.1).
func (c *gssapiClient) InitSecContextWithOptions(target string, input []byte, apOptions []int) ([]byte, bool, error) {
	if input == nil {
		tkt, key, err := c.krb.GetServiceTicket(target)
		if err != nil {
			return nil, false, err
		}
		c.ekey = key
		token, err := apReqToken(c.krb.Credentials.Domain(), c.krb.Credentials.CName(), tkt, key, apOptions)
		if err != nil {
			return nil, false, err
		}
		return token, true, nil
	}
	subkey, err := apRepSubkey(input, c.ekey)
	if err != nil {
		return nil, false, err
	}
	c.subkey = subkey
	return []byte{}, false, nil
}

// NegotiateSaslAuth answers the server's offer of security layers, the last
// step of the bind (RFC 4752 section 3.1). sharefinder chooses no security
// layer: the connection is protected by TLS, when there is TLS.
func (c *gssapiClient) NegotiateSaslAuth(input []byte, authzid string) ([]byte, error) {
	// with an RC4 key, as in the tickets impacket's getST gets, the offer is
	// an RFC 4757 wrap token, which has the framing of a context token
	if len(input) > 0 && input[0] == 0x60 {
		return c.negotiateRC4(input, authzid)
	}
	offer, err := unwrapToken(input)
	if err != nil {
		return nil, err
	}
	key, replyFlags := c.ekey, byte(0)
	if offer.Flags&wrapAcceptorSubkey != 0 {
		if len(c.subkey.KeyValue) == 0 {
			return nil, errors.New("the server's wrap token uses an acceptor subkey it never sent")
		}
		key, replyFlags = c.subkey, wrapAcceptorSubkey
	}
	if _, err := offer.Verify(key, keyusage.GSSAPI_ACCEPTOR_SEAL); err != nil {
		return nil, err
	}
	if err := checkOffer(offer.Payload); err != nil {
		return nil, err
	}

	etype, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return nil, err
	}
	reply := gssapi.WrapToken{
		Flags:     replyFlags,
		EC:        uint16(etype.GetHMACBitLength() / 8),
		SndSeqNum: 1,
		// the chosen layer, then the largest message the client accepts,
		// 0 without a security layer
		Payload: append([]byte{saslNoSecurityLayer, 0, 0, 0}, authzid...),
	}
	if err := reply.SetCheckSum(key, keyusage.GSSAPI_INITIATOR_SEAL); err != nil {
		return nil, err
	}
	return reply.Marshal()
}

// checkOffer checks the server's offer of security layers: 4 bytes, which
// must include "no security layer".
func checkOffer(payload []byte) error {
	if len(payload) != 4 {
		return fmt.Errorf("the server's offer of security layers has %d bytes, want 4", len(payload))
	}
	if payload[0]&saslNoSecurityLayer == 0 {
		return errors.New("the server requires an LDAP security layer (signing or sealing), which sharefinder does not support")
	}
	return nil
}

// negotiateRC4 is NegotiateSaslAuth for an RC4-HMAC context: the offer and
// the answer are RFC 4757 wrap tokens, protected with the acceptor subkey,
// else the ticket's session key.
func (c *gssapiClient) negotiateRC4(input []byte, authzid string) ([]byte, error) {
	key := c.subkey
	if len(key.KeyValue) == 0 {
		key = c.ekey
	}
	if key.KeyType != etypeID.RC4_HMAC || len(key.KeyValue) != 16 {
		return nil, fmt.Errorf("the server sent an RC4 wrap token, but the key of the context is of type %d", key.KeyType)
	}
	offer, err := unwrapRC4(input, key.KeyValue)
	if err != nil {
		return nil, err
	}
	if err := checkOffer(offer); err != nil {
		return nil, err
	}
	return wrapRC4(key.KeyValue, append([]byte{saslNoSecurityLayer, 0, 0, 0}, authzid...), 1)
}

// rc4WrapHeader opens an RFC 4757 wrap token that is not sealed: TOK_ID,
// SGN_ALG HMAC-MD5, SEAL_ALG none, filler.
var rc4WrapHeader = []byte{0x02, 0x01, 0x11, 0x00, 0xff, 0xff, 0xff, 0xff}

// rc4WrapLen is the length of an RC4 wrap token before its data: the header,
// SND_SEQ, SGN_CKSUM and the confounder.
const rc4WrapLen = 32

// unwrapRC4 checks the server's RC4 wrap token (RFC 4757 section 7.3) with
// key and returns its data without the padding. Sealed tokens are refused:
// a SASL GSSAPI offer is never sealed.
func unwrapRC4(token, key []byte) ([]byte, error) {
	var oid asn1.ObjectIdentifier
	rest, err := asn1.UnmarshalWithParams(token, &oid, "application,explicit,tag:0")
	if err != nil {
		return nil, fmt.Errorf("the server's RC4 wrap token: %w", err)
	}
	if !oid.Equal(oidKRB5) || len(rest) <= rc4WrapLen {
		return nil, errors.New("the server's RC4 wrap token is not a Kerberos wrap token")
	}
	if !bytes.Equal(rest[:8], rc4WrapHeader) {
		return nil, fmt.Errorf("the server's RC4 token % x is not an unsealed HMAC-MD5 wrap token", rest[:8])
	}
	sndSeq, cksum, confounder, data := rest[8:16], rest[16:24], rest[24:32], rest[32:]
	if !hmac.Equal(rc4Checksum(key, rest[:8], confounder, data), cksum) {
		return nil, errors.New("the server's RC4 wrap token has a bad checksum")
	}
	// the sequence number is followed by 0xFFFFFFFF in a token the acceptor sent
	if seq := rc4XOR(rc4SeqKey(key, cksum), sndSeq); !bytes.Equal(seq[4:], []byte{0xff, 0xff, 0xff, 0xff}) {
		return nil, errors.New("the RC4 wrap token does not come from the server")
	}
	pad := int(data[len(data)-1])
	if pad == 0 || pad > 8 || pad > len(data) {
		return nil, errors.New("the server's RC4 wrap token has bad padding")
	}
	for _, b := range data[len(data)-pad:] {
		if int(b) != pad {
			return nil, errors.New("the server's RC4 wrap token has bad padding")
		}
	}
	return data[:len(data)-pad], nil
}

// wrapRC4 makes the client's RC4 wrap token for payload, not sealed, with
// sequence number seq.
func wrapRC4(key, payload []byte, seq uint32) ([]byte, error) {
	confounder := make([]byte, 8)
	if _, err := rand.Read(confounder); err != nil {
		return nil, err
	}
	// RC4 is a stream cipher: one byte of padding
	data := append(append(make([]byte, 0, len(payload)+1), payload...), 1)
	cksum := rc4Checksum(key, rc4WrapHeader, confounder, data)
	// the sequence number, then 0x00000000: sent by the initiator
	plainSeq := make([]byte, 8)
	binary.BigEndian.PutUint32(plainSeq, seq)

	msg := make([]byte, 0, rc4WrapLen-2+len(data))
	msg = append(msg, rc4WrapHeader[2:]...)
	msg = append(msg, rc4XOR(rc4SeqKey(key, cksum), plainSeq)...)
	msg = append(msg, cksum...)
	msg = append(msg, confounder...)
	msg = append(msg, data...)
	return krb5ContextToken(rc4WrapHeader[:2], msg)
}

// rc4Checksum is the SGN_CKSUM of an RC4 wrap token: the first 8 bytes of
// the HMAC-MD5 checksum, with Microsoft's message type 13 for a wrap token,
// of the header, the confounder and the padded data.
func rc4Checksum(key, header, confounder, data []byte) []byte {
	ksign := hmacMD5(key, []byte("signaturekey\x00"))
	h := md5.New()
	h.Write([]byte{13, 0, 0, 0}) // little-endian
	h.Write(header)
	h.Write(confounder)
	h.Write(data)
	return hmacMD5(ksign, h.Sum(nil))[:8]
}

// rc4SeqKey is the key that encrypts the SND_SEQ of an RC4 wrap token.
func rc4SeqKey(key, cksum []byte) []byte {
	return hmacMD5(hmacMD5(key, []byte{0, 0, 0, 0}), cksum)
}

// rc4XOR encrypts or decrypts data with RC4 under key, an HMAC-MD5 output.
func rc4XOR(key, data []byte) []byte {
	out := make([]byte, len(data))
	if c, err := rc4.NewCipher(key); err == nil { // fails only for keys of 0 or over 256 bytes
		c.XORKeyStream(out, data)
	}
	return out
}

func hmacMD5(key, data []byte) []byte {
	m := hmac.New(md5.New, key)
	m.Write(data)
	return m.Sum(nil)
}

// DeleteSecContext forgets the keys of the context.
func (c *gssapiClient) DeleteSecContext() error {
	c.ekey = types.EncryptionKey{}
	c.subkey = types.EncryptionKey{}
	return nil
}

// Close ends the Kerberos client's sessions.
func (c *gssapiClient) Close() error {
	c.krb.Destroy()
	return nil
}

// apReqToken is the first token of the bind: the Kerberos initial context
// token (RFC 4121 section 4.1) carrying the AP-REQ for the LDAP ticket. Its
// authenticator asks for integrity, confidentiality and mutual
// authentication, and the AP-REQ requires mutual authentication: Active
// Directory refuses the request otherwise (AcceptSecurityContext error,
// data 57).
func apReqToken(realm string, cname types.PrincipalName, tkt messages.Ticket, key types.EncryptionKey, apOptions []int) ([]byte, error) {
	auth, err := types.NewAuthenticator(realm, cname)
	if err != nil {
		return nil, err
	}
	auth.Cksum = types.Checksum{
		CksumType: chksumtype.GSSAPI,
		Checksum:  gssChecksum(gssapi.ContextFlagInteg | gssapi.ContextFlagConf | gssapi.ContextFlagMutual),
	}
	req, err := messages.NewAPReq(tkt, key, auth)
	if err != nil {
		return nil, err
	}
	types.SetFlag(&req.APOptions, flags.APOptionMutualRequired)
	for _, o := range apOptions {
		types.SetFlag(&req.APOptions, o)
	}
	b, err := req.Marshal()
	if err != nil {
		return nil, err
	}
	return krb5ContextToken(tokIDAPReq, b)
}

// gssChecksum is the authenticator checksum of RFC 4121 section 4.1.1: no
// channel bindings, then the context flags.
func gssChecksum(contextFlags uint32) []byte {
	b := make([]byte, 24)
	binary.LittleEndian.PutUint32(b[0:4], 16) // length of the channel binding hash, all zeros
	binary.LittleEndian.PutUint32(b[20:24], contextFlags)
	return b
}

// krb5ContextToken frames a Kerberos message as a GSS-API context token
// (RFC 2743 section 3.1): [APPLICATION 0] the mechanism, the token ID, the
// message.
func krb5ContextToken(tokID, msg []byte) ([]byte, error) {
	oid, err := asn1.Marshal(oidKRB5)
	if err != nil {
		return nil, err
	}
	inner := make([]byte, 0, len(oid)+len(tokID)+len(msg))
	inner = append(append(append(inner, oid...), tokID...), msg...)
	return asn1.Marshal(asn1.RawValue{Class: asn1.ClassApplication, IsCompound: true, Tag: 0, Bytes: inner})
}

// apRepSubkey checks the server's context token: an AP-REP that only the
// holder of the LDAP service key can make, as it opens with the ticket's
// session key. It returns the acceptor subkey the AP-REP carries; a KRB-ERROR
// from the server is the error.
func apRepSubkey(token []byte, key types.EncryptionKey) (types.EncryptionKey, error) {
	var none types.EncryptionKey
	var oid asn1.ObjectIdentifier
	rest, err := asn1.UnmarshalWithParams(token, &oid, "application,explicit,tag:0")
	if err != nil {
		return none, fmt.Errorf("the server's Kerberos token: %w", err)
	}
	if !oid.Equal(oidKRB5) || len(rest) < 2 {
		return none, errors.New("the server's token is not a Kerberos token")
	}
	tokID, msg := rest[:2], rest[2:]
	switch {
	case bytes.Equal(tokID, tokIDAPRep):
		var rep messages.APRep
		if err := rep.Unmarshal(msg); err != nil {
			return none, err
		}
		// gokrb5 cuts the checksum and confounder off without a length
		// check: a shorter encrypted part would panic it
		etype, err := crypto.GetEtype(key.KeyType)
		if err != nil {
			return none, err
		}
		if n, least := len(rep.EncPart.Cipher), etype.GetConfounderByteSize()+etype.GetHMACBitLength()/8; n < least {
			return none, fmt.Errorf("the server's AP-REP is %d bytes, too short for its checksum", n)
		}
		plain, err := crypto.DecryptEncPart(rep.EncPart, key, keyusage.AP_REP_ENCPART)
		if err != nil {
			return none, fmt.Errorf("the server's AP-REP: %w", err)
		}
		var part messages.EncAPRepPart
		if err := part.Unmarshal(plain); err != nil {
			return none, err
		}
		return part.Subkey, nil
	case bytes.Equal(tokID, tokIDKRBError):
		var krbErr messages.KRBError
		if err := krbErr.Unmarshal(msg); err != nil {
			return none, err
		}
		return none, krbErr
	default:
		return none, fmt.Errorf("unexpected Kerberos token ID % x from the server", tokID)
	}
}

// unwrapToken parses the server's wrap token (RFC 4121 section 4.2.6.2). It
// undoes the rotation of the payload and checksum, which Windows rotates by
// the checksum's length (RRC), and refuses sealed tokens.
func unwrapToken(b []byte) (*gssapi.WrapToken, error) {
	if len(b) < gssapi.HdrLen {
		return nil, errors.New("the server's wrap token is shorter than its header")
	}
	unrotated := make([]byte, len(b))
	copy(unrotated, b[:gssapi.HdrLen])
	if data := b[gssapi.HdrLen:]; len(data) > 0 {
		r := int(binary.BigEndian.Uint16(b[6:8])) % len(data)
		n := copy(unrotated[gssapi.HdrLen:], data[r:])
		copy(unrotated[gssapi.HdrLen+n:], data[:r])
	}
	var wt gssapi.WrapToken
	if err := wt.Unmarshal(unrotated, true); err != nil {
		return nil, err
	}
	if wt.Flags&wrapSealed != 0 {
		return nil, errors.New("the server's wrap token is sealed, which a SASL GSSAPI offer never is")
	}
	return &wt, nil
}
