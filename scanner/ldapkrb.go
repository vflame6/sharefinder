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
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/jfjallid/gokrb5/v9/client"
	"github.com/jfjallid/gokrb5/v9/crypto"
	"github.com/jfjallid/gokrb5/v9/gssapi"
	"github.com/jfjallid/gokrb5/v9/iana/chksumtype"
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
	if len(offer.Payload) != 4 {
		return nil, fmt.Errorf("the server's offer of security layers has %d bytes, want 4", len(offer.Payload))
	}
	if offer.Payload[0]&saslNoSecurityLayer == 0 {
		return nil, errors.New("the server requires an LDAP security layer (signing or sealing), which sharefinder does not support")
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
