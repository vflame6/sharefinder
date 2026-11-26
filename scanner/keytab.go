package scanner

import (
	"bytes"
	"encoding/binary"
	"errors"
	"time"

	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/keytab"
)

// aesKeytab builds an in-memory keytab holding the AES key of user, so the
// LDAP Kerberos bind can log on with --aes-key: gokrb5 takes keys only from
// a keytab. The key is 16 bytes (AES128) or 32 bytes (AES256).
func aesKeytab(user, realm string, key []byte) (*keytab.Keytab, error) {
	var etype uint16
	switch len(key) {
	case 16:
		etype = uint16(etypeID.AES128_CTS_HMAC_SHA1_96)
	case 32:
		etype = uint16(etypeID.AES256_CTS_HMAC_SHA1_96)
	default:
		return nil, errors.New("an AES key is 16 or 32 bytes")
	}

	// one entry in the MIT keytab format, version 0x0502 (big-endian)
	var entry bytes.Buffer
	counted := func(b []byte) {
		_ = binary.Write(&entry, binary.BigEndian, uint16(len(b)))
		entry.Write(b)
	}
	_ = binary.Write(&entry, binary.BigEndian, uint16(1)) // name components
	counted([]byte(realm))
	counted([]byte(user))
	_ = binary.Write(&entry, binary.BigEndian, uint32(nametype.KRB_NT_PRINCIPAL))
	_ = binary.Write(&entry, binary.BigEndian, uint32(time.Now().Unix()))
	entry.WriteByte(1) // key version
	_ = binary.Write(&entry, binary.BigEndian, etype)
	counted(key)
	_ = binary.Write(&entry, binary.BigEndian, uint32(1)) // key version, 32 bits

	var file bytes.Buffer
	file.Write([]byte{0x05, 0x02})
	_ = binary.Write(&file, binary.BigEndian, int32(entry.Len()))
	file.Write(entry.Bytes())

	kt := keytab.New()
	if err := kt.Unmarshal(file.Bytes()); err != nil {
		return nil, err
	}
	return kt, nil
}
