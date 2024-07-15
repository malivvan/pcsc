package pcsc

import (
	"bytes"
	"crypto/rsa"
	"encoding/binary"
	"encoding/hex"
	"github.com/cloudflare/circl/dh/x25519"
	"github.com/cloudflare/circl/sign/ed25519"
	"strings"
)

var emptyGrip = [20]byte{}

type Ref interface {
	ID() uint64
	Short() []byte
	Long() []byte
	Grip() []byte
	Match(any) bool
}

type ref struct {
	id   uint64
	grip *[20]byte
}

func (r ref) cast() Ref {
	if r.id == 0 || r.grip == nil || bytes.Equal(r.grip[:], emptyGrip[:]) {
		return nil
	}
	return r
}

func refRSA(id uint64, key *rsa.PublicKey) Ref {
	return ref{
		id:   id,
		grip: computeRSAKeyGrip(key.N.Bytes()),
	}.cast()
}

func refX25519(id uint64, key x25519.Key) Ref {
	return ref{
		id:   id,
		grip: computeX25519KeyGrip(key[:]),
	}.cast()
}

func refEd25519(id uint64, key ed25519.PublicKey) Ref {
	return ref{
		id:   id,
		grip: computeED25519KeyGrip(key),
	}.cast()
}

func (r ref) ID() uint64 {
	return r.id

}
func (r ref) Short() []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(r.id))
	return b[:]
}

func (r ref) Long() []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], r.id)
	return b[:]
}

func (r ref) Grip() []byte {
	return r.grip[:]
}

func (r ref) Match(other any) bool {
	switch v := other.(type) {
	case int:
		return r.Match(uint64(v))
	case uint:
		return r.Match(uint64(v))
	case int32:
		return r.Match(uint64(v))
	case uint32:
		return r.Match(uint64(v))
	case int64:
		return r.Match(uint64(v))
	case string:
		return r.Match(r.sToB(v))
	case [4]byte:
		return r.Match(v[:])
	case [8]byte:
		return r.Match(v[:])
	case [20]byte:
		return r.Match(v[:])
	case uint64:
		return r.ID() == v
	case []byte:
		v = bytes.TrimSpace(v)
		switch len(v) {
		case 4: // Short ID
			return bytes.Equal(r.Short(), v)
		case 8: // Long ID
			return bytes.Equal(r.Long(), v)
		case 20: // Key Grip
			return bytes.Equal(r.Grip(), v)
		}
	}
	return false
}

func (r ref) sToB(s string) []byte {
	b, err := hex.DecodeString(strings.TrimSpace(strings.ToLower(s)))
	if err != nil {
		return nil
	}
	return b
}

func (r ref) bToS(b []byte) string {
	return strings.ToUpper(hex.EncodeToString(b))
}
