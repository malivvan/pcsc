package pcsc

import (
	"crypto"
	"fmt"
	openpgp "github.com/ProtonMail/go-crypto/openpgp"
	pgpPacket "github.com/ProtonMail/go-crypto/openpgp/packet"
	pgpCrypto "github.com/ProtonMail/gopenpgp/v2/crypto"
	"io"
	"time"
)

type signer struct {
	pub  crypto.PublicKey
	call func(io.Reader, []byte, crypto.SignerOpts) ([]byte, error)
}

func (s signer) Public() crypto.PublicKey { return s.pub }

func (s signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return s.call(rand, digest, opts)
}

type decrypter struct {
	pub  crypto.PublicKey
	call func(io.Reader, []byte, crypto.DecrypterOpts) ([]byte, error)
}

func (d decrypter) Public() crypto.PublicKey { return d.pub }

func (d decrypter) Decrypt(rand io.Reader, msg []byte, opts crypto.DecrypterOpts) (plaintext []byte, err error) {
	return d.call(rand, msg, opts)
}

type Manager struct {
	serials []string
}

func (m *Manager) add(pub *pgpPacket.PublicKey, priv *pgpPacket.PrivateKey) bool {
	if pub == nil {
		return false
	}
	grip := computeGrip(pub.PublicKey)

	fmt.Println("ADD", pub.KeyId, grip, priv != nil)
	return true
}

func (m *Manager) addEntity(now time.Time, entity *openpgp.Entity) (cnt int) {
	if entity == nil {
		return 0
	}
	if now.IsZero() {
		now = time.Now()
	}
	if !entity.PrimaryIdentity().SelfSignature.SigExpired(now) && !entity.PrimaryIdentity().Revoked(now) {
		if m.add(entity.PrimaryKey, entity.PrivateKey) {
			cnt++
		}
		for _, subkey := range entity.Subkeys {
			if !subkey.Sig.SigExpired(now) && !subkey.Revoked(now) {
				if m.add(subkey.PublicKey, subkey.PrivateKey) {
					cnt++
				}
			}
		}
	}
	return cnt
}

func (m *Manager) AddKeyFromArmored(publicKey string) (int, error) {
	publicKeyObj, err := pgpCrypto.NewKeyFromArmored(publicKey)
	if err != nil {
		return 0, err
	}
	cnt := m.addEntity(time.Time{}, publicKeyObj.GetEntity())
	return cnt, nil
}
