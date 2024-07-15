package pcsc

import (
	"fmt"
	iso "github.com/malivvan/pcsc/iso7816"
	"github.com/malivvan/pcsc/pgp"
	"github.com/malivvan/pcsc/piv"
	"github.com/malivvan/pcsc/scard"
	"github.com/malivvan/pcsc/yubikey"
	"sync"
)

// .pgp/
// ├── key.bolt
// ├── pid.lock
// ├── log.json
type Library struct {
	err error
	run func(func(*TX) error, ...string) error
}

func Load() *Library {
	err := scard.Initialize(scard.NewDefaultLogger(scard.LogLevelNone))
	if err != nil {
		return &Library{err: err}
	}
	var mutex sync.Mutex
	return &Library{
		run: func(handler func(*TX) error, serials ...string) error {
			mutex.Lock()
			defer mutex.Unlock()

			ctx, r, err := scard.NewContext(scard.SCardScopeSystem, nil, nil)
			if err != nil {
				return fmt.Errorf("NewContext failed (ret=0x%.8X) (err=%v)", r, err)
			}
			defer ctx.Release()

			readers, r, err := ctx.ListReaders(nil)
			if err != nil {
				return fmt.Errorf("ListReaders failed (ret=0x%.8X) (err=%v)", r, err)
			}
			if len(readers) == 0 {
				return fmt.Errorf("No readers found")
			}

			for _, serial := range serials {
				for _, reader := range readers {
					card, _, err := ctx.Connect(reader, scard.SCardShareShared, scard.SCardProtocolT0|scard.SCardProtocolT1)
					if err != nil {
						continue
					}
					status, _, err := card.Status()
					if err != nil {
						_, _ = card.Disconnect(scard.SCardLeaveCard)
						continue
					}

					var ioSendPci scard.SCardIORequest
					if status.ActiveProtocol == scard.SCardProtocolT0 {
						ioSendPci = scard.SCardIoRequestT0
					} else if status.ActiveProtocol == scard.SCardProtocolT1 {
						ioSendPci = scard.SCardIoRequestT1
					} else if status.ActiveProtocol == scard.SCardProtocolRaw {
						ioSendPci = scard.SCardIoRequestRaw
					} else {
						_, _ = card.Disconnect(scard.SCardLeaveCard)
						continue
					}

					r, err = card.BeginTransaction()
					if err != nil {
						_, _ = card.Disconnect(scard.SCardLeaveCard)
						continue
					}

					tx := &TX{
						r:    reader,
						ctx:  ctx,
						send: &ioSendPci,
						recv: nil,
						card: card,
						getr: iso.InsGetResponse,
					}
					if err := tx.Select(iso.AidYubicoManagement); err != nil {
						_, _ = card.EndTransaction(scard.SCardLeaveCard)
						_, _ = card.Disconnect(scard.SCardLeaveCard)
						continue
					}

					info, err := yubikey.GetDeviceInfo(tx)
					if err != nil {
						_, _ = card.EndTransaction(scard.SCardLeaveCard)
						_, _ = card.Disconnect(scard.SCardLeaveCard)
						continue
					}

					fmt.Println(info)
					fmt.Println(yubikey.GetSerialNumber(tx))
					pgpAPI, err := pgp.New(tx)
					if err != nil {
						_, _ = card.EndTransaction(scard.SCardLeaveCard)
						_, _ = card.Disconnect(scard.SCardLeaveCard)
						fmt.Println(err)
						continue
					}

					aidSN := pgpAPI.AID.Serial

					var sn int32
					sn |= int32(aidSN[0]) << 24
					sn |= int32(aidSN[1]) << 16
					sn |= int32(aidSN[2]) << 8
					sn |= int32(aidSN[3])
					if fmt.Sprintf("%X", sn) == serial {
						defer card.EndTransaction(scard.SCardLeaveCard)
						defer card.Disconnect(scard.SCardLeaveCard)
						return handler(tx)
					} else {
						card.EndTransaction(scard.SCardLeaveCard)
						card.Disconnect(scard.SCardLeaveCard)
					}

				}
			}
			return fmt.Errorf("No card found with serials: %v", serials)
		},
	}
}

func (lib *Library) Free() {
	scard.Finalize()
}

type TX struct {
	r    string
	ctx  scard.Context
	card scard.Card
	send *scard.SCardIORequest
	recv *scard.SCardIORequest
	getr iso.Instruction
}

func (lib *Library) Filter(serials ...string) *Manager {
	return &Manager{
		serials: serials,
	}
}

func (lib *Library) PGP(handler func(*pgp.TX) error, serials ...string) error {
	return lib.TX(func(tx *TX) error {
		pgpTX, err := pgp.New(tx)
		if err != nil {
			return err
		}
		return handler(pgpTX)
	}, serials...)
}

func (lib *Library) PIV(handler func(*piv.TX) error, serials ...string) error {
	return lib.TX(func(tx *TX) error {
		pivTX, err := piv.New(tx)
		if err != nil {
			return err
		}
		return handler(pivTX)
	}, serials...)
}

func (lib *Library) TX(handler func(*TX) error, serials ...string) error {
	return lib.run(handler, serials...)
}

func (tx *TX) SendAPDU(cmd *iso.CAPDU) (respBuf []byte, err error) {
	cmdBuf, err := cmd.Bytes()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize CAPDU: %w", err)
	}

	for {
		r, _, err := tx.Transmit(cmdBuf)
		if err != nil {
			return nil, fmt.Errorf("failed to transmit CAPDU: %w", err)
		}

		resp, err := iso.ParseRAPDU(r)
		if err != nil {
			return nil, fmt.Errorf("failed to parse RAPDU: %w", err)
		}

		respCode := resp.Code()
		respBuf = append(respBuf, resp.Data...)

		switch {
		case respCode.HasMore():
			cmdBuf = []byte{0x00, byte(tx.getr), 0x00, 0x00}

		case respCode.IsSuccess():
			return respBuf, nil

		default:
			return nil, respCode
		}
	}
}

func (tx *TX) Transmit(data []byte) ([]byte, uint64, error) {
	return tx.card.Transmit(tx.send, data, tx.recv)
}

func (tx *TX) Select(aid []byte) error {
	_, err := tx.SendAPDU(&iso.CAPDU{Ins: iso.InsSelect, P1: 0x04, P2: 0x00, Data: aid})
	return err
}

func (tx *TX) SetGRIns(ins iso.Instruction) {
	tx.getr = ins
}
