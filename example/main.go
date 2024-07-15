package main

import (
	"fmt"
	"github.com/malivvan/pcsc"
	"github.com/malivvan/pcsc/pgp"
	"github.com/malivvan/pcsc/piv"
)

type Config struct {
	Import     []string // List of PGP imports e.g. armoured keys
	Select     string   // reference to the PGP key used for signing messages
	SCard      []string // List of YubiKey serial numbers
	PGPSession string   // reference to the PGP key used for session auth
}

func main() {
	lib := pcsc.Load()
	defer lib.Free()

	err := lib.PGP(func(tx *pgp.TX) error {

		fmt.Println(tx.Challenge(10))
		return nil
	}, "25352142")
	if err != nil {
		fmt.Println(err)
		return
	}

	err = lib.PIV(func(tx *piv.TX) error {
		fmt.Println(tx.Serial())
		fmt.Println(tx.Certificate(piv.SlotAttestation))
		return nil
	}, "25352142")
	if err != nil {
		fmt.Println(err)
		return
	}
}
