package main

import (
	"fmt"
	"math/big"
	"strings"

	"errors"

	"github.com/OpenICP-BR/libICP"
	"github.com/mkideal/cli"
	clix "github.com/mkideal/cli/ext"
)

type genT struct {
	cli.Helper
	Subject    string    `cli:"s,subject" usage:"name of the certificate holder"`
	Issuer     string    `cli:"i,issuer" usage:"path to the issuer CA certificate. If null, a new self-signed root CA will be created"`
	NotBefore  clix.Time `cli:"b,not-before" usage:"not-before certificate attribute, use YYYY-mm-dd format"`
	NotAfter   clix.Time `cli:"a,not-after" usage:"not-after certificate attribute, use YYYY-mm-dd format"`
	Output     string    `cli:"o,output" usage:"path to write the result certificate" dft:"output.pfx"`
	Serial     string    `cli:"n,serial" usage:"sets the serial number for the new certificate"`
	Password   string    `cli:"p,password" usage:"password to encrypt the output file with"`
	InPassword string    `cli:"q,in-password" usage:"password of the input file"`
}

func GenFunc(ctx *cli.Context) error {
	var pfx libICP.PFX
	var cerr libICP.CodedError

	argv := ctx.Argv().(*genT)
	not_before := argv.NotBefore.Time
	not_after := argv.NotAfter.Time

	if argv.Issuer == "" {
		pfx, cerr = libICP.NewRootCA(not_before, not_after)
		if cerr != nil {
			return cerr
		}
		cerr = pfx.SaveToFile(argv.Output, argv.Password)
		if cerr != nil {
			return cerr
		}
	} else {
		// Parse subject
		subject_parts := strings.Split(argv.Subject, "/")
		subject := make(map[string]string)
		for _, part := range subject_parts {
			subpart := strings.Split(part, "=")
			if len(subpart) < 2 {
				continue
			}
			subject[subpart[0]] = subpart[1]
		}
		if subject["CN"] == "" || subject["C"] == "" {
			return errors.New("subject must have country and common name")
		}

		// Parse serial
		serial := big.NewInt(0)
		if argv.Serial == "" {
			argv.Serial = "1"
		}
		_, ok := serial.SetString(argv.Serial, 10)
		if !ok {
			return errors.New("serial must be a base 10 number")
		}

		// Load issuer
		issuer_pfx, err := libICP.NewPFXFromFile(argv.Issuer, argv.InPassword)
		if err != nil {
			fmt.Println("Is the password wrong?")
			return err
		}

		// Issue new certificate
		pfx, cerr = libICP.NewCertAndKey(subject, *issuer_pfx.Cert, serial, not_before, not_after)
		if cerr != nil {
			return cerr
		}

		// Save it
		cerr = pfx.SaveToFile(argv.Output, argv.Password)
		if cerr != nil {
			return cerr
		}
	}

	fmt.Printf("Issuer:  %s\n", pfx.Cert.Issuer)
	fmt.Printf("Subject: %s\n", pfx.Cert.Subject)

	if argv.Issuer == "" {
		fmt.Printf("%s[DONE] Root certificate written to file: %s%s\n", FgGreen+Bold, Reset, argv.Output)
	} else {
		fmt.Printf("%s[DONE] Certificate written to file: %s%s\n", FgGreen+Bold, Reset, argv.Output)
	}

	return nil
}
