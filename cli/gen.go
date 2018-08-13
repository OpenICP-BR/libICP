package main

import (
	"fmt"

	"github.com/gjvnq/libICP"
	"github.com/mkideal/cli"
)

func GenFunc(ctx *cli.Context) error {
	argv := ctx.Argv().(*genT)
	if argv.Issuer == "" {
		pfx, cerr := libICP.NewRootCA(argv.NotBefore.Time, argv.NotAfter.Time)
		if cerr != nil {
			return cerr
		}
		cerr = pfx.SaveToFile(argv.Output, argv.Password)
		if cerr != nil {
			return cerr
		}
		fmt.Printf("[DONE] Root certificate written to file: %s\n", argv.Output)
	}
	return nil
}
