package main

import (
	"fmt"
	"os"

	"github.com/mkideal/cli"
	clix "github.com/mkideal/cli/ext"
)

var help = cli.HelpCommand("display help information")

type rootT struct {
	cli.Helper
	CACache    string `cli:"C,ca-cache" usage:"sets the directory that holds the CAs" dft:"$HOME/.cache/OpenICP-BR/CAs"`
	FakeRootCA string `cli:"fake-root-ca" usage:"path to a testing CA (only for testing) (do not touch this)"`
}

var root = &cli.Command{
	Argv: func() interface{} { return new(rootT) },
	Fn: func(ctx *cli.Context) error {
		help.Run(nil)
		return nil
	},
}

type signT struct {
	cli.Helper
	ContentFile   string `cli:"c,content" usage:"path to the content to be signed"`
	SignatureFile string `cli:"s,signature" usage:"path to the signature (will be created if does not exist)"`
	IsDetached    bool   `cli:"a,attach" usage:"if false, the content will NOT be included in the signature file. If true, the content will be included, resulting in a larger file"`
}

var sign = &cli.Command{
	Name: "sign",
	Desc: "Signs a file using a digital certificate",
	Argv: func() interface{} { return new(signT) },
	Fn: func(ctx *cli.Context) error {
		argv := ctx.Argv().(*signT)
		ctx.String("Hello, sign command, I am %s %+v\n", argv.ContentFile, argv.IsDetached)
		return nil
	},
}

type joinSigsT struct {
	cli.Helper
	Name string `cli:"name" usage:"your name"`
}

var joinSigs = &cli.Command{
	Name: "join",
	Desc: "Join multiple signature files into one",
	Argv: func() interface{} { return new(joinSigsT) },
	Fn: func(ctx *cli.Context) error {
		argv := ctx.Argv().(*joinSigsT)
		ctx.String("Hello, verify command, I am %s\n", argv.Name)
		return nil
	},
}

type verifyT struct {
	cli.Helper
	Name string `cli:"name" usage:"your name"`
}

var verify = &cli.Command{
	Name: "verify",
	Desc: "Verifies if a signature is valid",
	Argv: func() interface{} { return new(verifyT) },
	Fn: func(ctx *cli.Context) error {
		argv := ctx.Argv().(*verifyT)
		ctx.String("Hello, verify command, I am %s\n", argv.Name)
		return nil
	},
}

type genT struct {
	cli.Helper
	Subject   string    `cli:"s,subject" usage:"name of the certificate holder"`
	Issuer    string    `cli:"i,issuer" usage:"path to the issuer CA certificate. If null, a new self-signed root CA will be created"`
	NotBefore clix.Time `cli:"b,not-before" usage:"not-before certificate attribute, use YYYY-mm-dd format"`
	NotAfter  clix.Time `cli:"a,not-after" usage:"not-after certificate attribute, use YYYY-mm-dd format"`
	Output    string    `cli:"o,output" usage:"path to write the result certificate" dft:"output.pfx"`
	Password  string    `cli:"p,password" usage:"password to encrypt the output file with"`
}

var gen = &cli.Command{
	Name: "gen",
	Desc: "generates a new testing certificate",
	Argv: func() interface{} { return new(genT) },
	Fn:   GenFunc,
}

func main() {
	if err := cli.Root(root,
		cli.Tree(help),
		cli.Tree(gen),
		cli.Tree(sign),
		cli.Tree(verify),
		cli.Tree(joinSigs),
	).Run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
