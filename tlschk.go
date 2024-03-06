package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/chzyer/readline"
	"github.com/mattn/go-isatty"
)

func main() {

	var err error
	defer func() {
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
		}
	}()

	cfg := Settings{
		Now:   time.Now(),
		IsTTY: isatty.IsTerminal(os.Stdout.Fd()),
	}

	flag.BoolVar(&cfg.Details, FLAG_DETAILS, false, "full cert details in JSON format")
	flag.BoolVar(&cfg.FullChain, FLAG_FULLCHAIN, false, "report all certs in chain")
	flag.BoolVar(&cfg.Verify, FLAG_VERIFY, false, "verify all certs in chain")
	flag.Parse()

	sDomains := flag.Args()
	if len(sDomains) > 0 {

		// queries from args
		for _, domain := range sDomains {
			cfg.ProcessLine(domain)
		}

	} else {

		// TODO: save & restore repl entries

		// queries from REPL
		rl, err := readline.New("> ")
		if err != nil {
			return
		}
		defer rl.Close()

		for {
			domain, e2 := rl.Readline()
			if e2 != nil {
				err = e2
				return
			}

			cfg.ProcessLine(domain)
		}
	}
}
