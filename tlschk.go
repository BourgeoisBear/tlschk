package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/chzyer/readline"
)

func GetConnState(domain string) (tls.ConnectionState, error) {

	// TODO: set timeout
	// TODO: intercept first ctrl-c to cancel dial without closing
	conn, err := tls.Dial(
		"tcp",
		domain,
		&tls.Config{InsecureSkipVerify: true},
	)
	if err != nil {
		return tls.ConnectionState{}, err
	}
	defer conn.Close()

	return conn.ConnectionState(), nil
}

type Settings struct {
	Details   bool
	FullChain bool
	Verify    bool
}

func (cfg Settings) ReportErr(domain string, err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, domain, "|", err.Error())
	}
}

func (cfg Settings) ReportCert(domain string, cert *x509.Certificate) {

	fmt.Println("---------------------------")

	fmt.Printf("   Issuer: %s\n", cert.Issuer)
	fmt.Printf("NotBefore: %s \n", cert.NotBefore.Format(time.RFC3339))
	fmt.Printf(" NotAfter: %s \n", cert.NotAfter.Format(time.RFC3339))

	tNow := time.Now()
	bValid := (tNow.Compare(cert.NotBefore) >= 0) && (tNow.Compare(cert.NotAfter) <= 0)
	fmt.Printf("   DateOK: %v\n", bValid)

	if cfg.Verify {
		_, err := cert.Verify(x509.VerifyOptions{})
		if err != nil {
			cfg.ReportErr(domain, err)
		}
		// TODO: format instead of ReportErr
	}

	/*
		TODO:
			- chain presentation (JSON vs tabular)
			- present subject domain in output
			- calc days remaining
			- SNI?
	*/

	shaPk := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	fmt.Printf("PubKey Signature (SHA256): %s\n", hex.EncodeToString(shaPk[:]))
	shaCrt := sha256.Sum256(cert.Raw)
	fmt.Printf("  Cert Signature (SHA256): %s\n", hex.EncodeToString(shaCrt[:]))
}

func (pCfg *Settings) ProcessLine(line string) {

	// check for formatting flag updates
	if flag, bFound := strings.CutPrefix(line, "-"); bFound {

		flag = strings.ToLower(strings.TrimSpace(flag))

		switch flag {
		case FLAG_DETAILS:
			pCfg.Details = !pCfg.Details
			fmt.Fprintf(os.Stderr, "%s | %t\n", flag, pCfg.Details)
		case FLAG_FULLCHAIN:
			pCfg.FullChain = !pCfg.FullChain
			fmt.Fprintf(os.Stderr, "%s | %t\n", flag, pCfg.FullChain)
		case FLAG_VERIFY:
			pCfg.Verify = !pCfg.Verify
			fmt.Fprintf(os.Stderr, "%s | %t\n", flag, pCfg.Verify)
		default:
			fmt.Fprintf(os.Stderr, "%s | INVALID FLAG\n", flag)
		}

	} else {

		pCfg.ReportDomain(line)

	}
}

func (cfg Settings) ReportDomain(domain string) {

	cstate, err := GetConnState(domain)

	if err != nil {

		cfg.ReportErr(domain, err)

	} else {

		for _, cert := range cstate.PeerCertificates {

			cfg.ReportCert(domain, cert)

			// report only first if fullchain not set
			if !cfg.FullChain {
				break
			}
		}
	}
}

const (
	FLAG_DETAILS   = "details"
	FLAG_FULLCHAIN = "fullchain"
	FLAG_VERIFY    = "verify"
)

func main() {

	var err error
	defer func() {
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
		}
	}()

	cfg := Settings{}

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
