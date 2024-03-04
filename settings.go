package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"time"
)

const (
	FLAG_DETAILS   = "details"
	FLAG_FULLCHAIN = "fullchain"
	FLAG_VERIFY    = "verify"
)

type Settings struct {
	Details   bool
	FullChain bool
	Verify    bool
	Now       time.Time
}

func (cfg Settings) ReportErr(domain string, err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, domain, "|", err.Error())
	}
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

func (cfg Settings) ReportDomain(domain string) {

	cstate, err := GetConnState(domain)

	if err != nil {

		cfg.ReportErr(domain, err)

	} else {

		for ix, cert := range cstate.PeerCertificates {

			cfg.ReportCert(domain, ix, cert)

			// report only first if fullchain not set
			if !cfg.FullChain {
				break
			}
		}
	}
}

func (cfg Settings) ReportCert(domain string, certIx int, cert *x509.Certificate) {

	shaPubkey := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	shaCert := sha256.Sum256(cert.Raw)

	ri := ReportItem{
		CertIx:    certIx,
		Domain:    domain,
		Issuer:    cert.Issuer.String(),
		NotBefore: cert.NotBefore,
		NotAfter:  cert.NotAfter,
		PubkeySig: shaPubkey[:],
		CertSig:   shaCert[:],
	}

	if cfg.Verify {
		_, ri.Valid = cert.Verify(x509.VerifyOptions{})
	}

	if cfg.Details {
		// TODO: JSON out
	} else {
		ri.ReportSimple(cfg.Now)
	}

	/*
		TODO:
			- chain presentation (JSON vs tabular)
			- present subject domain in output
			- SNI?
	*/
}
