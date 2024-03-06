package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

const (
	FLAG_DETAILS   = "detail"
	FLAG_FULLCHAIN = "fullchain"
	FLAG_VERIFY    = "verify"
)

type Settings struct {
	Details   bool
	FullChain bool
	Verify    bool
	Now       time.Time
	IsTTY     bool
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

var g_pDialer *net.Dialer

func init() {
	g_pDialer = new(net.Dialer)
	g_pDialer.KeepAlive = -1
	g_pDialer.Timeout = time.Second * 10
}

func GetConnState(domain string) (tls.ConnectionState, error) {

	// TODO: intercept first ctrl-c to cancel dial without closing
	conn, err := tls.DialWithDialer(
		g_pDialer,
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

func (cfg Settings) ReportCert(domain string, certIx int, cert *x509.Certificate) error {

	shaPubkey := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	shaCert := sha256.Sum256(cert.Raw)

	ri := ReportItem{
		Query:       domain,
		ChainIndex:  certIx,
		CommonName:  cert.Subject.String(),
		Issuer:      cert.Issuer.String(),
		PubkeySig:   shaPubkey[:],
		CertSig:     shaCert[:],
		Certificate: cert,
		NotBefore:   cert.NotBefore,
		NotAfter:    cert.NotAfter,
	}

	ri.TTLDays, ri.TTLInfo = CalcTTLDays(cert.NotBefore, cert.NotAfter, cfg.Now)

	// TODO: document that revocation lists aren't checked
	// TODO: document 'signed by unknown authority' when -fullchain not set

	if cfg.Verify {
		if _, verr := cert.Verify(x509.VerifyOptions{}); verr != nil {
			ri.VerifyError = verr.Error()
		} else {
			ri.Verified = true
		}
	}

	if cfg.Details {
		return ri.ReportJSON(cfg.IsTTY)
	} else {
		return ri.ReportSimple(cfg.IsTTY)
	}
}
