package main

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

type TTLInfo int

const (
	TTLI_OK TTLInfo = iota
	TTLI_EXPIRED
	TTLI_NOTYET
)

func (ti TTLInfo) String() string {
	switch ti {
	case TTLI_OK:
		return "OK"
	case TTLI_EXPIRED:
		return "EX"
	case TTLI_NOTYET:
		return "NY"
	}
	return "??"
}

type ReportItem struct {
	Query       string
	ChainIndex  int
	CommonName  string
	Issuer      string
	Verified    bool
	VerifyError string `json:",omitempty"`
	PubkeySig   []byte
	CertSig     []byte
	NotBefore   time.Time
	NotAfter    time.Time
	TTLDays     float64
	TTLInfo     TTLInfo           `json:"-"`
	Certificate *x509.Certificate `json:"-"`
}

// [< 0] Days Expired
// [>= 0] Days Remaining
func CalcTTLDays(NotBefore, NotAfter, now time.Time) (float64, TTLInfo) {

	var dur time.Duration
	info := TTLI_OK

	if now.Compare(NotBefore) < 0 {
		dur = NotAfter.Sub(NotBefore)
		info = TTLI_NOTYET
	} else {
		dur = NotAfter.Sub(now)
		if dur < 0 {
			info = TTLI_EXPIRED
		}
	}

	return (dur.Hours() / 24.0), info
}

const SEP = "\t"

func (ri ReportItem) ReportSimple(isTTY bool) error {

	_, err := fmt.Fprintln(
		os.Stdout,
		fmt.Sprintf("%s [%d]", ri.CommonName, ri.ChainIndex), SEP,
		ri.NotBefore.Format(time.DateTime), SEP,
		ri.NotAfter.Format(time.DateTime), SEP,
		fmt.Sprintf("%7.2f", ri.TTLDays), SEP,
		ri.TTLInfo.String(), SEP,
	)

	return err

	/*
		TODO: issuer
		TODO: modes
			- expiry
			- issuer
			- signatures
			- all
	*/

	// fmt.Printf("PubKey Signature (SHA256): %s\n", hex.EncodeToString(shaPk[:]))
	// fmt.Printf("  Cert Signature (SHA256): %s\n", hex.EncodeToString(shaCrt[:]))
	// Valid     error
	// PubkeySig []byte
	// CertSig   []byte
}

func (ri ReportItem) ReportJSON(isTTY bool) error {

	pEnc := json.NewEncoder(os.Stdout)

	if isTTY {
		pEnc.SetIndent("", "\t")
	}

	/*
		TODO: SNI
		TODO: base64 of sha hashes
	*/

	// fmt.Printf("PubKey Signature (SHA256): %s\n", hex.EncodeToString(shaPk[:]))
	// fmt.Printf("  Cert Signature (SHA256): %s\n", hex.EncodeToString(shaCrt[:]))

	return pEnc.Encode(&ri)

}
