package main

import (
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
	CertIx    int
	Domain    string
	Issuer    string
	NotBefore time.Time
	NotAfter  time.Time
	Valid     error
	PubkeySig []byte
	CertSig   []byte
}

// [< 0] Days Expired
// [>= 0] Days Remaining
func (ri ReportItem) CalcTTLDays(now time.Time) (float64, TTLInfo) {

	var dur time.Duration
	info := TTLI_OK

	if now.Compare(ri.NotBefore) < 0 {
		dur = ri.NotAfter.Sub(ri.NotBefore)
		info = TTLI_NOTYET
	} else {
		dur = ri.NotAfter.Sub(now)
		if dur < 0 {
			info = TTLI_EXPIRED
		}
	}

	return (dur.Hours() / 24.0), info
}

const SEP = "\t"

func (ri ReportItem) ReportSimple(now time.Time) {

	TTL, info := ri.CalcTTLDays(now)

	fmt.Fprintln(
		os.Stdout,
		fmt.Sprintf("%s [%d]", ri.Domain, ri.CertIx), SEP,
		ri.NotBefore.Format(time.DateTime), SEP,
		ri.NotAfter.Format(time.DateTime), SEP,
		fmt.Sprintf("%7.2f", TTL), SEP,
		info.String(), SEP,
	)

	/*
		TODO: goquote unstructured strings, tab separate
						strconv.Quote(ri.Issuer),
		TODO: issued-to
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
