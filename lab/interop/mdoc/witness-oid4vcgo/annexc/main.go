// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Egor Khaklin and the Polaris contributors

// OID4VCgo's mdocdcapi.VerifyResponse (github.com/idfoundry/oid4vcgo, MIT, by Oscar Sanderson), its
// ISO/IEC 18013-7 Annex C verifier, over each row of ../annexc-rows.json at the rows' instant.
//
//	annexc /in/annexc-rows.json
//
// One JSON line per row judged at the rows' instant ("when": "instant"), and for each row of kind
// "window" a second judged at the run date, this program's clock ("when": "run_date"), each
// prefixed "WITNESS ", then "WITNESS-DONE n", n the number of rows. Each row's Pending is built from
// the row: its origin, docType, requested elements, EncryptionInfo and recipient key, expiring five
// minutes after the time it is judged at. VerifyParams.Now is that time, which mdocdcapi gives to the
// MSO validity and, through verifier.WithVerificationTime, to the issuer certificate checks
// (mdocdcapi/response.go, verifyDocument); MaxClockSkew is the rows' max_skew_seconds. The trust
// anchor is the rows' IACA, through verifier.X5ChainIssuerKeyResolver with revocation declined
// (certrevocation.NoCheck{}), under verifier.AssuranceDevelopment with NoStatusCheck and Origins
// left empty, which there admits any https origin. A row this program cannot set up (a key or an
// instant that does not parse) prints outcome "error", which ../agree.py never reads as a verdict.
package main

import (
	"context"
	"crypto/ecdh"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/mdocdcapi"
	"github.com/idfoundry/oid4vcgo/verifier"
)

type fixture struct {
	At             string `json:"at"`
	MaxSkewSeconds int    `json:"max_skew_seconds"`
	IACA           string `json:"iaca_der_b64"`
	Rows           []row  `json:"rows"`
}

type row struct {
	ID              string              `json:"id"`
	Kind            string              `json:"kind"`
	Origin          string              `json:"origin"`
	DocType         string              `json:"doctype"`
	Elements        map[string][]string `json:"elements"`
	EncryptionInfo  string              `json:"encryption_info"`
	RecipientKeyHex string              `json:"recipient_key_hex"`
	Response        string              `json:"response"`
}

type verdict struct {
	ID      string                    `json:"id"`
	When    string                    `json:"when"`
	Outcome string                    `json:"outcome"`
	Error   string                    `json:"error,omitempty"`
	Claims  map[string]map[string]any `json:"claims,omitempty"`
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: annexc ROWS.json")
		os.Exit(2)
	}
	raw, err := os.ReadFile(os.Args[1])
	stop(err)
	var in fixture
	stop(json.Unmarshal(raw, &in))
	if len(in.Rows) == 0 {
		stop(fmt.Errorf("%s has no rows", os.Args[1]))
	}
	at, err := time.Parse(time.RFC3339, in.At)
	stop(err)
	der, err := base64.StdEncoding.DecodeString(in.IACA)
	stop(err)
	iaca, err := x509.ParseCertificate(der)
	stop(err)
	roots := x509.NewCertPool()
	roots.AddCert(iaca)
	runDate := time.Now().UTC().Truncate(time.Second)
	for _, r := range in.Rows {
		emit(judge(r, at, in.MaxSkewSeconds, roots), "instant")
		if r.Kind == "window" {
			emit(judge(r, runDate, in.MaxSkewSeconds, roots), "run_date")
		}
	}
	fmt.Printf("WITNESS-DONE %d\n", len(in.Rows))
}

func emit(v verdict, when string) {
	v.When = when
	line, err := json.Marshal(v)
	if err != nil {
		line, _ = json.Marshal(verdict{ID: v.ID, When: when, Outcome: "error", Error: "encode the verdict: " + err.Error()})
	}
	fmt.Printf("WITNESS %s\n", line)
}

func judge(r row, at time.Time, skew int, roots *x509.CertPool) verdict {
	scalar, err := hex.DecodeString(r.RecipientKeyHex)
	if err != nil {
		return verdict{ID: r.ID, Outcome: "error", Error: "recipient_key_hex: " + err.Error()}
	}
	key, err := ecdh.P256().NewPrivateKey(scalar)
	if err != nil {
		return verdict{ID: r.ID, Outcome: "error", Error: "recipient key: " + err.Error()}
	}
	elements := make(map[string]map[string]bool, len(r.Elements))
	for ns, names := range r.Elements {
		asked := make(map[string]bool, len(names))
		for _, name := range names {
			asked[name] = false
		}
		elements[ns] = asked
	}
	verified, err := mdocdcapi.VerifyResponse(context.Background(), mdocdcapi.VerifyParams{
		Pending: mdocdcapi.Pending{
			Origin: r.Origin, DocType: r.DocType, Elements: elements, EncryptionInfo: r.EncryptionInfo,
			RecipientKey: key, ExpiresAt: at.Add(5 * time.Minute),
		},
		Response:      r.Response,
		IssuerKeys:    verifier.X5ChainIssuerKeyResolver{Roots: roots, Revocation: certrevocation.NoCheck{}},
		Now:           func() time.Time { return at },
		MaxClockSkew:  time.Duration(skew) * time.Second,
		Assurance:     verifier.AssuranceDevelopment,
		NoStatusCheck: true,
	})
	if err != nil {
		return verdict{ID: r.ID, Outcome: "refused", Error: err.Error()}
	}
	return verdict{ID: r.ID, Outcome: "accepted", Claims: verified.NameSpaces}
}

func stop(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "annexc:", err)
		os.Exit(1)
	}
}
