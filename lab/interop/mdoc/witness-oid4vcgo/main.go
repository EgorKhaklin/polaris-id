// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Egor Khaklin and the Polaris contributors

// OID4VCgo (github.com/idfoundry/oid4vcgo, MIT, by Oscar Sanderson) as an mdoc witness: its own
// verifier-side mdoc code over each case of ../../negative-vectors/mdoc-vectors.json and each
// case's repaired twin.
//
//	witness /in/mdoc-vectors.json
//
// Two paths, both OID4VCgo's code, one JSON line per case and variant, prefixed "WITNESS ":
//
//	composed        every case. The exported functions verifier.verifyMdocPresentation calls
//	                (verifier/verify_response.go:685-766), in its order and with its stage
//	                labels: oid4vpmdoc.UnmarshalDeviceResponse, the issuer key from the IssuerAuth
//	                x5chain (verifier.X5ChainIssuerKeyResolver), mdoc.Verify,
//	                verifier.CheckMdocIssuer, oid4vpmdoc.BuildSessionTranscriptBytes or
//	                BuildDCAPISessionTranscriptBytes, the DeviceAuth type, mdoc.VerifyDeviceSignature,
//	                mdoc.CheckKeyAuthorizations, dcql.CredentialQuery.SatisfiedByMdocClaims, after
//	                dcql.Query.Validate, which VerifyResponse runs first. The query is the case's:
//	                its doctype_value, and its claims and claim_sets where it carries them. The
//	                SessionTranscript is built from the case's own request: client_id, nonce,
//	                response_uri and the RFC 7638 thumbprint of its encryption JWK (redirect), or
//	                origin, nonce and that thumbprint (DC API). The order and the labels are read
//	                from verify_response.go; no test here holds them to VerifyResponse.
//	verify_response the DC API cases only: the whole of verifier.Verifier.VerifyResponse, with
//	                Origin set. A redirect-flow Verifier's client_id is always derived from the
//	                hash of its own certificate (verifier/config.go:151-162, 240), so a request
//	                whose client_id has another prefix cannot be given to VerifyResponse, and only
//	                the composed path runs for it.
//	diagnostic      the composed path with verifier.CheckMdocIssuer (the document signer
//	                certificate checks) left out, as a diagnostic of the stages after it: never a
//	                verdict.
//
// The x5chain is taken from the IssuerAuth by x5chainOf, which restates cose.X5ChainOf
// (internal/cose/cose.go:616-626 at v0.49.0), a function of OID4VCgo's internal cose package that no
// caller outside the module can import; no test here holds it to it. x5chainOf checks no header:
// mdoc.Verify's cose.Verify decodes the IssuerAuth with decodeRaw and checks both buckets with
// rawSign1.headers (cose.go:305-324, 351-355, 400-413 and 512-526), the two functions
// cose.DecodeUnverified runs for verifyMdocPresentation (cose.go:382-398), so OID4VCgo's own code
// refuses a duplicate map key, a crit, a protected bucket it cannot decode, or an alg, kid or typ of
// the wrong type, with the cose package's own error text. The chain itself is verified by
// OID4VCgo. The trust anchors are the case's, and the instant is the case's, given to
// both the certificate checks and the MSO validity.
package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/fxamacker/cbor/v2"
	fapi "github.com/idfoundry/fapigo"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/oid4vpmdoc"
	"github.com/idfoundry/oid4vcgo/verifier"
)

type jwkKey struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type inputs struct {
	ResponseMode  string          `json:"response_mode"`
	ClientID      string          `json:"client_id"`
	Nonce         string          `json:"nonce"`
	ResponseURI   string          `json:"response_uri"`
	Origin        string          `json:"origin"`
	EncryptionJWK *jwkKey         `json:"encryption_jwk"`
	DoctypeValue  string          `json:"doctype_value"`
	Claims        json.RawMessage `json:"claims"`
	ClaimSets     json.RawMessage `json:"claim_sets"`
}

// query is the case's DCQL query: one mso_mdoc Credential Query for its doctype_value, with its
// claims and claim_sets where it carries them, decoded into OID4VCgo's own types and validated.
func (in inputs) query() (dcql.Query, error) {
	cq := dcql.MdocQuery("mdoc", in.DoctypeValue)
	if len(in.Claims) > 0 {
		if err := json.Unmarshal(in.Claims, &cq.Claims); err != nil {
			return dcql.Query{}, err
		}
	}
	if len(in.ClaimSets) > 0 {
		if err := json.Unmarshal(in.ClaimSets, &cq.ClaimSets); err != nil {
			return dcql.Query{}, err
		}
	}
	q := dcql.Query{Credentials: []dcql.CredentialQuery{cq}}
	return q, q.Validate()
}

type vector struct {
	ID       string   `json:"id"`
	At       string   `json:"at"`
	Anchors  []string `json:"trust_anchors_pem"`
	Inputs   inputs   `json:"inputs"`
	Response string   `json:"response"`
	Repaired *struct {
		Response string `json:"response"`
		Inputs   inputs `json:"inputs"`
	} `json:"repaired"`
}

type corpus struct {
	Version string   `json:"version"`
	Vectors []vector `json:"vectors"`
}

// verdict is one path's result: accepted, or refused at a stage with OID4VCgo's error text.
type verdict struct {
	Outcome       string `json:"outcome"`
	Stage         string `json:"stage,omitempty"`
	Error         string `json:"error,omitempty"`
	TranscriptHex string `json:"transcript_hex,omitempty"`
	NotRun        string `json:"not_run,omitempty"`
}

func refused(stage string, err error, transcript []byte) verdict {
	v := verdict{Outcome: "refused", Stage: stage, Error: err.Error()}
	if transcript != nil {
		v.TranscriptHex = hex.EncodeToString(transcript)
	}
	return v
}

func encryptionKey(j *jwkKey) (*ecdsa.PublicKey, []byte, error) {
	if j == nil || j.Kty != "EC" || j.Crv != "P-256" {
		return nil, nil, errors.New("the case's encryption_jwk is not an EC P-256 key")
	}
	x, err := base64.RawURLEncoding.DecodeString(j.X)
	if err != nil {
		return nil, nil, err
	}
	y, err := base64.RawURLEncoding.DecodeString(j.Y)
	if err != nil {
		return nil, nil, err
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{0x04}, x...), y...))
	if err != nil {
		return nil, nil, err
	}
	// RFC 7638 section 3: the required members in lexicographic order, no whitespace.
	canon := fmt.Sprintf(`{"crv":"%s","kty":"EC","x":"%s","y":"%s"}`, j.Crv, j.X, j.Y)
	sum := sha256.Sum256([]byte(canon))
	return pub, sum[:], nil
}

// preReadMode decodes an IssuerAuth only to find its x5chain: the bounds cose.DecodeUnverified
// decodes it with (internal/cose/cose.go:597-614), but a duplicate map key is let through, so that
// mdoc.Verify refuses it, not this pre-read.
var preReadMode = func() cbor.DecMode {
	mode, err := cbor.DecOptions{
		MaxNestedLevels:   16,
		MaxArrayElements:  4096,
		MaxMapPairs:       4096,
		DupMapKey:         cbor.DupMapKeyQuiet,
		FieldNameMatching: cbor.FieldNameMatchingCaseSensitive,
	}.DecMode()
	if err != nil {
		panic("build CBOR decoder: " + err.Error())
	}
	return mode
}()

// sign1MaxBytes is cose.MaxBytes (cose.go:224), the largest COSE_Sign1 cose.DecodeUnverified reads.
const sign1MaxBytes = 1 << 16

// rawSign1 is cose.rawSign1 (cose.go:191-197): an untagged COSE_Sign1.
type rawSign1 struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected map[int]any
	Payload     []byte
	Signature   []byte
}

// x5chainOf takes an IssuerAuth's chain as cose.X5ChainOf takes it (cose.go:616-626): the protected
// bucket's, else the unprotected bucket's. It refuses only what leaves no chain to read: an
// IssuerAuth over the size limit, not a CBOR array, or an x5chain that is not a byte string or an
// array of them. Every other header is left to mdoc.Verify, and a zero-length protected bucket is read
// as an empty one, so that mdoc.Verify decides it too. An IssuerAuth with no chain is not
// refused here: the issuer key resolver refuses its empty chain, as it does in
// verifyMdocPresentation. No test here holds the chain it takes to OID4VCgo.
func x5chainOf(sign1 []byte) ([][]byte, error) {
	if len(sign1) > sign1MaxBytes {
		return nil, fmt.Errorf("issuer auth is %d bytes, over the %d byte limit", len(sign1), sign1MaxBytes)
	}
	body := sign1
	if len(body) > 0 && body[0] == 0xd2 { // COSE_Sign1_Tagged: tag 18 in its one-byte form
		body = body[1:]
	}
	if len(body) == 0 || body[0]>>5 != 4 { // CBOR major type 4: an array
		return nil, errors.New("issuer auth is not a CBOR array, untagged or tagged 18")
	}
	var raw rawSign1
	if err := preReadMode.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("issuer auth: %w", err)
	}
	var protected map[int]any
	if len(raw.Protected) > 0 {
		if err := preReadMode.Unmarshal(raw.Protected, &protected); err != nil {
			return nil, fmt.Errorf("protected header: %w", err)
		}
	}
	fromProtected, err := headerX5Chain(protected)
	if err != nil {
		return nil, fmt.Errorf("protected header: %w", err)
	}
	fromUnprotected, err := headerX5Chain(raw.Unprotected)
	if err != nil {
		return nil, fmt.Errorf("unprotected header: %w", err)
	}
	if len(fromProtected) > 0 {
		return fromProtected, nil
	}
	return fromUnprotected, nil
}

// headerX5Chain returns one header bucket's x5chain (label 33), nil if it has none, read as
// cose.x5ChainFromValue reads it (cose.go:149-167): a byte string or an array of them.
func headerX5Chain(h map[int]any) ([][]byte, error) {
	v, ok := h[33]
	if !ok {
		return nil, nil
	}
	switch chain := v.(type) {
	case []byte:
		return [][]byte{chain}, nil
	case []any:
		out := make([][]byte, len(chain))
		for i, item := range chain {
			der, ok := item.([]byte)
			if !ok {
				return nil, fmt.Errorf("x5chain entry %d is not a byte string", i)
			}
			out[i] = der
		}
		return out, nil
	default:
		return nil, fmt.Errorf("x5chain has unexpected type %T", v)
	}
}

// algForKey restates verifier.mdocAlgForKey (verifier/verify_response.go:785-794), which is
// unexported. No test here holds it to OID4VCgo: the controls reach its ES256 case, and nothing
// here reaches its EdDSA case.
func algForKey(pub crypto.PublicKey) (oid4vci.COSEAlg, error) {
	switch pub.(type) {
	case *ecdsa.PublicKey:
		return oid4vci.COSEES256, nil
	case ed25519.PublicKey:
		return oid4vci.COSEEdDSA, nil
	default:
		return 0, fmt.Errorf("unsupported public key type %T", pub)
	}
}

func composed(raw []byte, in inputs, roots *x509.CertPool, at time.Time, signerChecks bool) verdict {
	ctx := verifier.WithVerificationTime(context.Background(), at)
	query, err := in.query()
	if err != nil {
		return refused("query", err, nil)
	}
	doc, err := oid4vpmdoc.UnmarshalDeviceResponse(raw)
	if err != nil {
		return refused("unmarshal device response", err, nil)
	}
	x5chain, err := x5chainOf(doc.IssuerSigned.IssuerAuth)
	if err != nil {
		return refused("decode issuer auth", err, nil)
	}
	resolver := verifier.X5ChainIssuerKeyResolver{Roots: roots}
	issuerPub, issuerAlg, err := resolver.ResolveMdocIssuerKey(ctx, x5chain, doc.DocType)
	if err != nil {
		return refused("resolve issuer key", err, nil)
	}
	verified, err := mdoc.Verify(doc.IssuerSigned, doc.DocType, issuerPub, issuerAlg, mdoc.VerifyOptions{Now: func() time.Time { return at }})
	if err != nil {
		return refused("verify issuer signed", err, nil)
	}
	if signerChecks {
		if _, err := verifier.CheckMdocIssuer(ctx, resolver, x5chain, doc.DocType, issuerPub, verified); err != nil {
			return refused("check document signer", err, nil)
		}
	}
	_, thumbprint, err := encryptionKey(in.EncryptionJWK)
	if err != nil {
		return refused("response encryption key", err, nil)
	}
	var transcript []byte
	switch in.ResponseMode {
	case "dc_api.jwt":
		transcript, err = oid4vpmdoc.BuildDCAPISessionTranscriptBytes(oid4vpmdoc.DCAPIHandoverParams{
			Origin: in.Origin, Nonce: in.Nonce, ResponseEncryptionJWKThumbprint: thumbprint,
		})
	case "direct_post.jwt":
		transcript, err = oid4vpmdoc.BuildSessionTranscriptBytes(oid4vpmdoc.HandoverParams{
			ClientID: in.ClientID, Nonce: in.Nonce, ResponseURI: in.ResponseURI,
			ResponseEncryptionJWKThumbprint: thumbprint,
		})
	default:
		err = fmt.Errorf("response_mode %q has no transcript here", in.ResponseMode)
	}
	if err != nil {
		return refused("build session transcript", err, nil)
	}
	if doc.DeviceSigned.AuthType != mdoc.DeviceAuthSignature {
		return refused("device authentication type", fmt.Errorf("device authentication type %d is not supported", doc.DeviceSigned.AuthType), transcript)
	}
	deviceAlg, err := algForKey(verified.DeviceKey)
	if err != nil {
		return refused("device key", err, transcript)
	}
	if err := mdoc.VerifyDeviceSignature(doc.DeviceSigned, verified.DeviceKey, deviceAlg, transcript, doc.DocType); err != nil {
		return refused("verify device signature", err, transcript)
	}
	if err := mdoc.CheckKeyAuthorizations(doc.DeviceSigned.NameSpaces, verified.KeyAuthorizations); err != nil {
		return refused("check key authorizations", err, transcript)
	}
	if err := query.Credentials[0].SatisfiedByMdocClaims(verified.DocType, verified.NameSpaces); err != nil {
		return refused("satisfied by mdoc claims", err, transcript)
	}
	return verdict{Outcome: "accepted", TranscriptHex: hex.EncodeToString(transcript)}
}

// newVerifier is a Verifier for VerifyResponse over the DC API. Its client certificate and
// signing key sign requests only, and no request is built here: they are made fresh and unused.
func newVerifier() (*verifier.Verifier, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "unused"},
		NotBefore: time.Unix(0, 0), NotAfter: time.Unix(1<<33, 0), KeyUsage: x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	responseURI, err := fapi.ParseEndpointURL("https://unused.invalid/response")
	if err != nil {
		return nil, err
	}
	return verifier.New(verifier.Config{
		Assurance: verifier.AssuranceDevelopment, ClientCertificate: cert, ResponseURI: responseURI,
		SigningAlg: oid4vci.ES256, EncValuesSupported: []oid4vci.JWEEnc{oid4vci.A128GCM},
		VPFormatsSupported: verifier.MdocFormatSupport(),
	}, verifier.Dependencies{Signer: key, Random: rand.Reader})
}

func verifyResponse(v *verifier.Verifier, presented string, in inputs, roots *x509.CertPool, at time.Time) verdict {
	if in.ResponseMode != "dc_api.jwt" {
		return verdict{NotRun: "a redirect-flow Verifier's client_id is derived from its own certificate"}
	}
	query, err := in.query()
	if err != nil {
		return refused("query", err, nil)
	}
	pub, _, err := encryptionKey(in.EncryptionJWK)
	if err != nil {
		return refused("response encryption key", err, nil)
	}
	// VerifyResponse reads only the public half of ResponseEncryptionKey (its RFC 7638 thumbprint).
	_, err = v.VerifyResponse(context.Background(), verifier.VerifyResponseRequest{
		Query:                 query,
		Response:              verifier.ParsedResponse{VPToken: map[string][]string{"mdoc": {presented}}},
		ExpectedNonce:         in.Nonce,
		Now:                   func() time.Time { return at },
		MdocIssuerKeys:        verifier.X5ChainIssuerKeyResolver{Roots: roots},
		AnyIssuerForAnyType:   true,
		NoStatusCheck:         true,
		ResponseEncryptionKey: &ecdsa.PrivateKey{PublicKey: *pub},
		Origin:                in.Origin,
		ExpectedOrigins:       []string{in.Origin},
	})
	if err != nil {
		return verdict{Outcome: "refused", Error: err.Error()}
	}
	return verdict{Outcome: "accepted"}
}

type line struct {
	Name           string  `json:"name"`
	Variant        string  `json:"variant"`
	ResponseMode   string  `json:"response_mode"`
	At             string  `json:"at"`
	Roots          int     `json:"roots"`
	ResponseSHA256 string  `json:"response_sha256"`
	Composed       verdict `json:"composed"`
	VerifyResponse verdict `json:"verify_response"`
	Diagnostic     verdict `json:"diagnostic_without_document_signer_checks"`
}

func run(v *verifier.Verifier, name, variant, presented string, in inputs, anchors []string, atText string) (line, error) {
	at, err := time.Parse(time.RFC3339, atText)
	if err != nil {
		return line{}, err
	}
	roots := x509.NewCertPool()
	n := 0
	for _, pem := range anchors {
		if !roots.AppendCertsFromPEM([]byte(pem)) {
			return line{}, fmt.Errorf("%s: a trust anchor does not parse", name)
		}
		n++
	}
	raw, err := base64.RawURLEncoding.DecodeString(presented)
	if err != nil {
		return line{}, fmt.Errorf("%s: response is not base64url: %w", name, err)
	}
	sum := sha256.Sum256(raw)
	return line{
		Name: name, Variant: variant, ResponseMode: in.ResponseMode, At: atText, Roots: n,
		ResponseSHA256: hex.EncodeToString(sum[:]),
		Composed:       composed(raw, in, roots, at, true),
		VerifyResponse: verifyResponse(v, presented, in, roots, at),
		Diagnostic:     composed(raw, in, roots, at, false),
	}, nil
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: witness mdoc-vectors.json")
		os.Exit(2)
	}
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var c corpus
	if err := json.Unmarshal(data, &c); err != nil || len(c.Vectors) == 0 {
		fmt.Fprintln(os.Stderr, "no cases:", err)
		os.Exit(1)
	}
	v, err := newVerifier()
	if err != nil {
		fmt.Fprintln(os.Stderr, "verifier:", err)
		os.Exit(1)
	}
	count := 0
	emit := func(l line, err error) {
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		out, _ := json.Marshal(l)
		fmt.Println("WITNESS " + string(out))
		count++
	}
	for _, vec := range c.Vectors {
		emit(run(v, vec.ID, "case", vec.Response, vec.Inputs, vec.Anchors, vec.At))
		if vec.Repaired != nil {
			emit(run(v, vec.ID, "repaired", vec.Repaired.Response, vec.Repaired.Inputs, vec.Anchors, vec.At))
		}
	}
	fmt.Printf("WITNESS-DONE %d\n", count)
}
