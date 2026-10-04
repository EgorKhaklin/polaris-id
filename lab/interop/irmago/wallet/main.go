// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Egor Khaklin and the Polaris contributors

// Command wallet is a wallet built on irmago (github.com/privacybydesign/irmago), the Go library
// under the Yivi wallet app. irmago does the work; this program wires it, as the app does, and
// plays the user who consents.
//
//	wallet init    DIR                             make the holder key
//	wallet store   DIR CREDENTIAL ISSUER_CA        verify and store a credential bound to it
//	wallet present DIR VERIFIER_CA TLS_CERT URI    answer one OpenID4VP request
//
// DIR holds irmago's holder storage: its SD-JWT VC and holder key tables in a SQLite database,
// and its encrypted file store, where the trust anchors are installed. The app keeps the same
// tables in SQLCipher; irmago opens them on any GORM dialector, and a pure Go one keeps this
// build free of C.
package main

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/ncruces/go-sqlite3/gormlite"
	"github.com/sirupsen/logrus"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/credentials/proofs"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
	"github.com/privacybydesign/irmago/eudi/metadata"
	"github.com/privacybydesign/irmago/eudi/openid4vp"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/privacybydesign/irmago/eudi/openid4vp/eudi_sdjwt_dcql"
	"github.com/privacybydesign/irmago/eudi/sdjwt"
	"github.com/privacybydesign/irmago/eudi/services"
	"github.com/privacybydesign/irmago/eudi/storage"
	"github.com/privacybydesign/irmago/eudi/storage/db"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/privacybydesign/irmago/eudi/storage/filesystem"
)

// The issuer the holder key's proof of possession is addressed to: the `iss` of the credential
// ../waltid/issue_sdjwt_vc.py mints.
const issuerURL = "https://issuer.polaris.test"

func main() {
	// irmago's log, which the app points at its own logger. Failures reach the handler as well.
	eudi.Logger = logrus.New()
	if os.Getenv("WALLET_VERBOSE") == "" {
		eudi.Logger.SetOutput(io.Discard)
	}
	var err error
	switch {
	case len(os.Args) == 3 && os.Args[1] == "init":
		err = initWallet(os.Args[2])
	case len(os.Args) == 5 && os.Args[1] == "store":
		err = store(os.Args[2], os.Args[3], os.Args[4])
	case len(os.Args) == 6 && os.Args[1] == "present":
		err = present(os.Args[2], os.Args[3], os.Args[4], os.Args[5])
	default:
		err = errors.New("usage: wallet init DIR | store DIR CREDENTIAL ISSUER_CA | present DIR VERIFIER_CA TLS_CERT URI")
	}
	if err != nil {
		fmt.Println("ERROR", err)
		os.Exit(1)
	}
}

type wallet struct {
	storage storage.Storage
	conf    *eudi.Configuration
	locale  *clientmodels.CurrentLocale
}

func open(dir string) (*wallet, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	key, err := storageKey(filepath.Join(dir, "storage.key"))
	if err != nil {
		return nil, err
	}
	st, err := storage.NewStorageWithDialector(
		gormlite.Open(filepath.Join(dir, storage.DbFilename)),
		filesystem.NewFileSystemStorage(key, filepath.Join(dir, "files")))
	if err != nil {
		return nil, err
	}
	conf, err := eudi.NewConfiguration(st)
	if err != nil {
		return nil, err
	}
	return &wallet{storage: st, conf: conf, locale: clientmodels.NewCurrentLocale("en")}, nil
}

// storageKey is the key the file store encrypts under, made on first use.
func storageKey(path string) ([32]byte, error) {
	var key [32]byte
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		if _, err := rand.Read(key[:]); err != nil {
			return key, err
		}
		return key, os.WriteFile(path, key[:], 0o600)
	}
	if err != nil {
		return key, err
	}
	if len(b) != len(key) {
		return key, fmt.Errorf("%s is not a 32-byte key", path)
	}
	copy(key[:], b)
	return key, nil
}

// initWallet makes the holder key as irmago's OpenID4VCI client makes one: its key service
// generates and stores the key and returns a proof of possession. The issuer reads the key from
// that proof, so the proof's header is what goes into holder.json.
func initWallet(dir string) error {
	w, err := open(dir)
	if err != nil {
		return err
	}
	defer w.storage.Close()

	builder := proofs.NewJwtProofBuilder("polaris-irmago-wallet", issuerURL, jwa.ES256(), nil,
		eudi_jwt.NewSystemClock(), proofs.CryptographicBindingMethod_JWK)
	ids, proofList, err := services.NewHolderBindingKeyService(w.storage.Db()).CreateKeyPairsWithProofs(1, builder)
	if err != nil {
		return err
	}
	msg, err := jws.Parse([]byte(proofList[0]))
	if err != nil {
		return err
	}
	key, ok := msg.Signatures()[0].ProtectedHeaders().JWK()
	if !ok {
		return errors.New("the proof of possession carries no jwk")
	}
	if _, err := jws.Verify([]byte(proofList[0]), jws.WithKey(jwa.ES256(), key)); err != nil {
		return fmt.Errorf("the proof of possession does not verify under its own key: %v", err)
	}
	pub, err := json.Marshal(key)
	if err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(dir, "holder.json"), map[string]json.RawMessage{"holder_jwk": pub}); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(dir, "keys.json"), ids); err != nil {
		return err
	}
	fmt.Println("HOLDER KEY", string(pub))
	return nil
}

// store installs ISSUER_CA as an issuer trust anchor and hands the credential to irmago's SD-JWT
// VC format, as its OpenID4VCI client does with a credential it received: the holder verifier
// checks the issuer's signature, the x5c chain to an installed anchor, that `iss` is in the
// certificate, and the disclosures; the store checks that `cnf` is the key from init.
func store(dir, credentialPath, issuerCA string) error {
	w, err := open(dir)
	if err != nil {
		return err
	}
	defer w.storage.Close()

	anchor, err := os.ReadFile(issuerCA)
	if err != nil {
		return err
	}
	if err := w.conf.Issuers.InstallCertificate(anchor); err != nil {
		return err
	}
	if err := w.conf.Reload(); err != nil {
		return err
	}
	var ids []models.PublicHolderBindingKey
	if err := readJSON(filepath.Join(dir, "keys.json"), &ids); err != nil {
		return err
	}
	raw, err := os.ReadFile(credentialPath)
	if err != nil {
		return err
	}

	holderVerifier := sdjwtvc.NewHolderVerificationProcessor(sdjwtvc.SdJwtVcVerificationContext{
		X509VerificationContext: &w.conf.Issuers,
		Clock:                   eudi_jwt.NewSystemClock(),
		JwtVerifier:             sdjwt.NewJwxJwtVerifier(),
	})
	format := services.NewCredentialFormats(w.conf, holderVerifier, w.storage.Db(), w.storage.FileSystem(),
		nil, w.locale)[models.CredentialFormatSdJwtVc]
	parsed, err := format.Parser.ParseAndVerify(strings.TrimSpace(string(raw)), issuerURL, true)
	if err != nil {
		return err
	}
	if err := format.Store.Store([]*services.ParsedCredential{parsed}, "pid",
		metadata.CredentialIssuerMetadata{CredentialIssuer: issuerURL}, true, ids); err != nil {
		return err
	}
	fmt.Println("STORED", parsed.VerifiableCredentialType, "from", parsed.IssuerIdentifier)
	return nil
}

// present answers one OpenID4VP request with irmago's client, wired as the app wires it: the
// SD-JWT VC query handler over the holder storage, signing the key binding JWT with the stored
// holder key, and the app's verifier validator (x509_san_dns and x509_hash against the verifier
// trust anchors, or a DID).
func present(dir, verifierCA, tlsCert, uri string) error {
	// irmago sends every request through one shared client on Go's default transport, so that
	// transport is told to trust the verifier's listener certificate, and nothing else.
	listener, err := os.ReadFile(tlsCert)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(listener) {
		return fmt.Errorf("no certificate in %s", tlsCert)
	}
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}

	w, err := open(dir)
	if err != nil {
		return err
	}
	defer w.storage.Close()

	// The verifier trust anchor this run installs is VERIFIER_CA alone. irmago's own pinned
	// anchors (the Yivi and Ver.iD roots) stay, as in the app.
	anchor, err := os.ReadFile(verifierCA)
	if err != nil {
		return err
	}
	if err := w.storage.FileSystem().Verifiers().CertificateManager().RemoveAll(); err != nil {
		return err
	}
	if err := w.conf.Verifiers.InstallCertificate(anchor); err != nil {
		return err
	}
	if err := w.conf.Reload(); err != nil {
		return err
	}

	query := eudi_sdjwt_dcql.NewSdJwtVcDcqlHandler(w.storage, db.NewSdJwtVcStore(w.storage.Db()), nil, nil,
		sdjwt.NewDefaultKeyBinder(services.NewHolderBindingKeyService(w.storage.Db())), w.locale, nil)
	validator := openid4vp.NewCompositeVerifierValidator(
		openid4vp.NewRequestorCertificateStoreVerifierValidator(&w.conf.Verifiers, &openid4vp.DefaultQueryValidatorFactory{}),
		openid4vp.NewDidVerifierValidator(false))
	client, err := openid4vp.NewClient(w.conf, []dcql.DcqlCredentialQueryHandler{query}, validator, w.locale)
	if err != nil {
		return err
	}

	s := &session{done: make(chan string, 1)}
	client.NewSession(uri, s)
	select {
	case result := <-s.done:
		fmt.Println(result)
	case <-time.After(60 * time.Second):
		fmt.Println("TIMEOUT no answer from the session in 60 s")
	}
	return nil
}

// session is the user: it is asked once, after irmago has fetched and verified the request and
// matched the query against the stored credentials, and it consents to what it is shown.
type session struct {
	asked atomic.Bool
	done  chan string
}

func (s *session) Failure(err *clientmodels.SessionError) {
	stage := "REQUEST REFUSED"
	if s.asked.Load() {
		stage = "DISPATCH FAILED"
	}
	s.done <- stage + " " + err.WrappedError
}

func (s *session) Cancelled() { s.done <- "CANCELLED nothing was disclosed" }

func (s *session) Success(result string, _ []clientmodels.LogCredential) {
	s.done <- "DISPATCHED " + result
}

func (s *session) DeliverDcApiResponse(string) {}

func (s *session) RequestVerificationPermission(plan *clientmodels.DisclosurePlan,
	requestor *clientmodels.TrustedParty, queryIds []dcql.ChoiceQueryIds, callback openid4vp.PermissionHandler) {
	s.asked.Store(true)
	fmt.Printf("ASKED by %q (%s, verified=%v)\n", requestor.Name, requestor.Id, requestor.Verified)
	selections, ok := consent(plan, queryIds)
	callback(ok, selections)
}

// consent picks, for each choice in the plan, the first credential the wallet holds and every
// claim path the plan shows for it, and hands the paths back verbatim, as the app's screen does
// (clientmodels.Attribute: "The UI sends this path back verbatim").
func consent(plan *clientmodels.DisclosurePlan, queryIds []dcql.ChoiceQueryIds) ([]dcql.DisclosureSelection, bool) {
	var selections []dcql.DisclosureSelection
	for i, choice := range plan.DisclosureChoicesOverview {
		if len(choice.OwnedOptions) == 0 {
			if choice.Optional {
				continue
			}
			fmt.Println("NOTHING HELD for a required choice")
			return nil, false
		}
		var ids dcql.ChoiceQueryIds
		if i < len(queryIds) {
			ids = queryIds[i]
		}
		for _, cred := range choice.OwnedOptions[0].Credentials {
			var paths [][]any
			for _, attribute := range cred.Attributes {
				if len(attribute.ClaimPath) > 0 {
					paths = append(paths, attribute.ClaimPath)
				}
			}
			fmt.Printf("CONSENT %s: %v\n", cred.CredentialId, paths)
			selections = append(selections, dcql.DisclosureSelection{
				QueryId:        ids.QueryIdFor(cred.Hash, paths),
				CredentialHash: cred.Hash,
				ClaimPaths:     paths,
			})
		}
	}
	return selections, len(selections) > 0
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}
