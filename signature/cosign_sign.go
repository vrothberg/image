package signature

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/url"
	"os"

	"github.com/containers/image/v5/docker/reference"
	"github.com/containers/image/v5/internal/useragent"
	"github.com/containers/image/v5/manifest"
	"github.com/containers/image/v5/types"
	goRegistryName "github.com/google/go-containerregistry/pkg/name"
	"github.com/opencontainers/go-digest"
	"github.com/pkg/errors"
	"github.com/sigstore/fulcio/pkg/api"
	fulcioAPI "github.com/sigstore/fulcio/pkg/api"
	"github.com/sigstore/sigstore/pkg/oauthflow"
	"github.com/sigstore/sigstore/pkg/signature"
	sigstoreSignature "github.com/sigstore/sigstore/pkg/signature"
	sigstoreOptions "github.com/sigstore/sigstore/pkg/signature/options"
	sigstorePayload "github.com/sigstore/sigstore/pkg/signature/payload"
	"github.com/theupdateframework/go-tuf/encrypted"
	"golang.org/x/term"
)

type CosignSignImageOptions struct {
	// InstanceDigest contains a digest of the specific manifest instance
	// to retrieve signatures for (when the primary manifest is a manifest
	// list); this never happens if the primary manifest is not a manifest
	// list (e.g. if the source never returns manifest lists).
	InstanceDigest *digest.Digest
	// FulcioURL allows for using a custom Fulcio server. By default, `CosignFulcioURL` is used.
	FulcioURL string
	// URL to a custom OIDC issuer. By default, `CosignOIDCIssuer` is used.
	OIDCIssuer string
	// Custom OIDC client. By default, `CosignOIDCClientID` is used.
	OIDCClientID string
	// Custom OIDC client secret.
	OIDCClientSecret string
	// RekorURL allows for using a custom Rekor server. By default, `CosignRekorURL` is used.
	RekorURL string
	// SignerVerifier can be used to sign and verify and image using a key pair.
	SignerVerifier sigstoreSignature.SignerVerifier

	// Internal fields
	sys *types.SystemContext
}

type CosignSignature struct {
	payload []byte
	// Annotations - see https://github.com/sigstore/cosign/blob/main/specs/SIGNATURE_SPEC.md
	certificate []byte // optional
	chain       []byte // optional
	signature   []byte // required
}

// Return the JSON marshaled payload of the signature.
func (c *CosignSignature) Payload() ([]byte, error) {
	return c.payload, nil
}

// Return the annotations of the signature.
func (c *CosignSignature) Annotations() (map[string]interface{}, error) {
	annotations := make(map[string]interface{})
	annotations[CosignAnnotationKeySignature] = c.signature
	annotations[CosignAnnotationKeyCertificate] = c.certificate
	annotations[CosignAnnotationKeyChain] = c.chain
	return annotations, nil
}

func CosignSignImage(ctx context.Context, source types.ImageSource, sys *types.SystemContext, options *CosignSignImageOptions) (*CosignSignature, error) {
	if options == nil {
		options = &CosignSignImageOptions{}
	}
	options.sys = sys

	manifestBytes, _, err := source.GetManifest(ctx, options.InstanceDigest)
	if err != nil {
		return nil, err
	}

	manifestDigest, err := manifest.Digest(manifestBytes)
	if err != nil {
		return nil, err
	}

	namedRef := source.Reference().DockerReference()
	if namedRef == nil {
		return nil, fmt.Errorf("no named reference for %s", source.Reference())
	}
	digestedRef, err := reference.WithDigest(namedRef, manifestDigest)
	if err != nil {
		return nil, err
	}

	payload, err := cosignPayload(ctx, digestedRef)
	if err != nil {
		return nil, err
	}

	signer, err := cosignKeylessSigner(ctx, options)
	if err != nil {
		return nil, err
	}

	signedManifest, err := signer.SignMessage(bytes.NewReader(payload), sigstoreOptions.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("signing payload: %v", err)
	}

	return &CosignSignature{payload: payload, signature: signedManifest, certificate: signer.Cert, chain: signer.Chain}, err
}

func cosignPayload(ctx context.Context, ref reference.Digested) ([]byte, error) {
	goRegistryDigest, err := goRegistryName.NewDigest(ref.String())
	if err != nil {
		return nil, fmt.Errorf("parsing refernce for payload: %v", err)
	}

	payload, err := (&sigstorePayload.Cosign{
		Image:       goRegistryDigest,
		Annotations: make(map[string]interface{}),
	}).MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("generting payload: %v", err)
	}

	return payload, nil
}

func newFulcioClient(fulcioURL string, sys *types.SystemContext) (fulcioAPI.Client, error) {
	if fulcioURL == "" {
		fulcioURL = CosignFulcioURL
	}
	fulcioServer, err := url.Parse(fulcioURL)
	if err != nil {
		return nil, fmt.Errorf("invalid fulcio URL: %v", err)
	}
	fClient := api.NewClient(fulcioServer, fulcioAPI.WithUserAgent(useragent.UserAgent(sys)))
	return fClient, nil
}

type keylessSigner struct {
	Cert  []byte
	Chain []byte
	SCT   []byte
	pub   *ecdsa.PublicKey
	*sigstoreSignature.ECDSASignerVerifier
}

// creates a signer using fulcio
func cosignKeylessSigner(ctx context.Context, options *CosignSignImageOptions) (*keylessSigner, error) {
	client, err := newFulcioClient(options.FulcioURL, options.sys)
	if err != nil {
		return nil, fmt.Errorf("creating Fulcio client: %v", err)
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating key: %v", err)
	}

	signer, err := sigstoreSignature.LoadECDSASignerVerifier(priv, crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("loading signer verifier: %v", err)
	}

	certResponse, err := cosignGetOIDCCertificate(ctx, priv, client, options)
	if err != nil {
		return nil, fmt.Errorf("getting OIDC certificate: %v", err)
	}

	return &keylessSigner{
		pub:                 &priv.PublicKey,
		ECDSASignerVerifier: signer,
		Cert:                certResponse.CertPEM,
		Chain:               certResponse.ChainPEM,
		SCT:                 certResponse.SCT,
	}, nil
}

func cosignGetOIDCCertificate(ctx context.Context, priv *ecdsa.PrivateKey, client fulcioAPI.Client, options *CosignSignImageOptions) (*fulcioAPI.CertificateResponse, error) {
	oidcIssuer := options.OIDCIssuer
	if oidcIssuer == "" {
		oidcIssuer = CosignOIDCIssuer
	}
	oidcClientID := options.OIDCClientID
	if oidcClientID == "" {
		oidcClientID = CosignOIDCClientID
	}

	var flow oauthflow.TokenGetter
	flow = oauthflow.DefaultIDTokenGetter
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		flow = oauthflow.NewDeviceFlowTokenGetter(oidcIssuer, oauthflow.SigstoreDeviceURL, oauthflow.SigstoreTokenURL)
	}

	tok, err := oauthflow.OIDConnect(oidcIssuer, oidcClientID, options.OIDCClientSecret, flow)
	if err != nil {
		return nil, fmt.Errorf("connect: %v", err)
	}

	// Sign the email address as part of the request
	h := sha256.Sum256([]byte(tok.Subject))
	proof, err := ecdsa.SignASN1(rand.Reader, priv, h[:])
	if err != nil {
		return nil, fmt.Errorf("sign ASN1: %v", err)
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, err
	}

	request := fulcioAPI.CertificateRequest{
		PublicKey: fulcioAPI.Key{
			Algorithm: "ecdsa",
			Content:   pubBytes,
		},
		SignedEmailAddress: proof,
	}
	certResponse, err := client.SigningCert(request, tok.RawString)
	if err != nil {
		return nil, fmt.Errorf("signing certificate: %v", err)
	}

	return certResponse, nil
}

type CosignLoadKeyOptions struct {
	Passphrase string
}

// CosignLoadKey loads the key at the specified path.
func CosignLoadKey(ctx context.Context, path string, options *CosignLoadKeyOptions) (sigstoreSignature.SignerVerifier, error) {
	if options == nil {
		options = &CosignLoadKeyOptions{}
	}

	f, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading keyfile: %v", err)
	}
	return cosignLoadPrivateKey(f, []byte(options.Passphrase))
}

const cosignPrivateKeyPemType = "ENCRYPTED COSIGN PRIVATE KEY"

func cosignLoadPrivateKey(key []byte, pass []byte) (sigstoreSignature.SignerVerifier, error) {
	// Decrypt first
	p, _ := pem.Decode(key)
	if p == nil {
		return nil, errors.New("invalid pem block")
	}
	if p.Type != cosignPrivateKeyPemType {
		return nil, fmt.Errorf("unsupported pem type: %s", p.Type)
	}

	x509Encoded, err := encrypted.Decrypt(p.Bytes, pass)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %v", err)
	}

	pk, err := x509.ParsePKCS8PrivateKey(x509Encoded)
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %v", err)
	}
	switch pk := pk.(type) {
	case *rsa.PrivateKey:
		return signature.LoadRSAPKCS1v15SignerVerifier(pk, crypto.SHA256)
	case *ecdsa.PrivateKey:
		return signature.LoadECDSASignerVerifier(pk, crypto.SHA256)
	default:
		return nil, fmt.Errorf("unsupported key type: %T", pk)
	}
}
