package signature

import (
	"context"
	"crypto"
	"fmt"
	"os"
	"strings"

	"github.com/containers/image/v5/internal/useragent"
	"github.com/containers/image/v5/types"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/opencontainers/go-digest"
	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/pkcs11key"
	"github.com/sigstore/cosign/pkg/oci"
	cosignOCI "github.com/sigstore/cosign/pkg/oci"
	rekor "github.com/sigstore/rekor/pkg/client"
	rekorClient "github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	sigstoreSignature "github.com/sigstore/sigstore/pkg/signature"
)

const (
	// FIXME: all of that should really be exported by cosign (but isn't yet).
	CosignAnnotationKeySignature   = "dev.cosignproject.cosign/signature"
	CosignAnnotationKeyCertificate = "dev.sigstore.cosign/certificate"
	CosignAnnotationKeyChain       = "dev.sigstore.cosign/chain"
	CosignAnnotationKeyBundle      = "dev.sigstore.cosign/bundle"
	CosignAnnotationKeyTimestamp   = "dev.sigstore.cosign/timestamp"
	CosignLayerMediaType           = "application/vnd.dev.cosign.simplesigning.v1+json"
	CosignOIDCIssuer               = "https://oauth2.sigstore.dev/auth"
	CosignOIDCClientID             = "sigstore"

	// Default URL of the Fulcio server.
	CosignFulcioURL = "https://v1.fulcio.sigstore.dev"

	// Default URL of the Rekor server.
	CosignRekorURL = "https://rekor.sigstore.dev"
)

type GetCosignSignaturesOptions struct {
	// InstanceDigest contains a digest of the specific manifest instance
	// to retrieve signatures for (when the primary manifest is a manifest
	// list); this never happens if the primary manifest is not a manifest
	// list (e.g. if the source never returns manifest lists).
	InstanceDigest *digest.Digest
}

type CosignImageSource interface {
	types.ImageSource
	GetCosignSignatures(ctx context.Context, sys *types.SystemContext, options *GetCosignSignaturesOptions) (cosignOCI.Signatures, error)
}

type CosignVerifyImageOptions struct {
	// InstanceDigest contains a digest of the specific manifest instance
	// to retrieve signatures for (when the primary manifest is a manifest
	// list); this never happens if the primary manifest is not a manifest
	// list (e.g. if the source never returns manifest lists).
	InstanceDigest *digest.Digest

	// Verifier can be used to verify the image signatures (e.g., via a
	// public key).
	Verifier sigstoreSignature.Verifier

	// RekorURL allows for using a custom Rekor server.  By default,
	// `CosignRekorURL` is used.
	RekorURL string
}

// newRekorClient creates a new rekort client.  If rekorURL is empty,
// CosignRekorURL is used.
func newRekorClient(rekorURL string, sys *types.SystemContext) (*rekorClient.Rekor, error) {
	if rekorURL == "" {
		rekorURL = CosignRekorURL
	}

	rekorClient, err := rekor.GetRekorClient(rekorURL, rekor.WithUserAgent(useragent.UserAgent(sys)))
	if err != nil {
		return nil, err
	}
	return rekorClient, nil
}

func CosignVerifyImage(ctx context.Context, source types.ImageSource, sys *types.SystemContext, options *CosignVerifyImageOptions) (bool, error) {
	if options == nil {
		options = &CosignVerifyImageOptions{}
	}

	cosignSource, ok := source.(CosignImageSource)
	if !ok {
		return false, fmt.Errorf("%s does not support cosign signing", source.Reference().Transport().Name())
	}

	signatures, err := cosignSource.GetCosignSignatures(ctx, sys, &GetCosignSignaturesOptions{InstanceDigest: options.InstanceDigest})
	if err != nil {
		return false, err
	}

	rekorClient, err := newRekorClient(options.RekorURL, sys)
	if err != nil {
		return false, fmt.Errorf("creating rekor client: %v", err)
	}

	if options.Verifier != nil {
		if pkcs11Key, ok := options.Verifier.(*pkcs11key.Key); ok {
			defer pkcs11Key.Close()
		}
	}

	cosignVerifyOptions := &cosign.CheckOpts{
		RekorClient: rekorClient,
		RootCerts:   fulcio.GetRoots(),
		SigVerifier: options.Verifier,
	}

	hash, err := signatures.Digest()
	if err != nil {
		return false, err
	}

	_, verified, err := cosignVerifySignatures(ctx, signatures, hash, cosignVerifyOptions)
	if err != nil {
		return false, err
	}

	return verified, nil
}

func cosignVerifySignatures(ctx context.Context, sigs oci.Signatures, h v1.Hash, co *cosign.CheckOpts) (checkedSignatures []oci.Signature, bundleVerified bool, err error) {
	sl, err := sigs.Get()
	if err != nil {
		return nil, false, err
	}

	validationErrs := []string{}

	for _, sig := range sl {
		verified, err := cosign.VerifyImageSignature(ctx, sig, h, co)
		bundleVerified = bundleVerified || verified
		if err != nil {
			validationErrs = append(validationErrs, err.Error())
			continue
		}

		// Phew, we made it.
		checkedSignatures = append(checkedSignatures, sig)
	}
	if len(checkedSignatures) == 0 {
		return nil, false, fmt.Errorf("no matching signatures:\n%s", strings.Join(validationErrs, "\n "))
	}
	return checkedSignatures, bundleVerified, nil
}

// CosignKeyVerifier creates a verifier for the specified path pointing to a public key.
func CosignKeyVerifier(path string) (sigstoreSignature.Verifier, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// PEM encoded file.
	pubKey, err := cryptoutils.UnmarshalPEMToPublicKey(raw)
	if err != nil {
		return nil, fmt.Errorf("pem to public key: %v", err)
	}

	return sigstoreSignature.LoadVerifier(pubKey, crypto.SHA256)
}
