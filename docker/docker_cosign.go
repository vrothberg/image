package docker

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/containers/image/v5/docker/reference"
	internalblobinfocache "github.com/containers/image/v5/internal/blobinfocache"
	"github.com/containers/image/v5/internal/iolimits"
	"github.com/containers/image/v5/manifest"
	"github.com/containers/image/v5/pkg/blobinfocache"
	"github.com/containers/image/v5/signature"
	"github.com/containers/image/v5/types"
	goRegistryV1 "github.com/google/go-containerregistry/pkg/v1"
	digest "github.com/opencontainers/go-digest"
	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"github.com/sigstore/cosign/pkg/cosign/bundle"
	cosignOCI "github.com/sigstore/cosign/pkg/oci"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sirupsen/logrus"
)

// cosignReference returns the reference of the signature for the specified
// reference and digest.
func cosignReference(ref reference.Named, d digest.Digest) (reference.Named, error) {
	// Reparsing with the name only so we drop possible digests etc.
	raw := fmt.Sprintf("%s:%s-%s.sig", ref.Name(), d.Algorithm(), d.Encoded())
	return reference.ParseNamed(raw)
}

// Implements cosignOCI.Signatures.
type cosignSignatures struct {
	cosignOCI.Signatures // FIXME: includes goregistry
	hash                 goRegistryV1.Hash
	signatures           []cosignOCI.Signature
}

// Implements cosignOCI.Signatures.
func (cs cosignSignatures) Get() ([]cosignOCI.Signature, error) {
	return cs.signatures, nil
}

// Implements cosignOCI.Signatures.
func (cs cosignSignatures) Digest() (goRegistryV1.Hash, error) {
	return cs.hash, nil
}

// TODO: doc comment
// Return nil if no cosign signatures are found.
func (s *dockerImageSource) GetCosignSignatures(ctx context.Context, sys *types.SystemContext, options *signature.GetCosignSignaturesOptions) (cosignOCI.Signatures, error) {
	if options == nil {
		options = &signature.GetCosignSignaturesOptions{}
	}

	sourceManifestDigest, err := s.manifestDigest(ctx, options.InstanceDigest)
	if err != nil {
		return nil, err
	}

	// Get the associated signature reference of the source image.
	signatureReference, err := cosignReference(s.logicalRef.ref, sourceManifestDigest)
	if err != nil {
		return nil, err
	}

	signatureImageSource, err := newImageSource(ctx, sys, dockerReference{ref: signatureReference})
	if err != nil {
		if strings.Contains(err.Error(), "manifest unknown") {
			logrus.Debugf("manifest unknown: assuming %s has no signatures on registry", s.logicalRef)
			return nil, nil
		}
		return nil, err
	}

	// Get the manifest, type and digest of the signature image.
	signatureManifestBytes, signatureManifestType, err := signatureImageSource.GetManifest(ctx, options.InstanceDigest)
	if err != nil {
		return nil, err
	}

	// The signature image *must* be an OCI one.
	if signatureManifestType != imgspecv1.MediaTypeImageManifest {
		return nil, fmt.Errorf("unsupported sigstore image: expected %q, received %q", imgspecv1.MediaTypeImageManifest, signatureManifestType)
	}

	// Parse the raw signature manifest into a proper manifest.
	signatureOCIManifest, err := manifest.OCI1FromManifest(signatureManifestBytes)
	if err != nil {
		return nil, err
	}

	// Extract the signatures.
	layerInfos := signatureOCIManifest.LayerInfos()
	signatures := make([]cosignOCI.Signature, len(layerInfos))
	for i := range layerInfos {
		signatures[i] = newCosignLayer(ctx, signatureImageSource, layerInfos[i])
	}

	signatureImageDigest, err := manifest.Digest(signatureManifestBytes)
	if err != nil {
		return nil, err
	}

	hash, err := goRegistryV1.NewHash(signatureImageDigest.String())
	if err != nil {
		return nil, err
	}

	return cosignSignatures{signatures: signatures, hash: hash}, nil
}

func newCosignLayer(ctx context.Context, image *dockerImageSource, info manifest.LayerInfo) *cosignLayer {
	return &cosignLayer{ctx: ctx, image: image, info: info}
}

// Implements cosignOCI.Signature
type cosignLayer struct {
	goRegistryV1.Layer // FIXME: includes goregistry
	ctx                context.Context
	image              *dockerImageSource
	info               manifest.LayerInfo
}

// Implements cosignOCI.Signature
func (c *cosignLayer) Payload() ([]byte, error) {
	// FIXME: the system context (and contect.Context) should probably be
	// part of the interface here.  The system context must be passed to
	// the cache constuctor.
	blob, _, err := c.image.GetBlob(c.ctx, c.info.BlobInfo, internalblobinfocache.FromBlobInfoCache(blobinfocache.DefaultCache(nil)))
	if err != nil {
		return nil, err
	}
	defer blob.Close()

	payload, err := iolimits.ReadAtMost(blob, iolimits.MaxSignatureBodySize)
	if err != nil {
		return nil, err
	}
	return payload, nil
}

// Implements cosignOCI.Signature
func (c *cosignLayer) Annotations() (map[string]string, error) {
	return c.info.Annotations, nil
}

// Implements cosignOCI.Signature
func (c *cosignLayer) Base64Signature() (string, error) {
	b64sig, ok := c.info.Annotations[signature.CosignAnnotationKeySignature]
	if !ok {
		return "", fmt.Errorf("signature layer %s is missing %q annotation: %v", c.info.Digest, signature.CosignAnnotationKeySignature, c.info.Annotations)
	}
	return b64sig, nil
}

// Implements cosignOCI.Signature
func (c *cosignLayer) Cert() (*x509.Certificate, error) {
	certPEM := c.info.Annotations[signature.CosignAnnotationKeyCertificate]
	if certPEM == "" {
		return nil, nil
	}
	certs, err := cryptoutils.LoadCertificatesFromPEM(strings.NewReader(certPEM))
	if err != nil {
		return nil, err
	}
	return certs[0], nil
}

// Implements cosignOCI.Signature
func (c *cosignLayer) Chain() ([]*x509.Certificate, error) {
	chainPEM := c.info.Annotations[signature.CosignAnnotationKeyChain]
	if chainPEM == "" {
		return nil, nil
	}
	certs, err := cryptoutils.LoadCertificatesFromPEM(strings.NewReader(chainPEM))
	if err != nil {
		return nil, err
	}
	return certs, nil
}

// Implements cosignOCI.Signature
func (c *cosignLayer) Bundle() (*bundle.RekorBundle, error) {
	val := c.info.Annotations[signature.CosignAnnotationKeyBundle]
	if val == "" {
		return nil, nil
	}
	var b bundle.RekorBundle
	if err := json.Unmarshal([]byte(val), &b); err != nil {
		return nil, errors.Wrap(err, "unmarshaling bundle")
	}
	return &b, nil
}
