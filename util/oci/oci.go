package oci

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	credentials "github.com/oras-project/oras-credentials-go"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
)

var (
	DockerMediaTypeManifest = "application/vnd.docker.distribution.manifest.v2+json"
)

func ShortDigest(desc ocispec.Descriptor) (digestString string) {
	digestString = desc.Digest.String()
	if err := desc.Digest.Validate(); err == nil {
		if algo := desc.Digest.Algorithm(); algo == digest.SHA256 {
			digestString = desc.Digest.Encoded()[:12]
		}
	}
	return digestString
}

func NewRepository(reference string, insecure bool, plaintext bool) (*remote.Repository, error) {

	repository, err := remote.NewRepository(reference)

	if err != nil {
		return nil, err
	}

	if repository.Reference.Reference == "" {
		repository.Reference.Reference = "latest"
	}

	// Set up Client
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// TODO: Check for/setup Certificates
	transport.TLSClientConfig.InsecureSkipVerify = insecure

	//Plain HTTP support
	repository.PlainHTTP = plaintext

	credentialStore, err := credentials.NewStoreFromDocker(credentials.StoreOptions{AllowPlaintextPut: true})
	if err != nil {
		return nil, err
	}

	//Setup Client
	authClient := &auth.Client{
		Credential: credentials.Credential(credentialStore),
		Cache:      auth.NewCache(),
		Client: &http.Client{
			Transport: transport,
		},
	}
	repository.Client = authClient

	return repository, nil

}

func Successors(ctx context.Context, fetcher content.Fetcher, node ocispec.Descriptor) (nodes []ocispec.Descriptor, subject, config *ocispec.Descriptor, err error) {
	switch node.MediaType {
	case DockerMediaTypeManifest, ocispec.MediaTypeImageManifest:
		var fetched []byte
		fetched, err = content.FetchAll(ctx, fetcher, node)
		if err != nil {
			return
		}
		var manifest ocispec.Manifest
		if err = json.Unmarshal(fetched, &manifest); err != nil {
			return
		}
		nodes = manifest.Layers
		subject = manifest.Subject
		config = &manifest.Config
	default:
		nodes, err = content.Successors(ctx, fetcher, node)
	}
	return
}
