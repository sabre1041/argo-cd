package commands

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"

	"github.com/spf13/cobra"

	"path/filepath"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	log "github.com/sirupsen/logrus"

	"github.com/argoproj/argo-cd/v2/common"
	argocdclient "github.com/argoproj/argo-cd/v2/pkg/apiclient"
	"github.com/argoproj/argo-cd/v2/util/errors"
	"github.com/opencontainers/go-digest"
	credentials "github.com/oras-project/oras-credentials-go"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/file"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
)

type OciOptions struct {
	ContentSource                  string
	Directory                      string
	RegistryReference              string
	InsecureSkipServerVerification bool
	TlsClientCertPath              string
	TlsClientCertKeyPath           string
}

const (
	OciTarArchiveExtension  = ".tar.gz"
	DockerMediaTypeManifest = "application/vnd.docker.distribution.manifest.v2+json"
)

// NewOCICommand returns a new instance of an `argocd oci` command
func NewOCICommand(clientOpts *argocdclient.ClientOptions) *cobra.Command {
	var command = &cobra.Command{
		Use:   "oci",
		Short: "Manage OCI resources and registries",
		Run: func(c *cobra.Command, args []string) {
			c.HelpFunc()(c, args)
			os.Exit(1)
		},
		Example: ``,
	}
	command.AddCommand(NewOCIPushCommand(clientOpts))
	command.AddCommand(NewOCIPullCommand(clientOpts))
	return command
}

func NewOCIPullCommand(clientOpts *argocdclient.ClientOptions) *cobra.Command {
	var (
		ociOpts OciOptions
	)
	var command = &cobra.Command{
		Use:   "pull SOURCE",
		Short: "Pull an OCI artifact from a registry to the local machine",
		PreRun: func(c *cobra.Command, args []string) {

			if len(args) != 1 {
				c.HelpFunc()(c, args)
				os.Exit(1)
			}

			ociOpts.RegistryReference = args[0]

		},

		Run: func(c *cobra.Command, args []string) {
			if len(args) != 1 {
				c.HelpFunc()(c, args)
				os.Exit(1)
			}

			ctx := c.Context()

			store, err := file.New(ociOpts.Directory)
			errors.CheckError(err)
			defer store.Close()

			repository, err := newRepository(&ociOpts, clientOpts)
			errors.CheckError(err)

			var printed sync.Map

			copyOpts := oras.DefaultCopyOptions
			copyOpts.FindSuccessors = func(ctx context.Context, fetcher content.Fetcher, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
				statusFetcher := content.FetcherFunc(func(ctx context.Context, target ocispec.Descriptor) (fetched io.ReadCloser, fetchErr error) {
					if _, ok := printed.LoadOrStore(target.Digest.String(), true); ok {
						return fetcher.Fetch(ctx, target)
					}
					log.Infof("Downloading %s", shortDigest(desc))
					rc, err := fetcher.Fetch(ctx, target)
					if err != nil {
						return nil, err
					}
					defer func() {
						if fetchErr != nil {
							rc.Close()
						}
					}()
					log.Infof("Processing %s", shortDigest(desc))
					return rc, nil
				})

				nodes, _, config, err := Successors(ctx, statusFetcher, desc)
				errors.CheckError(err)

				// Verify appropriate MediaTypes Present
				if desc.MediaType == ocispec.MediaTypeImageManifest || desc.MediaType == DockerMediaTypeManifest {
					if config.MediaType != common.OCIArtifactConfigMediaType {
						errors.Fatalf(1, "Invalid Config MediaType '%s'. Expected MediaType '%s'", config.MediaType, common.OCIArtifactConfigMediaType)
					}
				}

				return nodes, nil

			}
			copyOpts.OnCopySkipped = func(ctx context.Context, desc ocispec.Descriptor) error {
				log.Infof("Skipped %s", shortDigest(desc))
				return nil
			}
			copyOpts.PreCopy = func(ctx context.Context, desc ocispec.Descriptor) error {
				if _, ok := printed.LoadOrStore(desc.Digest.String(), true); ok {
					return nil
				}
				log.Infof("Downloading %s", shortDigest(desc))
				return nil
			}
			// Copy
			desc, err := oras.Copy(ctx, repository, repository.Reference.String(), store, repository.Reference.String(), copyOpts)
			errors.CheckError(err)

			fmt.Println("Pulled", repository.Reference.String())
			fmt.Println("Digest:", desc.Digest)

		},
	}
	command.Flags().StringVarP(&ociOpts.Directory, "directory", "d", ".", "output directory")
	command.Flags().StringVar(&ociOpts.TlsClientCertPath, "tls-client-cert-path", "", "path to the TLS client cert (must be PEM format)")
	command.Flags().StringVar(&ociOpts.TlsClientCertKeyPath, "tls-client-cert-key-path", "", "path to the TLS client cert's key path (must be PEM format)")
	command.Flags().BoolVar(&ociOpts.InsecureSkipServerVerification, "insecure-skip-server-verification", false, "disables server certificate and host key checks")

	return command
}

// NewOCIPushCommand lists all configured public keys from the server
func NewOCIPushCommand(clientOpts *argocdclient.ClientOptions) *cobra.Command {
	var (
		ociOpts OciOptions
	)
	var command = &cobra.Command{
		Use:   "push SOURCE DESTINATION",
		Short: "Push source as an OCI artifact to a remote registry",
		PreRun: func(c *cobra.Command, args []string) {

			if len(args) != 2 {
				c.HelpFunc()(c, args)
				os.Exit(1)
			}

			ociOpts.ContentSource = args[0]
			ociOpts.RegistryReference = args[1]

			ociOpts.ContentSource = filepath.Clean(ociOpts.ContentSource)
			if !filepath.IsAbs(ociOpts.ContentSource) {
				ociOpts.ContentSource = filepath.ToSlash(ociOpts.ContentSource)
			}

			if contentSourceStat, err := os.Stat(ociOpts.ContentSource); err != nil {
				errors.Fatalf(1, "Provided content path not found: %s", ociOpts.ContentSource)
			} else {
				if !contentSourceStat.IsDir() {
					if ociOpts.ContentSource[len(ociOpts.ContentSource)-len(OciTarArchiveExtension):] != OciTarArchiveExtension {
						errors.Fatalf(1, "Provided content source '%s' must be a directory or a %s formatted file", ociOpts.ContentSource, OciTarArchiveExtension)
					}
				}
			}

		},
		Run: func(c *cobra.Command, args []string) {

			ctx := c.Context()

			tmpDir, err := os.MkdirTemp("", "argocd-oci")
			errors.CheckError(err)
			defer os.RemoveAll(tmpDir)

			store, err := file.New(tmpDir)
			errors.CheckError(err)
			defer store.Close()

			// Setup Config
			configContent := []byte("{}")
			configDesc := content.NewDescriptorFromBytes(common.OCIArtifactConfigMediaType, configContent)

			desc, err := store.Add(ctx, ".", common.OCIArtifactContentMediaType, ociOpts.ContentSource)
			errors.CheckError(err)

			// TODO: Remove default annotations. Needed for oras CLI integration for testing
			// desc.Annotations = map[string]string{}
			repository, err := newRepository(&ociOpts, clientOpts)
			errors.CheckError(err)

			err = store.Push(ctx, configDesc, bytes.NewReader([]byte("{}")))
			errors.CheckError(err)

			packOpts := oras.PackOptions{
				ConfigDescriptor:  &configDesc,
				PackImageManifest: true,
			}

			root, err := oras.Pack(ctx, store, "", []ocispec.Descriptor{desc}, packOpts)
			errors.CheckError(err)
			err = store.Tag(ctx, root, root.Digest.String())
			errors.CheckError(err)

			copyOpts := oras.DefaultCopyOptions
			copyOpts.PreCopy = func(ctx context.Context, desc ocispec.Descriptor) error {
				log.Infof("Uploading %s", shortDigest(desc))
				return nil
			}

			copyOpts.OnCopySkipped = func(ctx context.Context, desc ocispec.Descriptor) error {
				log.Infof("Skipped %s", shortDigest(desc))
				return nil
			}

			copyOpts.PostCopy = func(ctx context.Context, desc ocispec.Descriptor) error {
				log.Infof("Uploaded %s", shortDigest(desc))
				return nil
			}
			_, err = oras.Copy(ctx, store, root.Digest.String(), repository, repository.Reference.Reference, copyOpts)
			errors.CheckError(err)

			log.Infof("Pushed %s", repository.Reference.String())
			log.Infof("Digest: %s", root.Digest)

		},
	}
	command.Flags().StringVar(&ociOpts.TlsClientCertPath, "tls-client-cert-path", "", "path to the TLS client cert (must be PEM format)")
	command.Flags().StringVar(&ociOpts.TlsClientCertKeyPath, "tls-client-cert-key-path", "", "path to the TLS client cert's key path (must be PEM format)")
	command.Flags().BoolVar(&ociOpts.InsecureSkipServerVerification, "insecure-skip-server-verification", false, "disables server certificate and host key checks")

	return command
}

func shortDigest(desc ocispec.Descriptor) (digestString string) {
	digestString = desc.Digest.String()
	if err := desc.Digest.Validate(); err == nil {
		if algo := desc.Digest.Algorithm(); algo == digest.SHA256 {
			digestString = desc.Digest.Encoded()[:12]
		}
	}
	return digestString
}

func newRepository(ociOpts *OciOptions, clientOpts *argocdclient.ClientOptions) (*remote.Repository, error) {

	repository, err := remote.NewRepository(ociOpts.RegistryReference)

	if err != nil {
		return nil, err
	}

	if repository.Reference.Reference == "" {
		repository.Reference.Reference = "latest"
	}

	// Set up Client
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// TODO: Check for/setup Certificates
	transport.TLSClientConfig.InsecureSkipVerify = ociOpts.InsecureSkipServerVerification

	//Plain HTTP support
	repository.PlainHTTP = clientOpts.PlainText

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
