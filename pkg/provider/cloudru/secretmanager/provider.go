/*
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package secretmanager

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"time"

	authV1 "github.com/cloudru-tech/iam-sdk/api/auth/v1"
	smsV1 "github.com/cloudru-tech/secret-manager-sdk/api/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	esv1beta1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1beta1"
	"github.com/external-secrets/external-secrets/pkg/provider/cloudru/secretmanager/adapter"
	"github.com/external-secrets/external-secrets/pkg/utils"
)

func init() {
	esv1beta1.Register(NewProvider(), &esv1beta1.SecretStoreProvider{CloudruSM: &esv1beta1.CloudruSMProvider{}})
}

var _ esv1beta1.Provider = &Provider{}
var _ esv1beta1.SecretsClient = &Client{}

// Provider is a secrets provider for Cloud.ru Secret Manager.
type Provider struct {
	mu sync.Mutex

	// clients is a map of Cloud.ru Secret Manager clients.
	// Is used to cache the clients to avoid multiple connections,
	// and excess token retrieving with same credentials.
	clients map[string]*adapter.APIClient
}

// NewProvider creates a new Cloud.ru Secret Manager Provider.
func NewProvider() *Provider {
	return &Provider{
		clients: make(map[string]*adapter.APIClient),
	}
}

// NewClient constructs a Cloud.ru Secret Manager Provider.
func (p *Provider) NewClient(
	ctx context.Context,
	store esv1beta1.GenericStore,
	kube kclient.Client,
	namespace string,
) (esv1beta1.SecretsClient, error) {
	if _, err := p.ValidateStore(store); err != nil {
		return nil, fmt.Errorf("invalid store: %w", err)
	}

	csmRef := store.GetSpec().Provider.CloudruSM
	storeKind := store.GetObjectKind().GroupVersionKind().Kind
	cr := NewKubeCredentialsResolver(kube, namespace, storeKind, csmRef.Auth.SecretRef)

	client, err := p.getClient(ctx, csmRef, cr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect cloud.ru services: %w", err)
	}

	return &Client{
		apiClient:         client,
		productInstanceID: csmRef.ProductInstanceID,
	}, nil
}

func (p *Provider) getClient(ctx context.Context, ref *esv1beta1.CloudruSMProvider, cr adapter.CredentialsResolver) (*adapter.APIClient, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	discoveryURL, tokenURL, smURL, err := provideEndpoints(ref)
	if err != nil {
		return nil, fmt.Errorf("parse endpoint URLs: %w", err)
	}

	creds, err := cr.Resolve(ctx)
	if err != nil {
		return nil, fmt.Errorf("resolve API credentials: %w", err)
	}

	connStack := fmt.Sprintf("%s,%s+%s", discoveryURL, creds.KeyID, creds.Secret)
	client, ok := p.clients[connStack]
	if ok {
		return client, nil
	}
	iamConn, err := grpc.NewClient(tokenURL,
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS13})),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                time.Second * 30,
			Timeout:             time.Second * 5,
			PermitWithoutStream: false,
		}),
		grpc.WithUserAgent("external-secrets"),
	)
	if err != nil {
		return nil, fmt.Errorf("initialize cloud.ru IAM gRPC client: initiate connection: %w", err)
	}

	smsConn, err := grpc.NewClient(smURL,
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS13})),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                time.Second * 30,
			Timeout:             time.Second * 5,
			PermitWithoutStream: false,
		}),
		grpc.WithUserAgent("external-secrets"),
	)
	if err != nil {
		return nil, fmt.Errorf("initialize cloud.ru Secret Manager gRPC client: initiate connection: %w", err)
	}

	iamClient := authV1.NewAuthServiceClient(iamConn)
	smsClient := smsV1.NewSecretManagerServiceClient(smsConn)
	client = adapter.NewAPIClient(cr, iamClient, smsClient)

	p.clients[connStack] = client
	return client, nil
}

// ValidateStore validates the store specification.
func (p *Provider) ValidateStore(store esv1beta1.GenericStore) (admission.Warnings, error) {
	if store == nil {
		return nil, errors.New("store is not provided")
	}
	spec := store.GetSpec()
	if spec == nil || spec.Provider == nil || spec.Provider.CloudruSM == nil {
		return nil, errors.New("csm spec is not provided")
	}

	csmProvider := spec.Provider.CloudruSM
	switch {
	case csmProvider.Auth.SecretRef == nil:
		return nil, errors.New("invalid spec: auth.secretRef is required")
	case csmProvider.ProductInstanceID == "":
		return nil, errors.New("invalid spec: productInstanceID is required")
	}
	if _, err := uuid.Parse(csmProvider.ProductInstanceID); err != nil {
		return nil, fmt.Errorf("invalid spec: productInstanceID is invalid UUID: %w", err)
	}

	ref := csmProvider.Auth.SecretRef
	err := utils.ValidateReferentSecretSelector(store, ref.AccessKeyID)
	if err != nil {
		return nil, fmt.Errorf("invalid spec: auth.secretRef.accessKeyID: %w", err)
	}

	err = utils.ValidateReferentSecretSelector(store, ref.AccessKeySecret)
	if err != nil {
		return nil, fmt.Errorf("invalid spec: auth.secretRef.accessKeySecret: %w", err)
	}

	return nil, nil
}

// Capabilities returns the provider Capabilities (ReadOnly).
func (p *Provider) Capabilities() esv1beta1.SecretStoreCapabilities {
	return esv1beta1.SecretStoreReadOnly
}

func provideEndpoints(ref *esv1beta1.CloudruSMProvider) (discoveryURL, tokenURL, smURL string, err error) {
	endpointsURL := EndpointsURI
	if ref.DiscoveryURL != "" {
		var u *url.URL
		u, err = url.Parse(ref.DiscoveryURL)
		if err != nil {
			return "", "", "", fmt.Errorf("invalid discovery URL: %w", err)
		}
		if u.Scheme != "https" && u.Scheme != "http" {
			return "", "", "", errors.New("invalid scheme in discovery URL, expecting the http or https")
		}

		endpointsURL = ref.DiscoveryURL
	}

	// using the discovery URL to get the endpoints.
	var endpoints *EndpointsResponse
	endpoints, err = GetEndpoints(endpointsURL)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to get the cloud.ru endpoints: %w", err)
	}

	smEndpoint := endpoints.Get("secret-manager")
	if smEndpoint == nil {
		return "", "", "", errors.New("secret-manager API is not available")
	}

	iamEndpoint := endpoints.Get("iam")
	if iamEndpoint == nil {
		return "", "", "", errors.New("iam API is not available")
	}

	return endpointsURL, iamEndpoint.Address, smEndpoint.Address, nil
}
