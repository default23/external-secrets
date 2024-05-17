package csm

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	esv1beta1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1beta1"
	"github.com/external-secrets/external-secrets/pkg/utils"
)

// Provider is a secrets provider for Cloud.ru Secret Manager.
type Provider struct {
}

var _ esv1beta1.Provider = &Provider{}
var _ esv1beta1.SecretsClient = &Client{}

func init() {
	esv1beta1.Register(&Provider{}, &esv1beta1.SecretStoreProvider{
		CSM: &esv1beta1.CSMProvider{},
	})
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

	endpoints, err := GetEndpoints()
	if err != nil {
		return nil, fmt.Errorf("failed to get cloud.ru endpoints: %w", err)
	}

	smEndpoint := endpoints.Get("secret-manager")
	if smEndpoint == nil {
		return nil, errors.New("secret-manager API is not available")
	}

	// retrieving the Auth Credentials from k8s secret.
	csmRef := store.GetSpec().Provider.CSM
	storeKind := store.GetObjectKind().GroupVersionKind().Kind

	apiClient, err := NewAPIClient(ctx, smEndpoint.Address, NewKubeCredentialsResolver(kube, namespace, storeKind, csmRef.Auth.SecretRef))
	if err != nil {
		return nil, fmt.Errorf("failed to create API client: %w", err)
	}

	return &Client{
		apiClient:         apiClient,
		productInstanceID: csmRef.ProductInstanceID,
	}, nil
}

// ValidateStore validates the store specification.
func (p *Provider) ValidateStore(store esv1beta1.GenericStore) (admission.Warnings, error) {
	if store == nil {
		return nil, errors.New("store is not provided")
	}
	spec := store.GetSpec()
	if spec == nil || spec.Provider == nil || spec.Provider.CSM == nil {
		return nil, errors.New("csm spec is not provided")
	}

	csmProvider := spec.Provider.CSM
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
