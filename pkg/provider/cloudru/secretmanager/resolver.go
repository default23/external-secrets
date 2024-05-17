package secretmanager

import (
	"context"
	"fmt"

	kclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/external-secrets/external-secrets/apis/externalsecrets/v1beta1"
	"github.com/external-secrets/external-secrets/pkg/provider/cloudru/secretmanager/adapter"
	"github.com/external-secrets/external-secrets/pkg/utils/resolvers"
)

// KubeCredentialsResolver resolves the credentials from the Kubernetes secret.
type KubeCredentialsResolver struct {
	ref  *v1beta1.CSMAuthSecretRef
	kube kclient.Client

	namespace string
	storeKind string
}

// NewKubeCredentialsResolver creates a new KubeCredentialsResolver.
func NewKubeCredentialsResolver(kube kclient.Client, namespace, storeKind string, ref *v1beta1.CSMAuthSecretRef) *KubeCredentialsResolver {
	return &KubeCredentialsResolver{
		ref:       ref,
		kube:      kube,
		namespace: namespace,
		storeKind: storeKind,
	}
}

// Resolve resolves the credentials from the Kubernetes secret.
func (kcr *KubeCredentialsResolver) Resolve(ctx context.Context) (*adapter.Credentials, error) {
	keyID, err := resolvers.SecretKeyRef(ctx, kcr.kube, kcr.storeKind, kcr.namespace, &kcr.ref.AccessKeyID)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve accessKeyID: %w", err)
	}

	secret, err := resolvers.SecretKeyRef(ctx, kcr.kube, kcr.storeKind, kcr.namespace, &kcr.ref.AccessKeySecret)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve accessKeySecret")
	}

	creds, err := adapter.NewCredentials(keyID, secret)
	if err != nil {
		return nil, fmt.Errorf("failed to get auth credentials: %w", err)
	}

	return creds, nil
}
