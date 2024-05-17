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

package csm

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/tidwall/gjson"
	corev1 "k8s.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"

	esv1beta1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1beta1"
	"github.com/external-secrets/external-secrets/pkg/find"
	api "github.com/external-secrets/external-secrets/pkg/provider/csm/api"
	"github.com/external-secrets/external-secrets/pkg/utils"
)

const (
	// listBatchSize is the maximum number of secrets to list in a single request.
	listBatchSize = 100
)

var log = ctrl.Log.WithName("provider").WithName("csm").WithName("secret-manager")

// Client is a client for the Cloud.ru Secret Manager.
type Client struct {
	apiClient *APIClient

	productInstanceID string
}

// GetSecret gets the secret by the remote reference.
func (c *Client) GetSecret(ctx context.Context, ref esv1beta1.ExternalSecretDataRemoteRef) ([]byte, error) {
	secret, err := c.accessSecret(ctx, ref.Key, ref.Version)
	if err != nil {
		return nil, err
	}

	if ref.Property == "" {
		return secret.GetData().GetValue(), nil
	}

	value := string(secret.GetData().GetValue())
	result := gjson.Parse(value).Get(ref.Property)
	if !result.Exists() {
		return nil, fmt.Errorf("the requested property %s does not exist in secret", ref.Property)
	}

	return []byte(result.Str), nil
}

func (c *Client) GetSecretMap(ctx context.Context, ref esv1beta1.ExternalSecretDataRemoteRef) (map[string][]byte, error) {
	secret, err := c.accessSecret(ctx, ref.Key, ref.Version)
	if err != nil {
		return nil, err
	}

	secretMap := make(map[string]json.RawMessage)
	if err = json.Unmarshal(secret.GetData().GetValue(), &secretMap); err != nil {
		return nil, fmt.Errorf("failed to json Unmarshal secret: %w", err)
	}

	out := make(map[string][]byte)
	for k, v := range secretMap {
		out[k] = v
	}

	return out, nil
}

// GetAllSecrets gets all secrets by the remote reference.
func (c *Client) GetAllSecrets(ctx context.Context, ref esv1beta1.ExternalSecretFind) (map[string][]byte, error) {
	if len(ref.Tags) == 0 && ref.Name == nil {
		return nil, fmt.Errorf("at least one of the following fields must be set: tags, name")
	}

	var totalSecrets []*api.Secret
	offset := 0
	for {
		resp, err := c.apiClient.ListSecrets(ctx, &api.ListSecretsRequest{
			Page: &api.Page{
				Limit:  listBatchSize,
				Offset: int32(offset),
			},
			ParentId: c.productInstanceID,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to list secrets: %w", err)
		}
		if len(resp.GetSecrets()) == 0 {
			break
		}

		secrets := filter(resp.Secrets, secretMatchLabels(ref.Tags))
		if ref.Name != nil {
			secrets, err = c.filterByName(ref, secrets)
			if err != nil {
				return nil, fmt.Errorf("failed to filter secrets by name: %w", err)
			}
		}

		totalSecrets = append(totalSecrets, secrets...)
		offset += len(resp.GetSecrets())
	}

	out := make(map[string][]byte)
	for _, s := range totalSecrets {
		secret, err := c.GetSecretMap(ctx, esv1beta1.ExternalSecretDataRemoteRef{Key: s.GetId()})
		if err != nil {
			return nil, fmt.Errorf("failed to get the secret by id: %s", s.GetId())
		}

		for k, v := range secret {
			out[k] = v
		}
	}

	return utils.ConvertKeys(ref.ConversionStrategy, out)
}

func (c *Client) filterByName(ref esv1beta1.ExternalSecretFind, list []*api.Secret) ([]*api.Secret, error) {
	nameMatcher, err := find.New(*ref.Name)
	if err != nil {
		return nil, fmt.Errorf("invalid name regex %q: %w", ref.Name.RegExp, err)
	}

	var out []*api.Secret
	for _, s := range list {
		if nameMatcher.MatchName(s.GetName()) {
			out = append(out, s)
		}
	}

	return out, nil
}

func (c *Client) accessSecret(ctx context.Context, id, version string) (*api.SecretPayload, error) {
	if version == "" {
		version = "latest"
	}

	req := &api.AccessSecretVersionRequest{
		SecretId:        id,
		SecretVersionId: version,
	}
	secret, err := c.apiClient.AccessSecretVersion(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to get the secret by id: %s", id)
	}

	return secret, nil
}

func (c *Client) PushSecret(ctx context.Context, secret *corev1.Secret, data esv1beta1.PushSecretData) error {
	return fmt.Errorf("push secret is not supported")
}

func (c *Client) DeleteSecret(ctx context.Context, remoteRef esv1beta1.PushSecretRemoteRef) error {
	return fmt.Errorf("delete secret is not supported")
}

func (c *Client) SecretExists(ctx context.Context, remoteRef esv1beta1.PushSecretRemoteRef) (bool, error) {
	return false, fmt.Errorf("secret exists is not supported")
}

// Validate validates the client.
func (c *Client) Validate() (esv1beta1.ValidationResult, error) {
	return esv1beta1.ValidationResultReady, nil
}

// Close closes the client.
func (c *Client) Close(_ context.Context) error { return c.apiClient.Close() }
