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
	"errors"
	"testing"

	smsV1 "github.com/cloudru-tech/secret-manager-sdk/api/v1"
	"github.com/google/uuid"
	tassert "github.com/stretchr/testify/assert"

	esv1beta1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1beta1"
	"github.com/external-secrets/external-secrets/pkg/provider/cloudru/secretmanager/fake"
)

func TestClient_GetSecret(t *testing.T) {
	tests := []struct {
		name        string
		ref         esv1beta1.ExternalSecretDataRemoteRef
		setup       func(mock *fake.MockSecretProvider)
		wantPayload []byte
		wantErr     error
	}{
		{
			name: "success",
			ref: esv1beta1.ExternalSecretDataRemoteRef{
				Key:     uuid.NewString(),
				Version: "1",
			},
			setup: func(mock *fake.MockSecretProvider) {
				mock.MockAccessSecretVersion([]byte("secret"), nil)
			},
			wantPayload: []byte("secret"),
			wantErr:     nil,
		},
		{
			name: "success_named_secret",
			ref: esv1beta1.ExternalSecretDataRemoteRef{
				Key:     "very_secret",
				Version: "1",
			},
			setup: func(mock *fake.MockSecretProvider) {
				// before it should find the secret by the name.
				mock.MockListSecrets([]*smsV1.Secret{
					{
						Id:   "50000000-4000-3000-2000-100000000001",
						Name: "very_secret",
					},
				}, nil)
				mock.MockAccessSecretVersion([]byte("secret"), nil)
			},
			wantPayload: []byte("secret"),
			wantErr:     nil,
		},
		{
			name: "success_multikv",
			ref: esv1beta1.ExternalSecretDataRemoteRef{
				Key:      uuid.NewString(),
				Version:  "1",
				Property: "another.secret",
			},
			setup: func(mock *fake.MockSecretProvider) {
				mock.MockAccessSecretVersion([]byte(`{"some": "value", "another": {"secret": "another_value"}}`), nil)
			},
			wantPayload: []byte("another_value"),
			wantErr:     nil,
		},
		{
			name: "error_access_secret",
			ref: esv1beta1.ExternalSecretDataRemoteRef{
				Key:     uuid.NewString(),
				Version: "1",
			},
			setup: func(mock *fake.MockSecretProvider) {
				mock.MockAccessSecretVersion(nil, errors.New("secret id is invalid"))
			},
			wantPayload: nil,
			wantErr:     errors.New("secret id is invalid"),
		},
		{
			name: "error_access_named_secret",
			ref: esv1beta1.ExternalSecretDataRemoteRef{
				Key:     "very_secret",
				Version: "1",
			},
			setup: func(mock *fake.MockSecretProvider) {
				mock.MockListSecrets(nil, errors.New("internal server error"))
			},
			wantPayload: nil,
			wantErr:     errors.New("list secrets by name 'very_secret': internal server error"),
		},
		{
			name: "error_access_named_secret:not_found",
			ref: esv1beta1.ExternalSecretDataRemoteRef{
				Key:     "very_secret",
				Version: "1",
			},
			setup: func(mock *fake.MockSecretProvider) {
				mock.MockListSecrets(nil, nil)
			},
			wantPayload: nil,
			wantErr:     errors.New("secret with name 'very_secret' not found"),
		},
		{
			name: "error_multikv:invalid_json",
			ref: esv1beta1.ExternalSecretDataRemoteRef{
				Key:      "50000000-4000-3000-2000-100000000001",
				Version:  "1",
				Property: "some",
			},
			setup: func(mock *fake.MockSecretProvider) {
				mock.MockAccessSecretVersion([]byte(`"some": "value"`), nil)
			},
			wantPayload: nil,
			wantErr:     errors.New(`expecting the secret "50000000-4000-3000-2000-100000000001" in JSON format, could not access property "some"`),
		},
		{
			name: "error_multikv:not_found",
			ref: esv1beta1.ExternalSecretDataRemoteRef{
				Key:      "50000000-4000-3000-2000-100000000001",
				Version:  "1",
				Property: "unexpected",
			},
			setup: func(mock *fake.MockSecretProvider) {
				mock.MockAccessSecretVersion([]byte(`{"some": "value"}`), nil)
			},
			wantPayload: nil,
			wantErr:     errors.New(`the requested property "unexpected" does not exist in secret "50000000-4000-3000-2000-100000000001"`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &fake.MockSecretProvider{}
			tt.setup(mock)
			c := &Client{
				apiClient:         mock,
				productInstanceID: "123",
			}

			got, gotErr := c.GetSecret(context.Background(), tt.ref)

			tassert.Equal(t, tt.wantPayload, got)
			tassert.Equal(t, tt.wantErr, gotErr)
		})
	}
}

func TestClient_GetSecretMap(t *testing.T) {
	tests := []struct {
		name        string
		ref         esv1beta1.ExternalSecretDataRemoteRef
		setup       func(mock *fake.MockSecretProvider)
		wantPayload map[string][]byte
		wantErr     error
	}{
		{
			name: "success",
			ref: esv1beta1.ExternalSecretDataRemoteRef{
				Key:     "50000000-4000-3000-2000-100000000001",
				Version: "1",
			},
			setup: func(mock *fake.MockSecretProvider) {
				mock.MockAccessSecretVersion([]byte(`{"some": "value", "another": "value", "foo": {"bar": "baz"}}`), nil)
			},
			wantPayload: map[string][]byte{
				"some":    []byte("value"),
				"another": []byte("value"),
				"foo":     []byte(`{"bar": "baz"}`),
			},
			wantErr: nil,
		},
		{
			name: "error_access_secret",
			ref: esv1beta1.ExternalSecretDataRemoteRef{
				Key:     "50000000-4000-3000-2000-100000000001",
				Version: "1",
			},
			setup: func(mock *fake.MockSecretProvider) {
				mock.MockAccessSecretVersion(nil, errors.New("secret id is invalid"))
			},
			wantPayload: nil,
			wantErr:     errors.New("secret id is invalid"),
		},
		{
			name: "error_not_json",
			ref: esv1beta1.ExternalSecretDataRemoteRef{
				Key:     "50000000-4000-3000-2000-100000000001",
				Version: "1",
			},
			setup: func(mock *fake.MockSecretProvider) {
				mock.MockAccessSecretVersion([]byte(`top_secret`), nil)
			},
			wantPayload: nil,
			wantErr:     errors.New(`expecting the secret "50000000-4000-3000-2000-100000000001" in JSON format`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &fake.MockSecretProvider{}
			tt.setup(mock)
			c := &Client{
				apiClient:         mock,
				productInstanceID: "123",
			}

			got, gotErr := c.GetSecretMap(context.Background(), tt.ref)

			tassert.Equal(t, tt.wantErr, gotErr)
			tassert.Equal(t, len(tt.wantPayload), len(got))
			for k, v := range tt.wantPayload {
				tassert.Equal(t, v, got[k])
			}
		})
	}
}

func TestClient_GetAllSecrets(t *testing.T) {
	tests := []struct {
		name        string
		ref         esv1beta1.ExternalSecretFind
		setup       func(mock *fake.MockSecretProvider)
		wantPayload map[string][]byte
		wantErr     error
	}{
		{
			name: "success",
			ref: esv1beta1.ExternalSecretFind{
				Name: &esv1beta1.FindName{RegExp: "label.*"},
				Tags: map[string]string{
					"env": "prod",
				},
			},
			setup: func(mock *fake.MockSecretProvider) {
				mock.MockListSecrets([]*smsV1.Secret{
					{
						Id:   "50000000-4000-3000-2000-100000000001",
						Name: "secret1",
					},
					{
						Id:   "50000000-4000-3000-2000-100000000002",
						Name: "secret2",
					},
				}, nil)

				mock.MockListSecrets(nil, nil) // mock next call

				mock.MockAccessSecretVersion([]byte(`{"some": "value", "another": "value", "foo": {"bar": "baz"}}`), nil)
				mock.MockAccessSecretVersion([]byte(`{"second_secret": "prop_value"}`), nil)
			},
			wantPayload: map[string][]byte{
				"some":          []byte("value"),
				"another":       []byte("value"),
				"foo":           []byte(`{"bar": "baz"}`),
				"second_secret": []byte("prop_value"),
			},
			wantErr: nil,
		},
		{
			name:        "error_no_filters",
			ref:         esv1beta1.ExternalSecretFind{},
			setup:       func(mock *fake.MockSecretProvider) {},
			wantPayload: nil,
			wantErr:     errors.New("at least one of the following fields must be set: tags, name"),
		},
		{
			name: "error_list_secrets",
			ref: esv1beta1.ExternalSecretFind{
				Name: &esv1beta1.FindName{RegExp: "label.*"},
				Tags: map[string]string{
					"env": "prod",
				},
			},
			setup: func(mock *fake.MockSecretProvider) {
				mock.MockListSecrets(nil, errors.New("internal server error"))
			},
			wantPayload: nil,
			wantErr:     errors.New("failed to list secrets: internal server error"),
		},
		{
			name: "error_not_json",
			ref: esv1beta1.ExternalSecretFind{
				Name: &esv1beta1.FindName{RegExp: "label.*"},
				Tags: map[string]string{
					"env": "prod",
				},
			},
			setup: func(mock *fake.MockSecretProvider) {
				mock.MockListSecrets([]*smsV1.Secret{
					{
						Id:   "50000000-4000-3000-2000-100000000001",
						Name: "secret1",
					},
					{
						Id:   "50000000-4000-3000-2000-100000000002",
						Name: "secret2",
					},
				}, nil)
				mock.MockListSecrets(nil, nil) // mock next call

				mock.MockAccessSecretVersion([]byte(`{"some": "value", "another": "value", "foo": {"bar": "baz"}}`), nil)
				mock.MockAccessSecretVersion([]byte(`top_secret`), nil)
			},
			wantPayload: nil,
			wantErr:     errors.New(`expecting the secret "50000000-4000-3000-2000-100000000002" in JSON format`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &fake.MockSecretProvider{}
			tt.setup(mock)
			c := &Client{
				apiClient:         mock,
				productInstanceID: "123",
			}

			got, gotErr := c.GetAllSecrets(context.Background(), tt.ref)

			tassert.Equal(t, tt.wantErr, gotErr)
			tassert.Equal(t, len(tt.wantPayload), len(got))
			for k, v := range tt.wantPayload {
				tassert.Equal(t, v, got[k])
			}
		})
	}
}
