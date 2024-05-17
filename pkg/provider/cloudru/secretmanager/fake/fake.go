package fake

import (
	"context"

	smsV1 "github.com/cloudru-tech/secret-manager-sdk/api/v1"

	"github.com/external-secrets/external-secrets/pkg/provider/cloudru/secretmanager/adapter"
)

type MockSecretProvider struct {
	ListSecretsFns  []func() ([]*smsV1.Secret, error)
	AccessSecretFns []func() ([]byte, error)
}

func (m *MockSecretProvider) ListSecrets(_ context.Context, _ *adapter.ListSecretsRequest) ([]*smsV1.Secret, error) {
	fn := m.ListSecretsFns[0]
	if len(m.ListSecretsFns) > 1 {
		m.ListSecretsFns = m.ListSecretsFns[1:]
	} else {
		m.ListSecretsFns = nil
	}

	return fn()
}

func (m *MockSecretProvider) AccessSecretVersion(_ context.Context, _, _ string) ([]byte, error) {
	fn := m.AccessSecretFns[0]
	if len(m.AccessSecretFns) > 1 {
		m.AccessSecretFns = m.AccessSecretFns[1:]
	} else {
		m.AccessSecretFns = nil
	}
	return fn()
}

func (m *MockSecretProvider) MockListSecrets(list []*smsV1.Secret, err error) {
	m.ListSecretsFns = append(m.ListSecretsFns, func() ([]*smsV1.Secret, error) { return list, err })
}

func (m *MockSecretProvider) MockAccessSecretVersion(data []byte, err error) {
	m.AccessSecretFns = append(m.AccessSecretFns, func() ([]byte, error) { return data, err })
}

func (m *MockSecretProvider) Close() error { return nil }
