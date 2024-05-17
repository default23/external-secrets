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
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"

	api "github.com/external-secrets/external-secrets/pkg/provider/csm/api"
)

// CredentialsResolver returns the actual client credentials.
type CredentialsResolver interface {
	Resolve(ctx context.Context) (*Credentials, error)
}

// APIClient - Secret Manager Service Client
type APIClient struct {
	api.SecretManagerServiceClient
	ctx    context.Context
	cancel context.CancelFunc

	cc *grpc.ClientConn
	cr CredentialsResolver

	accessToken          string
	accessTokenExpiresIn time.Duration
}

// Credentials holds the keyID and secret for the CSM client.
type Credentials struct {
	KeyID  string
	Secret string
}

// NewCredentials creates a new Credentials object.
func NewCredentials(kid, secret string) (*Credentials, error) {
	if kid == "" || secret == "" {
		return nil, errors.New("keyID and secret must be provided")
	}

	return &Credentials{KeyID: kid, Secret: secret}, nil
}

// NewAPIClient creates a new grpc SecretManager client.
func NewAPIClient(ctx context.Context, addr string, cr CredentialsResolver) (*APIClient, error) {
	cancelCtx, cancel := context.WithCancel(ctx)

	c := &APIClient{
		cr:     cr,
		ctx:    cancelCtx,
		cancel: cancel,
	}
	authInterceptor, err := c.AuthInterceptor()
	if err != nil {
		return nil, fmt.Errorf("initialize csm gRPC client: %w", err)
	}

	c.cc, err = grpc.DialContext(cancelCtx, addr,
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS13})),
		grpc.WithUnaryInterceptor(authInterceptor),
	)
	if err != nil {
		return nil, fmt.Errorf("initialize csm gRPC client: initiate connection: %w", err)
	}
	c.SecretManagerServiceClient = api.NewSecretManagerServiceClient(c.cc)

	return c, nil
}

// Close closes API client.
func (c *APIClient) Close() error {
	c.cancel()
	if err := c.cc.Close(); err != nil {
		return fmt.Errorf("close csm gRPC connection: %w", err)
	}

	return nil
}

func (c *APIClient) AuthInterceptor() (grpc.UnaryClientInterceptor, error) {
	if err := c.scheduleRefreshToken(); err != nil {
		return nil, err
	}

	return func(
		ctx context.Context,
		method string,
		req, reply interface{},
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption,
	) error {
		md, ok := metadata.FromOutgoingContext(ctx)
		if !ok {
			md = metadata.New(map[string]string{})
		}
		md.Set("authorization", "Bearer "+c.accessToken)
		return invoker(metadata.NewOutgoingContext(ctx, md), method, req, reply, cc, opts...)
	}, nil
}

func (c *APIClient) scheduleRefreshToken() error {
	if err := c.refreshToken(); err != nil {
		return fmt.Errorf("initialize access token: %v", err)
	}

	go func() {
		// schedule token refresh before it expires in a minute
		wait := c.accessTokenExpiresIn - time.Minute
		ticker := time.NewTicker(wait)

		defer ticker.Stop()

		for {
			select {
			case <-c.ctx.Done():
				return
			case <-ticker.C:
				if err := c.refreshToken(); err != nil {
					log.Error(err, "failed to refresh the Access token")
					ticker.Reset(time.Second)
					continue
				}

				ticker.Reset(c.accessTokenExpiresIn - time.Minute)
			}
		}
	}()

	return nil
}

// TokenResponse represents the response from the token endpoint.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

func (c *APIClient) refreshToken() error {
	// X-WWW-Form-Urlencoded request
	creds, err := c.cr.Resolve(c.ctx)
	if err != nil {
		return fmt.Errorf("resolve credentials: %w", err)
	}

	data := url.Values{}
	data.Set("client_id", creds.KeyID)
	data.Set("client_secret", creds.Secret)
	data.Set("grant_type", "client_credentials")

	req, _ := http.NewRequest(http.MethodPost, "https://auth.iam.cloud.ru/auth/system/openid/token", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("refresh token: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		errResp := make(map[string]interface{})
		if err = json.NewDecoder(res.Body).Decode(&errResp); err != nil {
			return fmt.Errorf("refresh token failed with status %s", res.Status)
		}

		return fmt.Errorf("refresh token failed with status %s: %v", res.Status, errResp)
	}

	var tr TokenResponse
	if err = json.NewDecoder(res.Body).Decode(&tr); err != nil {
		return fmt.Errorf("decode token response: %w", err)
	}

	c.accessToken = tr.AccessToken
	c.accessTokenExpiresIn = time.Duration(tr.ExpiresIn) * time.Second

	return nil
}
