package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"golang.org/x/sync/singleflight"
)

func getClientAssertionProvider(clientAssertion string, audience string) (clientAssertionProviderFn, error) {
	clientAssertionLC := strings.ToLower(clientAssertion)
	switch {
	// If there's no client assertion, return
	case clientAssertionLC == "":
		return nil, nil

	// Azure with user-assigned managed identity
	case strings.HasPrefix(clientAssertionLC, "azuremanagedidentity="):
		fic, err := azidentity.NewManagedIdentityCredential(&azidentity.ManagedIdentityCredentialOptions{
			ID: azidentity.ClientID(clientAssertion[len("azuremanagedidentity="):]),
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create Azure managed Identity credential object: %w", err)
		}
		return azureClientAssertionProvider(fic), nil

	// Azure with system-assigned managed identity
	case clientAssertionLC == "azuremanagedidentity":
		fic, err := azidentity.NewManagedIdentityCredential(nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create Azure Managed Identity credential object: %w", err)
		}
		return azureClientAssertionProvider(fic), nil

	// Azure Workload Identity
	case clientAssertionLC == "azureworkloadidentity":
		fic, err := azidentity.NewWorkloadIdentityCredential(nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create Azure Workload Identity credential object: %w", err)
		}
		return azureClientAssertionProvider(fic), nil

	// tsiam
	case strings.HasPrefix(clientAssertionLC, "tsiam="):
		fn, err := tsiamClientAssertionProvider(clientAssertion[len("tsiam="):], audience)
		if err != nil {
			return nil, fmt.Errorf("failed to create tsiam client assertion provider: %w", err)
		}
		return fn, nil

	// Invalid value supplied
	default:
		return nil, fmt.Errorf("invalid value for configuration option 'clientAssertion': '%s'", clientAssertion)
	}
}

func azureClientAssertionProvider(fic azcore.TokenCredential) clientAssertionProviderFn {
	return func(ctx context.Context) (string, error) {
		// Get the client assertion
		clientAssertion, err := fic.GetToken(ctx, policy.TokenRequestOptions{
			// This is a constant value
			Scopes: []string{"api://AzureADTokenExchange"},
		})
		if err != nil {
			return "", fmt.Errorf("failed to obtain client assertion: %w", err)
		}

		return clientAssertion.Token, nil
	}
}

func tsiamClientAssertionProvider(endpoint string, audience string) (clientAssertionProviderFn, error) {
	if audience == "" {
		return nil, errors.New("audience is empty")
	}

	// Parse the URL
	u, err := url.Parse(strings.TrimSuffix(endpoint, "/") + "/token")
	if err != nil {
		return nil, fmt.Errorf("failed to parse endpoint URL: %w", err)
	}
	q := u.Query()
	q.Set("resource", audience)
	u.RawQuery = q.Encode()
	reqUrl := u.String()

	client := http.DefaultClient

	type tokenResponse struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   string `json:"expires_in"`
	}

	// Token cache state
	var (
		cacheMu     sync.Mutex
		cachedToken string
		cacheExpiry time.Time
		sfGroup     singleflight.Group
	)

	// Create the function
	fn := func(parentCtx context.Context) (string, error) {
		// Return the cached token if it is still valid
		cacheMu.Lock()
		if cachedToken != "" && time.Now().Before(cacheExpiry) {
			defer cacheMu.Unlock()
			return cachedToken, nil
		}
		cacheMu.Unlock()

		// Condense concurrent refresh requests into a single HTTP call
		res, err, _ := sfGroup.Do("", func() (any, error) {
			// Re-check the cache: another goroutine may have already refreshed it while we were waiting to enter the singleflight group
			cacheMu.Lock()
			if cachedToken != "" && time.Now().Before(cacheExpiry) {
				defer cacheMu.Unlock()
				return cachedToken, nil
			}
			cacheMu.Unlock()

			// Use a background context so that a single caller's cancellation does not abort a shared in-flight request that other callers are also waiting on
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			req, rErr := http.NewRequestWithContext(ctx, http.MethodPost, reqUrl, nil)
			if rErr != nil {
				return "", fmt.Errorf("failed to create request for URL '%s': %w", reqUrl, rErr)
			}
			req.Header.Set("X-Tsiam", "1")

			resp, rErr := client.Do(req)
			if rErr != nil {
				return "", fmt.Errorf("error requesting token: %w", rErr)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				return "", fmt.Errorf("error requesting token: response status is not OK: %d", resp.StatusCode)
			}

			var tokenResp tokenResponse
			rErr = json.NewDecoder(resp.Body).Decode(&tokenResp)
			if rErr != nil {
				return "", fmt.Errorf("error parsing response: %w", rErr)
			}

			// Cache the token only when the effective TTL (expiry minus 1m) is positive
			if tokenResp.ExpiresIn != "" {
				expiresInSec, rErr := strconv.ParseInt(tokenResp.ExpiresIn, 10, 64)
				if rErr == nil {
					effectiveExpiry := time.Now().Add(time.Duration(expiresInSec)*time.Second - time.Minute)
					if effectiveExpiry.After(time.Now()) {
						cacheMu.Lock()
						cachedToken = tokenResp.AccessToken
						cacheExpiry = effectiveExpiry
						cacheMu.Unlock()
					}
				}
			}

			return tokenResp.AccessToken, nil
		})
		if err != nil {
			return "", err
		}

		return res.(string), nil //nolint:forcetypeassert
	}

	return fn, nil
}
