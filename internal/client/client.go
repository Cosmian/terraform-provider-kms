// Package client provides an HTTP client for the Cosmian KMS REST API.
// It handles authentication (Bearer token or mTLS) and constructs
// KMIP-over-JSON requests as described in the KMS OpenAPI spec.
package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
)

// Config holds the provider-level connection settings.
type Config struct {
	ServerURL   string
	APIKey      string
	TLSCertFile string
	TLSKeyFile  string
	CACertFile  string
}

// Client wraps an *http.Client pre-configured for the Cosmian KMS.
type Client struct {
	cfg        Config
	httpClient *http.Client
}

// New creates a Client from the given Config.
// Returns an error if TLS files are specified but cannot be loaded.
func New(cfg Config) (*Client, error) {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	// mTLS client certificate
	if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("loading mTLS key pair: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	// Custom CA bundle
	if cfg.CACertFile != "" {
		pool := x509.NewCertPool()
		pem, err := os.ReadFile(cfg.CACertFile) // #nosec G304 — path from trusted provider config
		if err != nil {
			return nil, fmt.Errorf("reading CA cert file: %w", err)
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no valid PEM certificates found in %s", cfg.CACertFile)
		}
		tlsCfg.RootCAs = pool
	}

	transport := &http.Transport{TLSClientConfig: tlsCfg}
	return &Client{
		cfg:        cfg,
		httpClient: &http.Client{Transport: transport},
	}, nil
}

// doKMIP sends a single KMIP operation node (TTLV-as-JSON) to POST /kmip/2_1
// and returns the parsed response node.
func (c *Client) doKMIP(ctx context.Context, req any) (map[string]any, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshalling KMIP request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.ServerURL+"/kmip/2_1", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating HTTP request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if c.cfg.APIKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("executing KMIP request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		var errBody map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&errBody)
		return nil, fmt.Errorf("KMS returned HTTP %d: %v", resp.StatusCode, errBody)
	}

	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding KMIP response: %w", err)
	}
	return result, nil
}

// doREST sends a JSON request to a non-KMIP KMS REST endpoint (e.g. /access/grant).
func (c *Client) doREST(ctx context.Context, method, path string, payload any) (map[string]any, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshalling REST request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, method, c.cfg.ServerURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating HTTP request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if c.cfg.APIKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("executing REST request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		var errBody map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&errBody)
		return nil, fmt.Errorf("KMS returned HTTP %d: %v", resp.StatusCode, errBody)
	}

	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding REST response: %w", err)
	}
	return result, nil
}

// extractTextString walks a TTLV node list looking for the first child with the
// given tag and returns its TextString value.
func extractTextString(nodes []any, tag string) (string, error) {
	for _, n := range nodes {
		node, ok := n.(map[string]any)
		if !ok {
			continue
		}
		if node["tag"] == tag {
			v, ok := node["value"].(string)
			if !ok {
				return "", fmt.Errorf("tag %q value is not a string", tag)
			}
			return v, nil
		}
	}
	return "", fmt.Errorf("tag %q not found in response", tag)
}

// responseNodes returns the "value" array of a TTLV response node.
func responseNodes(resp map[string]any) ([]any, error) {
	v, ok := resp["value"]
	if !ok {
		return nil, fmt.Errorf("response has no 'value' field")
	}
	nodes, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("response 'value' is not an array")
	}
	return nodes, nil
}
