// Package client — KMIP high-level operations used by Terraform resources.
package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// SymmetricKeyParams defines the attributes for a KMIP symmetric key.
type SymmetricKeyParams struct {
	Algorithm     string   // e.g. "AES"
	KeyLengthBits int      // e.g. 256
	Name          string   // object name (stored as a KMIP Name attribute)
	Tags          []string // arbitrary string tags
	UsageMask     int      // default: 524 (Encrypt|Decrypt|WrapKey)
}

// KeyPairParams defines the attributes for a KMIP key pair.
type KeyPairParams struct {
	Algorithm     string // e.g. "RSA", "EC"
	KeyLengthBits int    // e.g. 4096 for RSA, 256 for EC (curve size)
	Name          string
}

// AccessRightParams maps to the KMS /access/grant and /access/revoke payloads.
type AccessRightParams struct {
	ObjectUID      string
	UserID         string
	OperationTypes []string // e.g. ["Get", "Decrypt"]
}

// CreateSymmetricKey creates a symmetric key via KMIP 2.1 Create and returns its UID.
func (c *Client) CreateSymmetricKey(ctx context.Context, p SymmetricKeyParams) (string, error) {
	if p.UsageMask == 0 {
		p.UsageMask = 12 // Encrypt | Decrypt
	}

	// KMIP 2.1: attributes go directly inside an "Attributes" node.
	attrs := []any{
		ttlvLeaf("CryptographicAlgorithm", "Enumeration", p.Algorithm),
		ttlvLeaf("CryptographicLength", "Integer", p.KeyLengthBits),
		ttlvLeaf("CryptographicUsageMask", "Integer", p.UsageMask),
	}
	if p.Name != "" {
		attrs = append(attrs, ttlvNode("Name", []any{
			ttlvLeaf("NameValue", "TextString", p.Name),
			ttlvLeaf("NameType", "Enumeration", "UninterpretedTextString"),
		}))
	}
	if len(p.Tags) > 0 {
		// Tags are stored as a JSON-encoded array string inside a VendorAttribute.
		tagJSON := tagsToJSON(p.Tags)
		attrs = append(attrs, ttlvNode("Attribute", []any{
			ttlvLeaf("VendorIdentification", "TextString", "cosmian"),
			ttlvLeaf("AttributeName", "TextString", "tag"),
			ttlvLeaf("AttributeValue", "TextString", tagJSON),
		}))
	}

	req := ttlvNode("Create", []any{
		ttlvLeaf("ObjectType", "Enumeration", "SymmetricKey"),
		ttlvNode("Attributes", attrs),
	})

	resp, err := c.doKMIP(ctx, req)
	if err != nil {
		return "", fmt.Errorf("CreateSymmetricKey: %w", err)
	}
	nodes, err := responseNodes(resp)
	if err != nil {
		return "", fmt.Errorf("CreateSymmetricKey response: %w", err)
	}
	return extractTextString(nodes, "UniqueIdentifier")
}

// CreateKeyPair creates an asymmetric key pair via KMIP 2.1 CreateKeyPair.
// Returns (privateUID, publicUID, error).
func (c *Client) CreateKeyPair(ctx context.Context, p KeyPairParams) (string, string, error) {
	// KMIP 2.1: CommonAttributes / PrivateKeyAttributes / PublicKeyAttributes.
	commonAttrs := []any{
		ttlvLeaf("CryptographicAlgorithm", "Enumeration", p.Algorithm),
		ttlvLeaf("CryptographicLength", "Integer", p.KeyLengthBits),
	}
	if p.Name != "" {
		commonAttrs = append(commonAttrs, ttlvNode("Name", []any{
			ttlvLeaf("NameValue", "TextString", p.Name),
			ttlvLeaf("NameType", "Enumeration", "UninterpretedTextString"),
		}))
	}

	req := ttlvNode("CreateKeyPair", []any{
		ttlvNode("CommonAttributes", commonAttrs),
		ttlvNode("PrivateKeyAttributes", []any{
			ttlvLeaf("CryptographicUsageMask", "Integer", 1), // Sign
		}),
		ttlvNode("PublicKeyAttributes", []any{
			ttlvLeaf("CryptographicUsageMask", "Integer", 2), // Verify
		}),
	})

	resp, err := c.doKMIP(ctx, req)
	if err != nil {
		return "", "", fmt.Errorf("CreateKeyPair: %w", err)
	}
	nodes, err := responseNodes(resp)
	if err != nil {
		return "", "", fmt.Errorf("CreateKeyPair response: %w", err)
	}
	privUID, err := extractTextString(nodes, "PrivateKeyUniqueIdentifier")
	if err != nil {
		return "", "", fmt.Errorf("CreateKeyPair: %w", err)
	}
	pubUID, err := extractTextString(nodes, "PublicKeyUniqueIdentifier")
	if err != nil {
		return "", "", fmt.Errorf("CreateKeyPair: %w", err)
	}
	return privUID, pubUID, nil
}

// GetAttributes fetches KMIP attributes for an object UID.
// Returns a map of attribute name → value for use in Terraform Read.
// Note: the KMS returns HTTP 200 even for Destroyed objects (State = "Destroyed").
func (c *Client) GetAttributes(ctx context.Context, uid string) (map[string]any, error) {
	req := ttlvNode("GetAttributes", []any{
		ttlvLeaf("UniqueIdentifier", "TextString", uid),
	})

	resp, err := c.doKMIP(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("GetAttributes(%s): %w", uid, err)
	}
	return resp, nil
}

// ObjectExists returns true if the object exists AND is not in the Destroyed state.
// Use this in resource Read functions instead of GetAttributes to handle the KMS
// behaviour of keeping Destroyed objects in the database.
func (c *Client) ObjectExists(ctx context.Context, uid string) (bool, error) {
	resp, err := c.GetAttributes(ctx, uid)
	if err != nil {
		// HTTP error → object not found
		return false, nil //nolint:nilerr
	}
	// Walk the response for State = "Destroyed"
	nodes, _ := responseNodes(resp)
	for _, n := range nodes {
		node, ok := n.(map[string]any)
		if !ok {
			continue
		}
		if node["tag"] == "Attributes" {
			attrs, _ := node["value"].([]any)
			for _, a := range attrs {
				attr, ok := a.(map[string]any)
				if !ok {
					continue
				}
				if attr["tag"] == "State" && attr["value"] == "Destroyed" {
					return false, nil
				}
			}
		}
	}
	return true, nil
}

// Destroy destroys an object by UID via KMIP Destroy.
func (c *Client) Destroy(ctx context.Context, uid string) error {
	req := ttlvNode("Destroy", []any{
		ttlvLeaf("UniqueIdentifier", "TextString", uid),
	})
	_, err := c.doKMIP(ctx, req)
	if err != nil {
		return fmt.Errorf("Destroy(%s): %w", uid, err)
	}
	return nil
}

// GrantAccess calls POST /access/grant.
// UniqueIdentifier is an untagged serde enum: pass a plain string.
// operation_types must be lowercase KmipOperation names, e.g. "get", "decrypt".
func (c *Client) GrantAccess(ctx context.Context, p AccessRightParams) error {
	payload := map[string]any{
		"unique_identifier": p.ObjectUID,
		"user_id":           p.UserID,
		"operation_types":   toLower(p.OperationTypes),
	}
	_, err := c.doREST(ctx, http.MethodPost, "/access/grant", payload)
	if err != nil {
		return fmt.Errorf("GrantAccess: %w", err)
	}
	return nil
}

// ListAccesses calls GET /access/list/{uid} and returns raw UserAccessResponse entries.
// The endpoint returns a JSON array, so we bypass doREST (which decodes into map[string]any).
func (c *Client) ListAccesses(ctx context.Context, uid string) ([]map[string]any, error) {
	return c.listAccessesRaw(ctx, uid)
}

// listAccessesRaw calls GET /access/list/{uid} expecting a JSON array response.
func (c *Client) listAccessesRaw(ctx context.Context, uid string) ([]map[string]any, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.ServerURL+"/access/list/"+uid, nil)
	if err != nil {
		return nil, fmt.Errorf("creating HTTP request: %w", err)
	}
	if c.cfg.APIKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("KMS returned HTTP %d", resp.StatusCode)
	}

	var result []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding access list: %w", err)
	}
	return result, nil
}

// RevokeAccess calls POST /access/revoke.
func (c *Client) RevokeAccess(ctx context.Context, p AccessRightParams) error {
	payload := map[string]any{
		"unique_identifier": p.ObjectUID,
		"user_id":           p.UserID,
		"operation_types":   toLower(p.OperationTypes),
	}
	_, err := c.doREST(ctx, http.MethodPost, "/access/revoke", payload)
	if err != nil {
		return fmt.Errorf("RevokeAccess: %w", err)
	}
	return nil
}

// tagsToJSON serialises a string slice to a JSON array, e.g. ["env=prod","team=data"].
// This is the format the KMS uses for the vendor-attribute "tag" field.
func tagsToJSON(tags []string) string {
	b, _ := json.Marshal(tags)
	return string(b)
}

// toLower returns a new slice with each string lowercased.
// KmipOperation is serialised to lowercase by serde (rename_all = "lowercase").
func toLower(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = strings.ToLower(s)
	}
	return out
}

// ─── TTLV helpers ──────────────────────────────────────────────────────────

// ttlvNode builds a Structure TTLV node (no "type" field).
func ttlvNode(tag string, value []any) map[string]any {
	return map[string]any{"tag": tag, "value": value}
}

// ttlvLeaf builds a scalar TTLV node.
func ttlvLeaf(tag, typ string, value any) map[string]any {
	return map[string]any{"tag": tag, "type": typ, "value": value}
}

// ttlvAttr builds a KMIP 1.x Attribute child (AttributeName + AttributeValue).
func ttlvAttr(name, typ string, value any) map[string]any {
	return ttlvNode("Attribute", []any{
		ttlvLeaf("AttributeName", "TextString", name),
		ttlvLeaf("AttributeValue", typ, value),
	})
}
