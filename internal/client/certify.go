// Certificate resource and Certify client method.
package client

import (
	"context"
	"fmt"
)

// CertificateParams defines the attributes for a KMIP Certify operation.
type CertificateParams struct {
	// PublicKeyUID is the KMS UID of the public key to certify.
	PublicKeyUID string
	// SubjectCN is the certificate subject Common Name.
	SubjectCN string
	// SubjectO is the subject Organisation.
	SubjectO string
	// SubjectC is the subject Country (2-letter code).
	SubjectC string
	// IssuerPrivateKeyUID, when non-empty, signs with that CA key; otherwise self-signed.
	IssuerPrivateKeyUID string
	// ValidityDays sets the certificate validity duration.
	ValidityDays int
}

// Certify calls KMIP Certify on a public key and returns the certificate UID.
// The caller must Activate the private key before calling this.
func (c *Client) Certify(ctx context.Context, p CertificateParams) (string, error) {
	certAttrs := []any{
		ttlvLeaf("CertificateSubjectCn", "TextString", p.SubjectCN),
		ttlvLeaf("CertificateSubjectO", "TextString", p.SubjectO),
		ttlvLeaf("CertificateSubjectC", "TextString", p.SubjectC),
		// Empty fields required by KMS Certify schema
		ttlvLeaf("CertificateSubjectOu", "TextString", ""),
		ttlvLeaf("CertificateSubjectEmail", "TextString", ""),
		ttlvLeaf("CertificateSubjectSt", "TextString", ""),
		ttlvLeaf("CertificateSubjectL", "TextString", ""),
		ttlvLeaf("CertificateSubjectUid", "TextString", ""),
		ttlvLeaf("CertificateSubjectSerialNumber", "TextString", ""),
		ttlvLeaf("CertificateSubjectTitle", "TextString", ""),
		ttlvLeaf("CertificateSubjectDc", "TextString", ""),
		ttlvLeaf("CertificateSubjectDnQualifier", "TextString", ""),
		ttlvLeaf("CertificateIssuerCn", "TextString", ""),
		ttlvLeaf("CertificateIssuerO", "TextString", ""),
		ttlvLeaf("CertificateIssuerOu", "TextString", ""),
		ttlvLeaf("CertificateIssuerEmail", "TextString", ""),
		ttlvLeaf("CertificateIssuerC", "TextString", ""),
		ttlvLeaf("CertificateIssuerSt", "TextString", ""),
		ttlvLeaf("CertificateIssuerL", "TextString", ""),
		ttlvLeaf("CertificateIssuerUid", "TextString", ""),
		ttlvLeaf("CertificateIssuerSerialNumber", "TextString", ""),
		ttlvLeaf("CertificateIssuerTitle", "TextString", ""),
		ttlvLeaf("CertificateIssuerDc", "TextString", ""),
		ttlvLeaf("CertificateIssuerDnQualifier", "TextString", ""),
	}

	attrs := []any{
		ttlvLeaf("CertificateType", "Enumeration", "X509"),
		ttlvNode("CertificateAttributes", certAttrs),
	}

	reqValue := []any{
		ttlvLeaf("UniqueIdentifier", "TextString", p.PublicKeyUID),
		ttlvNode("Attributes", attrs),
	}

	if p.IssuerPrivateKeyUID != "" {
		reqValue = append(reqValue, ttlvLeaf("PrivateKeyUniqueIdentifier", "TextString", p.IssuerPrivateKeyUID))
	}

	req := ttlvNode("Certify", reqValue)

	resp, err := c.doKMIP(ctx, req)
	if err != nil {
		return "", fmt.Errorf("Certify(%s): %w", p.PublicKeyUID, err)
	}
	nodes, err := responseNodes(resp)
	if err != nil {
		return "", fmt.Errorf("Certify response: %w", err)
	}
	return extractTextString(nodes, "UniqueIdentifier")
}

// Activate calls KMIP Activate on an object (required before Certify).
func (c *Client) Activate(ctx context.Context, uid string) error {
	req := ttlvNode("Activate", []any{
		ttlvLeaf("UniqueIdentifier", "TextString", uid),
	})
	_, err := c.doKMIP(ctx, req)
	if err != nil {
		return fmt.Errorf("Activate(%s): %w", uid, err)
	}
	return nil
}
