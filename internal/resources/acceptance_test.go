// Package resources_test contains acceptance tests for Cosmian KMS Terraform resources.
// Tests require a running KMS server. Set COSMIAN_KMS_SERVER_URL (default: http://localhost:9998).
// Enable with: TF_ACC=1 go test -v -timeout 120s ./internal/resources/
package resources_test

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-framework/provider"

	kmsClient "github.com/cosmian/terraform-provider-kms/internal/client"
	kmsProvider "github.com/cosmian/terraform-provider-kms/internal/provider"
)

// testProviderFactories is used by all acceptance tests.
var testProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"kms": providerserver.NewProtocol6WithError(kmsProvider.New("test")()),
}

// testClient returns a KMS client pointed at the acceptance test server.
func testClient(t *testing.T) *kmsClient.Client {
	t.Helper()
	serverURL := os.Getenv("COSMIAN_KMS_SERVER_URL")
	if serverURL == "" {
		serverURL = "http://localhost:9998"
	}
	c, err := kmsClient.New(kmsClient.Config{ServerURL: serverURL})
	if err != nil {
		t.Fatalf("creating test client: %v", err)
	}
	return c
}

// skipIfNoAcc skips the test when TF_ACC is not set.
func skipIfNoAcc(t *testing.T) {
	t.Helper()
	if os.Getenv("TF_ACC") == "" {
		t.Skip("Set TF_ACC=1 to run acceptance tests")
	}
}

// providerConfig is the minimal provider HCL for acceptance tests.
func providerConfig() string {
	serverURL := os.Getenv("COSMIAN_KMS_SERVER_URL")
	if serverURL == "" {
		serverURL = "http://localhost:9998"
	}
	return fmt.Sprintf(`
provider "kms" {
  server_url = %q
}
`, serverURL)
}

// TestAccSymmetricKey_lifecycle tests create → read → destroy for cosmian_kms_symmetric_key.
func TestAccSymmetricKey_lifecycle(t *testing.T) {
	skipIfNoAcc(t)
	c := testClient(t)

	// Create via client directly and verify.
	uid, err := c.CreateSymmetricKey(context.Background(), kmsClient.SymmetricKeyParams{
		Algorithm:     "AES",
		KeyLengthBits: 256,
		Name:          "tf-test-symkey",
	})
	if err != nil {
		t.Fatalf("CreateSymmetricKey: %v", err)
	}
	t.Logf("created symmetric key UID: %s", uid)

	// GetAttributes must succeed.
	_, err = c.GetAttributes(context.Background(), uid)
	if err != nil {
		t.Fatalf("GetAttributes after create: %v", err)
	}

	// Destroy.
	if err := c.Destroy(context.Background(), uid); err != nil {
		t.Fatalf("Destroy: %v", err)
	}

	// KMS keeps Destroyed objects in DB with State=Destroyed.
	// ObjectExists must return false after Destroy.
	exists, err := c.ObjectExists(context.Background(), uid)
	if err != nil {
		t.Fatalf("ObjectExists after Destroy returned error: %v", err)
	}
	if exists {
		t.Fatal("expected ObjectExists to return false after Destroy")
	}
	t.Log("ObjectExists correctly returned false after Destroy")
}

// TestAccKeyPair_lifecycle tests CreateKeyPair → GetAttributes × 2 → Destroy × 2.
func TestAccKeyPair_lifecycle(t *testing.T) {
	skipIfNoAcc(t)
	c := testClient(t)

	privUID, pubUID, err := c.CreateKeyPair(context.Background(), kmsClient.KeyPairParams{
		Algorithm:     "RSA",
		KeyLengthBits: 2048,
		Name:          "tf-test-keypair",
	})
	if err != nil {
		t.Fatalf("CreateKeyPair: %v", err)
	}
	t.Logf("private: %s  public: %s", privUID, pubUID)

	for _, uid := range []string{privUID, pubUID} {
		if _, err := c.GetAttributes(context.Background(), uid); err != nil {
			t.Fatalf("GetAttributes(%s): %v", uid, err)
		}
	}

	// Destroy both keys.
	for _, uid := range []string{privUID, pubUID} {
		if err := c.Destroy(context.Background(), uid); err != nil {
			t.Fatalf("Destroy(%s): %v", uid, err)
		}
	}
}

// TestAccAccessRight_grantRevoke tests GrantAccess → ListAccesses → RevokeAccess.
func TestAccAccessRight_grantRevoke(t *testing.T) {
	skipIfNoAcc(t)
	c := testClient(t)

	// Create a symmetric key to grant access on.
	uid, err := c.CreateSymmetricKey(context.Background(), kmsClient.SymmetricKeyParams{
		Algorithm:     "AES",
		KeyLengthBits: 256,
		Name:          "tf-test-access-key",
	})
	if err != nil {
		t.Fatalf("CreateSymmetricKey: %v", err)
	}
	t.Cleanup(func() { _ = c.Destroy(context.Background(), uid) })

	// Grant access.
	err = c.GrantAccess(context.Background(), kmsClient.AccessRightParams{
		ObjectUID:      uid,
		UserID:         "tf-test-user@example.com",
		OperationTypes: []string{"Get", "Decrypt"},
	})
	if err != nil {
		t.Fatalf("GrantAccess: %v", err)
	}

	// List accesses and verify.
	accesses, err := c.ListAccesses(context.Background(), uid)
	if err != nil {
		t.Fatalf("ListAccesses: %v", err)
	}
	found := false
	for _, a := range accesses {
		if a["user_id"] == "tf-test-user@example.com" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("user not found in access list: %v", accesses)
	}

	// Revoke access.
	err = c.RevokeAccess(context.Background(), kmsClient.AccessRightParams{
		ObjectUID:      uid,
		UserID:         "tf-test-user@example.com",
		OperationTypes: []string{"Get", "Decrypt"},
	})
	if err != nil {
		t.Fatalf("RevokeAccess: %v", err)
	}
}

// TestAccCertificate_lifecycle tests CreateKeyPair → Activate → Certify → GetAttributes → Destroy.
func TestAccCertificate_lifecycle(t *testing.T) {
	skipIfNoAcc(t)
	c := testClient(t)

	privUID, pubUID, err := c.CreateKeyPair(context.Background(), kmsClient.KeyPairParams{
		Algorithm:     "RSA",
		KeyLengthBits: 2048,
		Name:          "tf-test-cert-pair",
	})
	if err != nil {
		t.Fatalf("CreateKeyPair: %v", err)
	}
	t.Cleanup(func() {
		_ = c.Destroy(context.Background(), privUID)
		_ = c.Destroy(context.Background(), pubUID)
	})

	// Activate private key before Certify.
	if err := c.Activate(context.Background(), privUID); err != nil {
		t.Fatalf("Activate private key: %v", err)
	}

	certUID, err := c.Certify(context.Background(), kmsClient.CertificateParams{
		PublicKeyUID: pubUID,
		SubjectCN:    "tf-test",
		SubjectO:     "Cosmian",
		SubjectC:     "FR",
	})
	if err != nil {
		t.Fatalf("Certify: %v", err)
	}
	t.Logf("certificate UID: %s", certUID)
	t.Cleanup(func() { _ = c.Destroy(context.Background(), certUID) })

	if _, err := c.GetAttributes(context.Background(), certUID); err != nil {
		t.Fatalf("GetAttributes on certificate: %v", err)
	}
}

// Compile-time check that the provider satisfies the interface.
var _ provider.Provider = kmsProvider.New("test")()
