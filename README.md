# Terraform Provider for Cosmian KMS

Manage cryptographic keys, certificates, and access rights in [Cosmian KMS](https://github.com/Cosmian/kms) using Terraform or OpenTofu.

## Requirements

- [Terraform](https://developer.hashicorp.com/terraform/downloads) >= 1.0 or [OpenTofu](https://opentofu.org/) >= 1.6
- [Go](https://golang.org/doc/install) >= 1.22 (to build from source)
- A running Cosmian KMS instance >= 5.0

## Using the Provider

```hcl
terraform {
  required_providers {
    cosmian-kms = {
      source  = "cosmian/kms"
      version = "~> 0.1"
    }
  }
}

provider "cosmian-kms" {
  server_url = "https://kms.example.com"
  api_key    = var.kms_api_key   # or set COSMIAN_KMS_API_KEY env var
}
```

## Resources

| Resource | Description |
|----------|-------------|
| `cosmian_kms_symmetric_key` | AES symmetric key (KMIP Create / Destroy) |
| `cosmian_kms_key_pair` | RSA / EC key pair (KMIP CreateKeyPair / Destroy) |
| `cosmian_kms_certificate` | X.509 certificate (KMIP Certify / Destroy) |
| `cosmian_kms_access_right` | Grant a user access to a KMS object |

## Data Sources

| Data Source | Description |
|-------------|-------------|
| `data.cosmian_kms_symmetric_key` | Read a symmetric key by UID |
| `data.cosmian_kms_key_pair` | Read a key pair by private/public UIDs |
| `data.cosmian_kms_access_list` | List all access rights on a KMS object |

## Local Development

```bash
# Build
make build

# Run acceptance tests (requires a local KMS)
export TF_ACC=1
export COSMIAN_KMS_SERVER_URL=http://localhost:9998
make testacc
```

To test without publishing a release, configure Terraform to use the local binary:

```hcl
# ~/.terraformrc
provider_installation {
  dev_overrides {
    "cosmian/kms" = "/path/to/terraform-provider-kms"
  }
  direct {}
}
```

## License

[Mozilla Public License 2.0](LICENSE)
