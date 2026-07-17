terraform {
  required_providers {
    kms = {
      source  = "cosmian/kms"
      version = "~> 0.1"
    }
  }
}

provider "kms" {
  server_url = "https://kms.example.com:9998"
  api_key    = var.kms_api_key # or set COSMIAN_KMS_API_KEY env var

  # mTLS alternative:
  # tls_cert_file = "/etc/kms/client.crt"
  # tls_key_file  = "/etc/kms/client.key"
  # ca_cert_file  = "/etc/kms/ca.pem"
}

variable "kms_api_key" {
  type      = string
  sensitive = true
}
