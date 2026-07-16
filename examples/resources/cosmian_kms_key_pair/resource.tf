resource "cosmian_kms_key_pair" "signing_pair" {
  algorithm       = "RSA"
  key_length_bits = 4096
  name            = "code-signing"
}

output "public_key_uid" {
  value     = cosmian_kms_key_pair.signing_pair.public_key_uid
  sensitive = true
}
