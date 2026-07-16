resource "cosmian_kms_symmetric_key" "data_key" {
  algorithm       = "AES"
  key_length_bits = 256
  name            = "database-encryption-key"
  tags            = ["env=prod", "team=data"]
}

output "key_uid" {
  value     = cosmian_kms_symmetric_key.data_key.id
  sensitive = true
}
