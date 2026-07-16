resource "cosmian_kms_symmetric_key" "data_key" {
  algorithm       = "AES"
  key_length_bits = 256
  name            = "shared-data-key"
}

resource "cosmian_kms_access_right" "alice_can_decrypt" {
  object_uid = cosmian_kms_symmetric_key.data_key.id
  user_id    = "alice@example.com"
  operations = ["Get", "Decrypt"]
}
