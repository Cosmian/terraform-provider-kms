resource "symmetric_key" "data_key" {
  algorithm       = "AES"
  key_length_bits = 256
  name            = "shared-data-key"
}

resource "access_right" "alice_can_decrypt" {
  object_uid = symmetric_key.data_key.id
  user_id    = "alice@example.com"
  operations = ["Get", "Decrypt"]
}
