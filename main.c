#include <assert.h>
#include <endian.h>
#include <errno.h>
#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

typedef struct header_t {
  u_int32_t iter_count;
  unsigned char salt[12];
  unsigned char nonce[12];

} __attribute__((__packed__)) header_t;

char *format_hex(unsigned const char *buffer, int len) {
  char *ret = malloc(len * 2 + 1);
  for (int j = 0; j < len; j++) snprintf(ret + j * 2, 3, "%02X", buffer[j]);
  return ret;
}

int main(int argc, char *argv[]) {
  char *contents;
  size_t length;
  int tlserr;
  char *password = NULL;
  if (argc < 2 || argc > 3) {
    fprintf(stderr, "Usage: %s ANDOTP_BACKUP_FILE [PASSWORD]\n", argv[0]);
    exit(1);
  }
  FILE *file = fopen(argv[1], "rb");
  if (file == NULL) {
    fprintf(stderr, "Failed to open '%s': %s\n", argv[1], strerror(errno));
    exit(1);
  }
  if (fseek(file, 0L, SEEK_END) < 0) {
    fprintf(stderr, "Failed to fseek '%s': %s\n", argv[1], strerror(errno));
    exit(1);
  }
  if (argc == 3)
    password = argv[2];
  else
    password = getpass("Password: ");
  length = ftell(file);
  rewind(file);
  int n;
  assert((contents = malloc(length)) != NULL);
  assert((n = fread(contents, 1, length, file)) == length);
  header_t *header = (header_t *)contents;
  unsigned char *ct = (unsigned char *)contents + sizeof(header_t);
  /* iter */
  int32_t iter_count = be32toh(header->iter_count);
  gnutls_datum_t salt = {.data = header->salt, .size = 12};
  unsigned char derived_key[32];
  gnutls_datum_t password_key = {.data = (unsigned char *)password, .size = strlen(password)};
  if ((tlserr = gnutls_pbkdf2(GNUTLS_MAC_SHA1, &password_key, &salt, iter_count, derived_key, 32)) < 0) {
    printf("gnutls_pbkdf2 failed: %s\n", gnutls_strerror(tlserr));
    goto cleanup;
  }
  gnutls_datum_t key = {.data = derived_key, .size = 32};

  gnutls_session_t session;
  gnutls_aead_cipher_hd_t hd;
  assert(gnutls_init(&session, 0) == GNUTLS_E_SUCCESS);

  assert(key.size == 32);

  if (gnutls_aead_cipher_init(&hd, GNUTLS_CIPHER_AES_256_GCM, &key) < 0) {
    printf("Error init gnutls_cipher_init");
  }
  char decrypted[8096];
  size_t decrypted_length = 8096;
  char *derived_key_hex = format_hex(derived_key, 32);
  char *salt_hex = format_hex(salt.data, 12);
  free(salt_hex);
  char *nonce_hex = format_hex(header->nonce, 12);
  free(nonce_hex);
  free(derived_key_hex);
  if ((tlserr = gnutls_aead_cipher_decrypt(hd, header->nonce, 12, NULL, 0, 16, ct, length - sizeof(header_t), decrypted,
                                           &decrypted_length)) < 0) {
    printf("gnutls_aead_cipher_decrypt failed: %s\n", gnutls_strerror(tlserr));
    goto cleanup;
  }
  fwrite(decrypted, 1, decrypted_length, stdout);
cleanup:
  gnutls_deinit(session);
  free(contents);
}
