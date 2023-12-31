#include <openssl/evp.h>
#include <openssl/sha.h>
#include <cstring>


size_t pkcs7(unsigned char * buff, size_t msglen, size_t bsize)
{
  size_t i;
  size_t padd = (unsigned char)(bsize - msglen % bsize);
  if(padd > 255) printf("ERROR: Too much padding");
  for(i = 0; i < padd; i++) buff[msglen + i] = (unsigned char)padd;

  return msglen + padd;
}

int encrypt_aes128ecb(const unsigned char * p, size_t pl, unsigned char * c, const unsigned char * k)
{
  int outl = 0;
  EVP_CIPHER_CTX * ctx = EVP_CIPHER_CTX_new();
  EVP_EncryptInit(ctx, EVP_aes_128_ecb(), k, NULL);
  EVP_EncryptUpdate(ctx, c, &outl, p, pl);
  int _outl = 0;
  EVP_EncryptFinal(ctx, c + outl, &_outl);
  EVP_CIPHER_CTX_free(ctx);
  int cl = outl + _outl;
  return cl;
}

int decrypt_aes128ecb(const unsigned char * c, size_t cl, unsigned char * p, const unsigned char * k)
{
  int outl = 0;
  EVP_CIPHER_CTX * ctx = EVP_CIPHER_CTX_new();
  EVP_DecryptInit(ctx, EVP_aes_128_ecb(), k, NULL);
  EVP_DecryptUpdate(ctx, p, &outl, c, cl);
  int _outl = 0;
  EVP_DecryptFinal(ctx, p + outl, &_outl);
  EVP_CIPHER_CTX_free(ctx);
  int pl = outl + _outl;
  return pl;
}

size_t encrypt_aes128cbc(const unsigned char * p, size_t pl, unsigned char * c, const unsigned char * k, const unsigned char * iv)
{
  // Point previous block to IV
  const unsigned char * pblock = iv;
  // Calculate number of blocks
  size_t nblocks = pl / 16 + (pl % 16 > 0);
  // Count length of c
  size_t cl = 0;
  // Iterate for each block
  size_t i;
  for(i = 0; i < nblocks; i++)
  {
    // XOR buffer
    unsigned char pxorc[16];
    for (int j = 0; j < 16; j++)
        pxorc[j] = pblock[j] ^ p[i * 16 + j];
    // Encrypt block
    encrypt_aes128ecb(pxorc, 16, c + i * 16, k);
    // Point previous block to new ciphered block
    pblock = c + i * 16;
  }

  return 16 * nblocks;
}

size_t decrypt_aes128cbc(const unsigned char * c, size_t cl, unsigned char * p, const unsigned char * k, const unsigned char * iv)
{
  // Point previous block to IV
  const unsigned char * pblock = iv;
  // Calculate number of blocks
  size_t nblocks = cl / 16;
  // Count length of p
  size_t pl = 0;
  // Iterate for each block
  size_t i;
  for(i = 0; i < nblocks; i++)
  {
    // XOR buffer
    unsigned char pxorc[16];
    // Decrypt block
    decrypt_aes128ecb(c + i * 16, 16, pxorc, k);
    // Xor with previous cipher block
    for (int j = 0; j < 16; j++)
        p[i * 16 + j] = pxorc[j] ^ pblock[j];
    // Point previous block to last ciphered block
    pblock = c + i * 16;
  }

  return 16 * nblocks;
}

int detect_ebc(const unsigned char * c, size_t cl)
{
  // Look for repeating patterns
  int nblocks = cl / 16;
  int i, j, rep = 0;
  for(i = 0; i < nblocks - 1; i++)
    for(j = i + 1; j < nblocks; j++)
      if(std::strncmp((char*)(c + i * 16), (char*)(c + j * 16), 16) == 0)
        rep++;

  return rep;
}

int pkcs7strip(unsigned char * p, size_t l)
{
  int pl = p[l - 1]; // Padding length

  // Check padding
  int i;
  for(i = 0; i < pl; i++)
    if(p[l - 1 - i] != pl) return 0;

  // Strip padding
  for(i = 0; i < pl; i++)
    p[l - 1 - i] = 0;

  // Return
  return pl;
}

void aes128ctr(const unsigned char * in, size_t l, unsigned char * out,
  const unsigned char * k, uint64_t nonce)
{
  uint64_t ctr = 0; // Counter register
  unsigned char buff[32]; // AES stream buffer
  unsigned char blck[16] = {0}; // AES block buffer
  uint64_t * _nonce = (uint64_t *)blck; // Point to nonce
  uint64_t * _ctr = (uint64_t *)(blck + 8); // Point to counter
  *_nonce = htole64(nonce); // Store nonce little-endian

  // Iterate each plaintext byte
  size_t i;
  for(i = 0; i < l; i++)
  {
    // Generate next AES block every 16 bytes
    if(!(i % 16))
    {
      *_ctr = htole64(ctr++);
      encrypt_aes128ecb(blck, 16, buff, k);
    }

    // Xor
    out[i] = in[i] ^ buff[i % 16];
  }
}

void aes128ctroff(const unsigned char * in, size_t l, unsigned char * out,
  const unsigned char * k, uint64_t nonce, uint64_t offset)
{
  uint64_t ctr = offset; // Counter register
  unsigned char buff[32]; // AES stream buffer
  unsigned char blck[16] = {0}; // AES block buffer
  uint64_t * _nonce = (uint64_t *)blck; // Point to nonce
  uint64_t * _ctr = (uint64_t *)(blck + 8); // Point to counter
  *_nonce = htole64(nonce); // Store nonce little-endian

  // Iterate each plaintext byte
  size_t i;
  for(i = 0; i < l; i++)
  {
    // Generate next AES block every 16 bytes
    if(!(i % 16))
    {
      *_ctr = htole64(ctr++);
      encrypt_aes128ecb(blck, 16, buff, k);
    }

    // Xor
    out[i] = in[i] ^ buff[i % 16];
  }
}

void mtcrypt(const unsigned char * in, size_t l, unsigned char * out,
  uint32_t k)
{
  mtseed(k);
  size_t i;
  int j = 4;
  uint32_t bbuff;
  uint8_t * b = (uint8_t*)(&bbuff);
  for(i = 0; i < l; i++)
  {
    // Get next 4 bytes
    if(j > 3)
    {
      bbuff = mtrand();
      j = 0;
    }

    // Encrypt
    out[i] = in[i] ^ b[j++];
  }
}

void macsha1(const uint8_t * data, size_t l, uint8_t out[20],
  const uint8_t key[16])
{
  // Create context
  SHA1_CTX ctx;
  SHA1Init(&ctx);

  // Hash key
  SHA1Update(&ctx, key, 16);
  // Hash data
  SHA1Update(&ctx, data, l);

  // Final round
  SHA1Final(out, &ctx);
}

int macsha1chk(const uint8_t * data, size_t l, const uint8_t mac[20],
  const uint8_t key[16])
{
  // Calculate MAC
  uint8_t datamac[20];
  macsha1(data, l, datamac, key);

  // Compare
  return std::memcmp(mac, datamac, 20) == 0;
}

void macmd4(uint8_t * data, size_t l, uint8_t out[16], uint8_t key[16])
{
  // Create context
  md4_context ctx;
  md4_starts(&ctx);

  // Hash key
  md4_update(&ctx, key, 16);
  // Hash data
  md4_update(&ctx, data, l);

  // Final round
  md4_finish(&ctx, out);
}

int macmd4chk(uint8_t * data, size_t l, uint8_t mac[16], uint8_t key[16])
{
  // Calculate MAC
  uint8_t datamac[16];
  macmd4(data, l, datamac, key);

  // Compare
  return std::memcmp(mac, datamac, 16) == 0;
}

void hmacsha1(const uint8_t * data, size_t l, uint8_t out[20],
  const uint8_t key[64])
{
  SHA1_CTX ctx;

  // Xor key with inner padding
  uint8_t i_key_pad[64];
  sbxorarray(key, 0x36, i_key_pad, 64);

  // Inner hash
  uint8_t hash1[20];
  SHA1Init(&ctx);
  SHA1Update(&ctx, i_key_pad, 64);
  SHA1Update(&ctx, data, l);
  SHA1Final(hash1, &ctx);

  // Xor key with outer padding
  uint8_t o_key_pad[64];
  sbxorarray(key, 0x5c, o_key_pad, 64);

  // Outer hash
  SHA1Init(&ctx);
  SHA1Update(&ctx, o_key_pad, 64);
  SHA1Update(&ctx, hash1, 20);
  SHA1Final(out, &ctx);
}

int hmacsha1chk(const uint8_t * data, size_t l, const uint8_t hmac[20],
  const uint8_t key[64])
{
  // Calculate HMAC
  uint8_t datahmac[20];
  hmacsha1(data, l, datahmac, key);

  // Compare
  return std::memcmp(hmac, datahmac, 20) == 0;
}
