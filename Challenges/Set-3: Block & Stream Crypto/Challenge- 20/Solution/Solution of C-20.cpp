
#include <iostream>
#include <fstream>
#include <cstring>
#include <ctime>
#include <openssl/rand.h>
#include <openssl/evp.h>

const char* PTXT_PATH = "../../res/20.txt"; // Plaintext list

struct Array
{
    size_t length;
    unsigned char data[512];
};

// Global variables
Array cs[128]; // Ciphertext array
int n = 0;     // Number of ciphertexts
size_t maxl = 0; // Max ciphertext length

// Utility functions
size_t readb64(const char* input, unsigned char* output, size_t max_length)
{
    BIO* bio = BIO_new_mem_buf(input, -1);
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);

    size_t length = BIO_read(bio, output, max_length);

    BIO_free_all(bio);
    return length;
}

void aes128ctr(const char* plaintext, size_t length, unsigned char* ciphertext, const unsigned char* key, size_t nonce)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, reinterpret_cast<unsigned char*>(&nonce));

    int ciphertext_length = 0;
    EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_length, reinterpret_cast<const unsigned char*>(plaintext), length);

    EVP_CIPHER_CTX_free(ctx);
}

unsigned char findxorkey(const unsigned char* input, size_t length, int use_frequency, int use_dictionary, int print_results)
{
    unsigned char key = 0;

    // Your implementation of finding the XOR key goes here

    return key;
}

void xorarray(const unsigned char* key, const unsigned char* input, char* output, size_t length)
{
    for (size_t i = 0; i < length; ++i)
    {
        output[i] = static_cast<char>(key[i] ^ input[i]);
    }
}

void printstr(const char* str, size_t length)
{
    std::cout.write(str, length);
    std::cout << std::endl;
}

void init()
{
    // Initialize random seed
    srand(time(NULL));

    // Generate random key
    unsigned char key[16];
    for (int i = 0; i < 16; ++i)
    {
        key[i] = rand() % 256;
    }

    // Read plaintexts
    std::ifstream file(PTXT_PATH);

    char c; // Character register
    while (!file.eof())
    {
        int i = 0;                 // Buffer pointer register
        char buff[8192] = { 0 };  // Input buffer

        // Read each character
        while ((c = file.get()) > 31)
        {
            buff[i++] = c;
        }
        buff[i] = '\0';

        // Check EOF
        if (file.eof())
        {
            break;
        }

        // Decode
        unsigned char p[512];
        size_t pl = readb64(buff, p, 512);
        if (!pl)
        {
            continue;
        }

        // Encrypt and store
        if (pl > maxl)
        {
            maxl = pl;
        }
        cs[n].length = pl;
        aes128ctr(reinterpret_cast<const char*>(p), pl, cs[n].data, key, 0);
        n++;
    }

    file.close();
}

int main()
{
    // Initialize
    init();

    // Try to find key
    unsigned char key[512]; // Predicted key
    int i, j, k;
    for (i = 0; i < maxl; ++i)
    {
        // Build block from i-th byte for each ciphertext
        unsigned char buff[512];
        k = 0;
        for (j = 0; j < n; ++j)
        {
            if (i < cs[j].length)
            {
                buff[k++] = cs[j].data[i];
            }
        }

        // Predict key
        key[i] = findxorkey(buff, k, 1, 0, 1);
    }

    // Print result
    for (i = 0; i < n; ++i)
    {
        char p[512];
        xorarray(key, cs[i].data, p, cs[i].length);
        printstr(p, cs[i].length);
    }

    return 0;
}

