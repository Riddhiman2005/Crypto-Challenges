
#include "../../utils/crypto.h"
#include "../../utils/stringutils.h"

#include <iostream>
#include <cstdlib>
#include <cstring>
#include <ctime>

#define PUT_UINT32_LE(n, b, i)              \
    {                                       \
        (b)[(i)] = (uint8_t)((n));          \
        (b)[(i) + 1] = (uint8_t)((n) >> 8); \
        (b)[(i) + 2] = (uint8_t)((n) >> 16);\
        (b)[(i) + 3] = (uint8_t)((n) >> 24);\
    }

static uint8_t md4_padding[64] =
{
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

static char tkn[] = "comment1=cooking%20MCs;userdata=foo;comment2=%20like"
                   "%20a%20pound%20of%20bacon";
static uint8_t k[16];

void gettoken(uint8_t mac[16])
{
    // Generate random key
    srand(time(NULL));
    for (int i = 0; i < 16; i++)
        k[i] = rand() % 256;

    // Generate MAC
    macmd4(tkn, strlen(tkn), mac, k);
}

size_t gluepadding(size_t l, uint8_t* out)
{
    uint32_t total[2];

    uint32_t left, fill;

    left = total[0] & 0x3F;
    fill = 64 - left;

    total[0] += l;
    total[0] &= 0xFFFFFFFF;

    if (total[0] < l)
        total[1]++;

    uint32_t last, padn;
    uint32_t high, low;
    uint8_t msglen[8];

    high = (total[0] >> 29) | (total[1] << 3);
    low = (total[0] << 3);

    PUT_UINT32_LE(low, msglen, 0);
    PUT_UINT32_LE(high, msglen, 4);

    last = total[0] & 0x3F;
    padn = (last < 56) ? (56 - last) : (120 - last);

    memcpy(out, md4_padding, padn);
    memcpy(out + padn, msglen, 8);

    return padn + 8;
}

int chktkn(uint8_t* msg, size_t msglen, uint8_t mac[16])
{
    return macmd4chk(msg, msglen, mac, k);
}

int main()
{
    // Get token MAC
    uint8_t tknmac[16];
    gettoken(tknmac);
    std::cout << "For token:\n\t" << tkn << "\nGot MAC:\n\t";
    printhex(tknmac, 16);
    std::cout << "\nForging MAC...\n\n";

    /// Forge MAC
    // Get glue padding
    uint8_t glue[512];
    size_t gluel;
    gluel = gluepadding(strlen(tkn) + 16, glue);
    // Build forged token
    char frgtkn[8192] = {0};
    size_t frgtknl = 0;
    memcpy(frgtkn, tkn, strlen(tkn));
    frgtknl += strlen(tkn);
    memcpy(frgtkn + frgtknl, glue, gluel);
    frgtknl += gluel;
    // Forge MD4 hash
    md4_context ctx;
    md4_starts(&ctx);
    uint32_t* state = (uint32_t*)ctx.state;
    uint32_t* _mac = (uint32_t*)tknmac;
    // Replace state registers
    for (int i = 0; i < 4; i++)
        state[i] = le32toh(_mac[i]);

    uint32_t left, fill;
    left = ctx.total[0] & 0x3F;
    fill = 64 - left;
    ctx.total[0] += frgtknl + 16;
    ctx.total[0] &= 0xFFFFFFFF;
    if (ctx.total[0] < frgtknl + 16)
        ctx.total[1]++;

    // Append ';admin=True'
    char* tknappend = ";admin=true";
    md4_update(&ctx, (uint8_t*)tknappend, strlen(tknappend));
    memcpy(frgtkn + frgtknl, tknappend, strlen(tknappend));
    frgtknl += strlen(tknappend);
    uint8_t frgmac[16];
    md4_finish(&ctx, frgmac);
    // Print results
    std::cout << "For token:\n\t";
    printstr(frgtkn, frgtknl);
    std::cout << "Got MAC:\n\t";
    printhex(frgmac, 16);

    // Check results
    std::cout << "\n\nChecking MAC validity: "
              << (chktkn((uint8_t*)frgtkn, frgtknl, frgmac) ? "OK" : "FAIL") << "\n";

    return 0;
}

