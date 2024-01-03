#include <stdio.h>
#include <unistd.h>

#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/evp.h>

#include <libkeccak.h>

#define NUM_THREADS     20

#define ADDRESS_LENGTH  20

static void calculate_address(
    const unsigned char *data,
    size_t dataLen,
    struct libkeccak_state *state,
    unsigned char *address)
{
    // Reset state
    libkeccak_state_reset(state);

    // Generate hash
    unsigned char hashsum[32] = {};
    libkeccak_zerocopy_digest(state, (unsigned char *)data, dataLen, 0, NULL, hashsum);

    size_t offset = sizeof(hashsum) - ADDRESS_LENGTH;
    for (size_t i = offset; i < sizeof(hashsum); i++)
        address[i - offset] = hashsum[i];
}

struct Key
{
    unsigned char priv[32];
    unsigned char pub[256]; // libkeccak wants extra space
    size_t pubLen;
    unsigned char address[ADDRESS_LENGTH];
};

static void makeKey(
    EC_KEY *key,
    BN_CTX *ctx,
    struct libkeccak_state *state,
    struct Key *output)
{
    // Create a new EC key
    EC_KEY_generate_key(key);

    // Get private point
    const BIGNUM *bnPriv = EC_KEY_get0_private_key(key);
    BN_bn2binpad(bnPriv, output->priv, sizeof(output->priv));

    // Get public key
    const EC_GROUP *group = EC_KEY_get0_group(key);
    const EC_POINT *pub_point = EC_KEY_get0_public_key(key);
    unsigned char *pub = NULL;
    output->pubLen = EC_POINT_point2buf(group, pub_point, POINT_CONVERSION_UNCOMPRESSED, &pub, ctx);
    memcpy(output->pub, pub + 1, --output->pubLen);
    OPENSSL_free(pub);

    calculate_address(output->pub, output->pubLen, state, output->address);
}

static int matchesPattern(
    struct Key *key)
{
    static const unsigned char zeros[32] = {};

    // Starts with 5 '0' in hex
    if (memcmp(key->address, zeros, 2) != 0 || (key->address[2] & 0xF0))
        return 0;

    // Ends with 2 '0' in hex
    if (memcmp(key->address + sizeof(key->address) - 1, zeros, 1) != 0)
        return 0;

    // Last 4 nibbles before that are decimals in hex
    for (size_t byte = 1; byte < 3; byte++)
    {
        unsigned char lhs = key->address[sizeof(key->address) - byte - 1]>>4;
        unsigned char rhs = key->address[sizeof(key->address) - byte - 1] & 0x0F;
        if (lhs > 9 || rhs > 9)
            return 0;
    }

    return 1;
}

static void printKey(
    EC_KEY *eckey,
    struct Key *key)
{
    time_t now = time(NULL);
    char szOutput[64] = {};
    snprintf(szOutput, sizeof(szOutput), "keys/%lld.txt", (long long)now);
    FILE *fp = fopen(szOutput, "w");

    fprintf(fp, "Private: ");
    for (size_t ui = 0; ui < sizeof(key->priv); ui++)
        fprintf(fp, "%02hhX", key->priv[ui]);
    fprintf(fp, "\n");

    fprintf(fp, "Public: ");
    for (size_t ui = 0; ui < key->pubLen; ui++)
        fprintf(fp, "%02hhX", key->pub[ui]);
    fprintf(fp, "\n");

    printf("Address: ");
    fprintf(fp, "Address: ");
    for (size_t ui = 0; ui < sizeof(key->address); ui++)
    {
        printf("%02hhX", key->address[ui]);
        fprintf(fp, "%02hhX", key->address[ui]);
    }
    printf("\n");
    fprintf(fp, "\n");

    EC_KEY *dup = EC_KEY_dup(eckey);
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_assign_EC_KEY(pkey, dup);

    unsigned char data[2048] = {};
    unsigned char *p = data;
    size_t len = i2d_PrivateKey(pkey, &p);
    fprintf(fp, "DER: ");
    for (size_t ui = 0; ui < len; ui++)
        fprintf(fp, "%02hhX", data[ui]);
    fprintf(fp, "\n");

    EVP_PKEY_free(pkey);
    fclose(fp);
}

static void *runThread(void *pv)
{
    long threadid = 0;
    memcpy(&threadid, &pv, sizeof(threadid));

    BN_CTX *ctx = BN_CTX_new();
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_secp256k1);

    struct libkeccak_generalised_spec gspec = {};
    libkeccak_generalised_spec_initialise(&gspec);
    struct libkeccak_spec *spec = (struct libkeccak_spec *)&gspec;
    libkeccak_spec_sha3(spec, 256);

	struct libkeccak_state state = {};
    libkeccak_state_initialise(&state, spec);

    size_t ui = 0;
    while (1)
    {
        struct Key wallet = {};
        makeKey(key, ctx, &state, &wallet);

        if (matchesPattern(&wallet))
            printKey(key, &wallet);

        if (threadid == 0 && ++ui % 100000 == 0)
            printf("%zu\n", ui * NUM_THREADS);
    }

    BN_CTX_free(ctx);
    EC_KEY_free(key);
    libkeccak_state_fast_destroy(&state);

    return NULL;
}

int main(int argc, const char **argv)
{
    (void)argc;
    (void)argv;

    printf("Running %d threads.\n", NUM_THREADS);
    for (size_t ui = 0; ui < NUM_THREADS - 1; ui++)
    {
        pthread_t t = 0;
        void *pv = NULL;
        long threadid = (long)ui;
        memcpy(&pv, &threadid, sizeof(threadid));
        pthread_create(&t, NULL, runThread, pv);
        //usleep(100 * 1000);
    }

    runThread((void *)NUM_THREADS);

    return 0;
}
