//
// Created by parallels on 3/29/20.
//

#include <stdint.h>
#include <openssl/pem.h>
#include <err.h>
#include "sign.h"

EVP_PKEY *ec_key_create(FILE *f, const char *fname,int ec_curve)
{
    EC_KEY		*eckey = NULL;
    EVP_PKEY	*pkey = NULL;

    if ((eckey = EC_KEY_new_by_curve_name(ec_curve)) == NULL ) {
        warnx("EC_KEY_new_by_curve_name");
        goto err;
    }

    if (!EC_KEY_generate_key(eckey)) {
        warnx("EC_KEY_generate_key");
        goto err;
    }

    /* set OPENSSL_EC_NAMED_CURVE to be able to load the key */

    EC_KEY_set_asn1_flag(eckey, OPENSSL_EC_NAMED_CURVE);

    /* Serialise the key to the disc in EC format */

    if (!PEM_write_ECPrivateKey(f, eckey, NULL, NULL, 0, NULL, NULL)) {
        warnx("PEM_write_ECPrivateKey");
        goto err;
    }

    /* Convert the EC key into a PKEY structure */

    if ((pkey=EVP_PKEY_new()) == NULL) {
        warnx("EVP_PKEY_new");
        goto err;
    }
    if (!EVP_PKEY_set1_EC_KEY(pkey, eckey)) {
        warnx("EVP_PKEY_assign_EC_KEY");
        goto err;
    }

    warnx("%s: PEM_write_ECPrivateKey", fname);

    goto out;

    err:
    EC_KEY_free(eckey);
    EVP_PKEY_free(pkey);
    pkey = NULL;
    out:
    return pkey;
}


EVP_PKEY *ec_key_load(FILE *f, const char *fname)
{
    EVP_PKEY	*pkey;
    pkey = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    if (pkey == NULL) {
        return NULL;
    }
    return pkey;
}

int ec_sign(EC_KEY *eckey,int curve,uint8_t *hash,uint8_t *sig, uint32_t *sig_len)
{
    int err = 0;
    EC_GROUP *ecgroup= EC_GROUP_new_by_curve_name(curve);
    const BIGNUM *big_prikey = EC_KEY_get0_private_key(eckey);
    printf("private key:%s\n",BN_bn2hex(big_prikey));

    const EC_POINT *pubkey = EC_KEY_get0_public_key(eckey);
    BN_CTX *bignum_ctx = BN_CTX_new();
    printf("public  key:%s\n",EC_POINT_point2hex(ecgroup,pubkey,POINT_CONVERSION_COMPRESSED,bignum_ctx));
    printf("public  key:%s\n",EC_POINT_point2hex(ecgroup,pubkey,POINT_CONVERSION_UNCOMPRESSED,bignum_ctx));
    BN_CTX_free(bignum_ctx);

    ECDSA_SIG *signature = ECDSA_do_sign(hash,32, eckey);
    if (NULL == signature){
        printf("Failed to generate EC Signature\n");
        err = -1;
        goto cleanup;
    }
    const BIGNUM *big_r = ECDSA_SIG_get0_r(signature);
    const BIGNUM *big_s = ECDSA_SIG_get0_s(signature);
    printf("sig:(r)%s (s)%s\n",BN_bn2hex(big_r),BN_bn2hex(big_s));
    BN_bn2bin(big_r,sig);
    BN_bn2bin(big_s,sig + 32);
    *sig_len = 64;

    cleanup:
    return err;
}


int ec_create_signature(FILE* f_key,const uint8_t *fname,uint8_t *hash, uint8_t* sig, int* sig_len)
{
    int err = 0;
    EVP_PKEY *pkey = NULL;
    EC_KEY *eckey = NULL;

    pkey = ec_key_load(f_key,fname);
    if(pkey == NULL)
    {
        // create new key
        pkey = ec_key_create(f_key,fname,NID_secp256k1);
        if (pkey == NULL){
            err = -1;
            goto cleanup;
        }
    }
    eckey = EVP_PKEY_get1_EC_KEY(pkey);

    err = ec_sign(eckey, NID_secp256k1, hash, sig, sig_len);

    cleanup:
    if(eckey)
        EC_KEY_free(eckey);
    EVP_PKEY_free(pkey);
    return err;
}
