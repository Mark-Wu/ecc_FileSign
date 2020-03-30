//
// Created by parallels on 3/29/20.
//

#include <stdint.h>
#include <openssl/pem.h>
#include <string.h>
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

int ec_sign(EC_KEY *eckey,int curve,uint8_t *hash,uint8_t format,uint8_t *sig, uint32_t *sig_len)
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

    if(format){
        uint8_t bin_r[32],bin_s[32];
        BN_bn2bin(big_r,bin_r);
        BN_bn2bin(big_s,bin_s);
        ec_signature_to_asn1(bin_r,bin_s,sig,sig_len);

    }else{
        BN_bn2bin(big_r,sig);
        BN_bn2bin(big_s,sig + 32);
        *sig_len = 64;
    }
    printf("signature(%d):",*sig_len);
    for (int i = 0; i < *sig_len; ++i) {
        printf("%02x",sig[i]);
    }
    printf("\n");

    cleanup:
    return err;
}


int ec_signature_to_asn1(uint8_t *r ,uint8_t *s, uint8_t *asn1,int32_t *asn1_len)
{
    uint8_t len_r = 32,len_s = 32,total_len;
    uint8_t r_prefix = 0,s_prefix = 0;
    uint8_t *pos = asn1;

    if(!r || !s || !asn1 || !asn1_len)
        return -1;

    if(r[0] >= 0x80){
        r_prefix = 0x01;
        len_r += 1;
    }
    if(s[0] >= 0x80){
        s_prefix = 0x01;
        len_s += 1;
    }
    total_len = len_s + len_r + 4;

    *pos++ = 0x30; //type array
    *pos++ = total_len; //total  length
    *pos++ = 0x02;  // type int
    *pos++ = len_r; // length
    if(r_prefix)
        *pos++ = 0x00;
    memcpy(pos,r,32);
    pos += 32;

    *pos++ = 0x02;  // type int
    *pos++ = len_s; // length
    if(s_prefix)
        *pos++ = 0x00;
    memcpy(pos,s,32);
    pos += 32;

    *asn1_len = pos - asn1;

    return 0;
}


int ec_create_signature(FILE* f_key,const uint8_t *fname,uint8_t *hash,uint8_t format, uint8_t* sig, int* sig_len)
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

    err = ec_sign(eckey, NID_secp256k1, hash,format ,sig, sig_len);

    cleanup:
    if(eckey)
        EC_KEY_free(eckey);
    EVP_PKEY_free(pkey);
    return err;
}
