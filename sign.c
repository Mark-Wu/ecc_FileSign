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


EVP_PKEY *key_load(FILE *f, const char *fname)
{
    EVP_PKEY	*pkey;

    pkey = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    if (pkey == NULL) {
        return NULL;
    }
    return pkey;
}

int ec_sign(EVP_PKEY *eckey,int curve,uint8_t *hash,uint8_t *psignature, uint32_t *plen)
{
    int err = 0;




    return err;
}
