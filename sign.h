//
// Created by parallels on 3/29/20.
//

#ifndef FILESIGN_SIGN_H
#define FILESIGN_SIGN_H


EVP_PKEY *key_load(FILE *f, const char *fname);

EVP_PKEY *ec_key_create(FILE *f, const char *fname,int ec_curve);

int ec_sign(EVP_PKEY *eckey,int curve,uint8_t *hash,uint8_t *psignature, uint32_t *plen);

#endif //FILESIGN_SIGN_H
