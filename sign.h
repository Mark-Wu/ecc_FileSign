//
// Created by parallels on 3/29/20.
//

#ifndef FILESIGN_SIGN_H
#define FILESIGN_SIGN_H


EVP_PKEY *ec_key_load(FILE *f, const char *fname);

EVP_PKEY *ec_key_create(FILE *f, const char *fname,int ec_curve);

int ec_sign(EC_KEY *eckey,int curve,uint8_t *hash,uint8_t format,uint8_t *sig, uint32_t *sig_len);

int ec_signature_to_asn1(uint8_t *r ,uint8_t *s, uint8_t *asn1,int32_t *asn1_len);

int ec_create_signature(FILE* f_key,const uint8_t *fname,uint8_t *hash,uint8_t format,uint8_t* sig, int* sig_len);

#endif //FILESIGN_SIGN_H
