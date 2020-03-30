#include <stdio.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/in.h>
#include <err.h>
#include <getopt.h>
#include "sign.h"

#pragma pack(1)
typedef struct {
    uint8_t magic[4]; // "KPOD"
    uint32_t head_len;
    uint32_t expiry;
    uint32_t code_len;
    uint32_t version;
    uint8_t reserved0[12];
    uint8_t hash[32];
    uint8_t rexerved1[896];
    uint8_t signature[64];
} hw_header;
#pragma pack()


char *l_opt_arg;
char* const short_options = "f:t:p:";

struct option long_options[] =
        {
                {"from", 1, NULL, 'f'},
                {"to",1, NULL, 't'},
                {"pem", 1, NULL, 'p'},
                {0, 0, 0, 0},
        };



hw_header* hw_header_init()
{
    hw_header * hd = malloc(sizeof(hw_header));
    memset(hd,0x00, sizeof(hw_header));

    memcpy(hd->magic,"KPOD",4);
    hd->expiry = time(NULL)+ 365*24*3600;
    hd->version = 1;
    hd->head_len = 64;

    return hd;
}

int hw_header_exit(hw_header * hd)
{
    free(hd);

    return 0;
}

static unsigned long get_file_size(const char *filename)
{
    unsigned long size;
    FILE* fp = fopen( filename, "rb" );
    if(fp==NULL)
    {
        printf("ERROR: Open file %s failed.\n", filename);
        return 0;
    }
    fseek( fp, SEEK_SET, SEEK_END );
    size=ftell(fp);
    fclose(fp);
    return size;
}

static int sha256_file(const char *fname, unsigned char *hash,int32_t *hash_len)
{
    int fd;
    int ret,i;
    uint8_t buffer[64] = {0};

    if (fname)
        fd = open(fname, O_RDONLY);

    if (fd < 0) {
        fprintf(stderr, "Can't open file: %s\n", strerror(errno));
        goto out_error;
    }

    EVP_MD_CTX *mdctx;
    mdctx = EVP_MD_CTX_create();

    const EVP_MD *md = EVP_sha256();

    EVP_DigestInit_ex(mdctx, md, NULL);

    while (1) {
        ret = read(fd, buffer, 64);
        if (ret < 0) {
            if (errno == EINTR)
                continue;

            fprintf(stderr, "Unable to read file: %s\n", strerror(errno));
            goto out_error;
        }

        if (ret == 0)
            break;
        EVP_DigestUpdate(mdctx, buffer, ret);
        printf("Digest is: ");
        for(i = 0; i < ret; i++)
            printf("%02x", buffer[i]);
        printf("\n");
    }

    EVP_DigestFinal_ex(mdctx, hash, hash_len);
    EVP_MD_CTX_destroy(mdctx);
    printf("hash is: ");
    for(i = 0; i < *hash_len; i++)
        printf("%02x", hash[i]);
    printf("\n");


    out_error:
        close(fd);
    return 0;
}

static int sha256_header(hw_header *p,uint8_t *hash, uint32_t *hash_len)
{

    EVP_MD_CTX *mdctx;
    uint32_t temp = 0,i = 0;
    mdctx = EVP_MD_CTX_create();
    const EVP_MD *md = EVP_sha256();

    EVP_DigestInit_ex(mdctx, md, NULL);

    EVP_DigestUpdate(mdctx, p->magic, 4);
    temp = htonl(p->head_len);
    EVP_DigestUpdate(mdctx, &temp, 4);
    temp = htonl(p->expiry);
    EVP_DigestUpdate(mdctx,&temp, 4);
    temp = htonl(p->code_len);
    EVP_DigestUpdate(mdctx,&temp, 4);
    temp =htonl(p->version);
    EVP_DigestUpdate(mdctx, &temp, 4);
    EVP_DigestUpdate(mdctx, p->reserved0, 12);
    EVP_DigestUpdate(mdctx, p->hash, 32);
    EVP_DigestFinal_ex(mdctx, hash, hash_len);
    EVP_MD_CTX_destroy(mdctx);
    printf("hd hash is: ");
    for(i = 0; i < *hash_len; i++)
        printf("%02x", hash[i]);
    printf("\n");




}

static int create_signature(unsigned char* hash,uint8_t* pubkey,uint8_t* sig, int* sig_len)
{
    int function_status = -1;
    EC_KEY *eckey=EC_KEY_new();
    if (NULL == eckey)
    {
        printf("Failed to create new EC Key\n");
        function_status = -1;
    }
    else
    {
        EC_GROUP *ecgroup= EC_GROUP_new_by_curve_name(NID_secp256k1);
        if (NULL == ecgroup)
        {
            printf("Failed to create new EC Group\n");
            function_status = -1;
        }
        else
        {
            int set_group_status = EC_KEY_set_group(eckey,ecgroup);
            const int set_group_success = 1;

            if (set_group_success != set_group_status){
                printf("Failed to set group for EC Key\n");
                function_status = -1;
            }

            const int gen_success = 1;
            int gen_status = EC_KEY_generate_key(eckey);
            if (gen_success != gen_status){
                printf("Failed to generate EC Key\n");
                function_status = -1;
            }
            const BIGNUM *big_prikey = EC_KEY_get0_private_key(eckey);
            printf("private key:%s\n",BN_bn2hex(big_prikey));

            const EC_POINT *pubkey = EC_KEY_get0_public_key(eckey);
            BN_CTX *bignum_ctx = BN_CTX_new();
            printf("public  key:%s\n",EC_POINT_point2hex(ecgroup,pubkey,POINT_CONVERSION_COMPRESSED,bignum_ctx));
            printf("public  key:%s\n",EC_POINT_point2hex(ecgroup,pubkey,POINT_CONVERSION_UNCOMPRESSED,bignum_ctx));
            BN_CTX_free(bignum_ctx);

            ECDSA_SIG *signature = ECDSA_do_sign(hash, 32, eckey);
            if (NULL == signature){
                printf("Failed to generate EC Signature\n");
                function_status = -1;
            }
            const BIGNUM *big_r = ECDSA_SIG_get0_r(signature);
            const BIGNUM *big_s = ECDSA_SIG_get0_s(signature);
            printf("sig:(r)%s (s)%s\n",BN_bn2hex(big_r),BN_bn2hex(big_s));
            BN_bn2bin(big_r,sig);
            BN_bn2bin(big_s,sig + 32);
            *sig_len = 64;

            int verify_status = ECDSA_do_verify(hash, strlen(hash), signature, eckey);
            const int verify_success = 1;
            if (verify_success != verify_status)
            {
                printf("Failed to verify EC Signature\n");
                function_status = -1;
            }
            else
            {
                printf("Verifed EC Signature\n");
                function_status = 1;
            }

            EC_GROUP_free(ecgroup);
        }
        EC_KEY_free(eckey);
    }

    return function_status;
}

static int file_signed(const char *from,const char *to, uint8_t * signature,int32_t sig_len)
{
    uint8_t *hardcode = "signature";
    uint8_t sig_type = 0;
    int fd_read = -1;
    int fd_write = -1;
    uint8_t data[128] = {0};
    int read_len = 0,write_len = 0;

    if (from)
        fd_read = open(from, O_RDONLY);
    if (fd_read < 0) {
        fprintf(stderr, "Can't open file: %s\n", strerror(errno));
        return -1;
    }
    if (to)
        fd_write = open(to, O_CREAT|O_RDWR);
    if (fd_write < 0) {
        fprintf(stderr, "Can't open file: %s\n", strerror(errno));
        return -1;
    }

    while (1) {
        read_len = read(fd_read, data, 128);
        if (read_len < 0) {
            if (errno == EINTR)
                continue;
            fprintf(stderr, "Unable to read file: %s\n", strerror(errno));
            goto out_error;
        }
        if (read_len == 0)
            break;

        write_len = write(fd_write, data, read_len);
        if (write_len < 0) {
            if (errno == EINTR)
                continue;
            fprintf(stderr, "Unable to write file: %s\n", strerror(errno));
            goto out_error;
        }
    }
    write_len = write(fd_write, hardcode, strlen(hardcode));
    if (write_len < 0) {
        fprintf(stderr, "Unable to write file: %s\n", strerror(errno));
        goto out_error;
    }
    write_len = write(fd_write, &sig_type, 1);
    if (write_len < 0) {
        fprintf(stderr, "Unable to write file: %s\n", strerror(errno));
        goto out_error;
    }
    write_len = write(fd_write, signature, sig_len);
    if (write_len < 0) {
        fprintf(stderr, "Unable to write file: %s\n", strerror(errno));
        goto out_error;
    }

    out_error:
        if(fd_read)
            close(fd_read);
        if(fd_write)
            close(fd_write);

    return 0;
}

static int new_signed_file(const char *from,const char *to,hw_header *p)
{
    int err = 0;
    int fd_read = -1;
    int fd_write = -1;
    int write_len = 0, read_len = 0;
    uint8_t data[1024] = {0};
    uint32_t temp = 0;

    if (to)
        fd_write = open(to, O_CREAT|O_RDWR);
    if (fd_write < 0) {
        fprintf(stderr, "Can't open file: %s\n", strerror(errno));
        return -1;
    }

    if (from)
        fd_read = open(from, O_RDONLY);
    if (fd_read < 0) {
        fprintf(stderr, "Can't open file: %s\n", strerror(errno));
        return -1;
    }

    write_len = write(fd_write, p->magic, 4);
    if (write_len < 0) {
        fprintf(stderr, "Unable to write file: %s\n", strerror(errno));
        goto out_error;
    }
    temp = htonl(p->head_len);
    write_len = write(fd_write, &temp, 4);
    if (write_len < 0) {
        fprintf(stderr, "Unable to write file: %s\n", strerror(errno));
        goto out_error;
    }
    temp = htonl(p->expiry);
    write_len = write(fd_write, &temp, 4);
    if (write_len < 0) {
        fprintf(stderr, "Unable to write file: %s\n", strerror(errno));
        goto out_error;
    }
    temp = htonl(p->code_len);
    write_len = write(fd_write,&temp, 4);
    if (write_len < 0) {
        fprintf(stderr, "Unable to write file: %s\n", strerror(errno));
        goto out_error;
    }
    temp = htonl(p->version);
    write_len = write(fd_write, &temp, 4);
    if (write_len < 0) {
        fprintf(stderr, "Unable to write file: %s\n", strerror(errno));
        goto out_error;
    }
    write_len = write(fd_write, p->reserved0, 12);
    if (write_len < 0) {
        fprintf(stderr, "Unable to write file: %s\n", strerror(errno));
        goto out_error;
    }
    write_len = write(fd_write, p->hash, 32);
    if (write_len < 0) {
        fprintf(stderr, "Unable to write file: %s\n", strerror(errno));
        goto out_error;
    }
    write_len = write(fd_write,p->rexerved1, 896);
    if (write_len < 0) {
        fprintf(stderr, "Unable to write file: %s\n", strerror(errno));
        goto out_error;
    }
    write_len = write(fd_write, p->signature, 64);
    if (write_len < 0) {
        fprintf(stderr, "Unable to write file: %s\n", strerror(errno));
        goto out_error;
    }
    while (1) {
        read_len = read(fd_read, data, 1024);
        if (read_len < 0) {
            if (errno == EINTR)
                continue;
            fprintf(stderr, "Unable to read file: %s\n", strerror(errno));
            goto out_error;
        }
        if (read_len == 0)
            break;

        write_len = write(fd_write, data, read_len);
        if (write_len < 0) {
            if (errno == EINTR)
                continue;
            fprintf(stderr, "Unable to write file: %s\n", strerror(errno));
            goto out_error;
        }
    }

    out_error:
    if(fd_read)
        close(fd_read);
    if(fd_write)
        close(fd_write);

    return err;
}

int main( int argc , char * argv[] )
{
    int err = 0;
    uint8_t hash[32] = {0};
    int hash_len = 0;
    uint8_t pubkey[33] = {0};
    int signature_len = 0;

    uint8_t h_hash[32] = {0};
    int h_hash_len = 0;

    const char *fd_from = NULL;
    const char *fd_to = NULL;
    const char *fpem = NULL;
    FILE  *f_key = NULL;


    int c;
    while((c = getopt_long(argc, argv, short_options, long_options, NULL)) != -1)
    {
        switch (c)
        {
            case 'f':
                fd_from = optarg;
                printf("file to be signing: %s.\n",fd_from);
                break;
            case 't':
                fd_to = optarg;
                printf("file signed : %s.\n",fd_to);
                break;
            case 'p':
                fpem = optarg;
                printf("Our love is %s.\n", fpem);
                break;
            default:
                printf("help:\n\t");
                printf("FileSign -f test.bin -t test_signed.bin -p key.pem \n");
                break;
        }
    }



    f_key = fopen(fpem,"a+");
    if(f_key == NULL){
        warnx("open %s err\n",fpem);
        return -1;
    }

    hw_header * p= hw_header_init();

    sha256_file(fd_from,hash,&hash_len);

    memcpy(p->hash,hash,hash_len);

    p->code_len = get_file_size(fd_from);

    sha256_header(p,h_hash,&h_hash_len);

    err = ec_create_signature(f_key,fpem,h_hash,0x01,p->signature,&signature_len); //asn1 dec encode
    if(err < 0)
        goto cleanup;

    new_signed_file(fd_from,fd_to,p);

    cleanup:
    hw_header_exit(p);
    if(f_key != NULL)
        fclose(f_key);
    return  0;
}