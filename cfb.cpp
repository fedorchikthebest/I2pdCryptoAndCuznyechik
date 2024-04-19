#include"kuznyechik.h"
#include"cfb.h"
#include <string.h>


void kuznechik_cfb(unsigned char *text, unsigned char *out_text, unsigned char *key, unsigned char *iv, unsigned long long int size_in){

    long long int text_size = size_in + (16 - size_in % 16);

    unsigned char in[text_size];
    unsigned char iv_out[16];

    for (int i = 0; i < text_size; i++){
        if (i < size_in) in[i] = text[i];
        else in[i] = 0;
    }

    cppcrypto::kuznyechik encryptor;
    cppcrypto::kuznyechik::direction e;

    encryptor.init(key, e);

    for(int i = 0; i < text_size; i += 16){
        encryptor.encrypt_block(iv, iv_out);
        for (int j = i; j < i + 16; j++){
            out_text[j] = iv_out[j - i] ^ in[j];
        }
        memcpy(iv, &out_text[i], 16);
    }
}