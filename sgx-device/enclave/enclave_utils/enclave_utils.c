#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "enclave_utils.h"
#include "../Enclave.h"
#include "rsa.h"


// Proof verification 

int32_t t_verify_presence(uint8_t *tree, uint8_t *root_hash)
{


}

int32_t t_verify_extension(uint8_t *from_tree, uint8_t *to_tree)
{

}



// Create serialized blob for enclave state
uint8_t* t_serialize_state(struct state_t *state, uint32_t root_hash_len)
{
    uint8_t *buf;
    uint8_t *decrypt_buf;
    uint8_t *signing_buf;

    // Serialize keys using ANS.1 encoding
    decrypt_buf =  t_serialize_private_key(state->decrypt_key);
    uint32_t decrypt_der_len = ((uint32_t *) decrypt_buf)[0]; // retrieve size from first 4 bytes
    uint8_t *decrypt_der = &decrypt_buf[sizeof(uint32_t)]; //align to start of key

    signing_buf =  t_serialize_private_key(state->signing_key);
    uint32_t signing_der_len = ((uint32_t *) signing_buf)[0]; // retrieve size from first 4 bytes
    uint8_t *signing_der = &signing_buf[sizeof(uint32_t)]; //align to start of key

    // Alloctate memory
    uint32_t header_len = sizeof(uint32_t) * HEADER_COUNT; // reserve space for size of the two keys and the root_hash
    uint32_t state_size = header_len + decrypt_der_len + signing_der_len + root_hash_len;
    buf = (uint8_t *) malloc(state_size);

    // store the size of items at the start of the array (typecast as uint32_t)
    uint32_t *uint_ptr = (uint32_t *) buf;
    uint_ptr[DECRYPT_KEY_HEADER]    = decrypt_der_len;
    uint_ptr[SIGNING_KEY_HEADER]    = signing_der_len;
    uint_ptr[ROOT_HASH_HEADER]      = root_hash_len;

    // Copy state to the different offsets in the array
    uint32_t decrypt_key_offset = header_len;
    uint32_t signing_key_offset = header_len + decrypt_der_len;
    uint32_t root_hash_offset 	= header_len + decrypt_der_len + signing_der_len;

    memcpy(&buf[decrypt_key_offset], decrypt_der, decrypt_der_len);
    memcpy(&buf[signing_key_offset], signing_der, signing_der_len);		
    memcpy(&buf[root_hash_offset], state->root_hash, root_hash_len);


    // Checks
    if(memcmp(decrypt_der, &buf[decrypt_key_offset], decrypt_der_len) != 0){
        printf("Serialized state err: decryption key missmatch \n");
        free(buf);
        buf = NULL;
    }
    if(memcmp(signing_der, &buf[signing_key_offset], signing_der_len) != 0){
        printf("Serialized state err: signing key missmatch \n");
        free(buf);
        buf = NULL;
    }
    if(memcmp(state->root_hash, &buf[root_hash_offset], root_hash_len) != 0){
        printf("Serialized state err: shasum missmatch \n");
        free(buf);
        buf = NULL;
    }

    // Free temp buffers
    free(decrypt_buf);
    free(signing_buf);

    return buf;
}

int32_t t_deserialize_state(uint8_t *buf, struct state_t *s)
{
    uint32_t header_len, decrypt_der_len, signing_der_len, root_hash_len;
    uint32_t *uint_ptr = (uint32_t *) buf;

    // Get the sizes from the header fields
    header_len      = sizeof(uint32_t) * HEADER_COUNT;
    decrypt_der_len = uint_ptr[DECRYPT_KEY_HEADER];
    signing_der_len = uint_ptr[SIGNING_KEY_HEADER];
    root_hash_len   = uint_ptr[ROOT_HASH_HEADER];


    // retreive state from the different offsets in the array
    uint32_t decrypt_key_offset = header_len;
    uint32_t signing_key_offset = header_len + decrypt_der_len;
    uint32_t root_hash_offset 	= header_len + decrypt_der_len + signing_der_len;

    s->decrypt_key =  t_deserialize_private_key(&buf[decrypt_key_offset], decrypt_der_len);
    s->signing_key =  t_deserialize_private_key(&buf[signing_key_offset], signing_der_len);
    s->root_hash = &buf[root_hash_offset];
    
    if(!s->decrypt_key || !s->signing_key)
        return -1;
    else
        return 0;
}