#ifndef ENCLAVE_UTILS_H_   /* Include guard */
#define ENCLAVE_UTILS_H_

#include <stdint.h>
#include "../Enclave.h"

// Header counts and locations in a serialized state array
#define HEADER_COUNT 3
enum HEADER_SIZE_OFFSETS {
    DECRYPT_KEY_HEADER = 0,
    SIGNING_KEY_HEADER,
    ROOT_HASH_HEADER
};


// Proof verification 
int32_t t_verify_presence(uint8_t *tree, uint8_t *root_hash);

int32_t t_verify_extension(uint8_t *from_tree, uint8_t *to_tree);


// State serialization

uint8_t* t_serialize_state(struct state_t *state, uint32_t rhash_len);

int32_t t_deserialize_state(uint8_t *buf, struct state_t *s);


#endif