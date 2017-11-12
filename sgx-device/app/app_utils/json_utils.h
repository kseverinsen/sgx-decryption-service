#ifndef _UNTRUSTED_JSON_H_
#define _UNTRUSTED_JSON_H_


#include <stdio.h>
#include <stdint.h>
#include <list>
#include <string>

#include "json.hpp"

using namespace std;
using json = nlohmann::json;



void _traverse( json::reference j, std::list<string> *list);

int32_t serialize_extension_proof(uint8_t *proof_str, uint8_t *old_tree, uint8_t *new_tree);

int32_t test_json();





#endif