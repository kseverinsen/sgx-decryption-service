#include <iostream>
#include <fstream>
#include <streambuf>
#include <iomanip> // for std::setw
#include <string>
#include <list>
#include <array>
#include <stdint.h>

#include "base64.h"
#include "json.hpp"

#define SHA256_DIGEST_LENGTH 32

using namespace std;
using json = nlohmann::json;



void _traverse( json::reference j, std::list<string> *list)

{
    // if visting a leaf, add Hash to list and return
    if(j["Hash"] != nullptr){
        list->push_back(j["Hash"].get<std::string>());
        return;
    }
    // else add 'null' to represent a branch
    list->push_back(std::string("null"));   

    // Recursive calls
    _traverse(j["Left"], list);
    _traverse(j["Right"], list);
    
    return;
}


std::list<std::string> flatten_tree(json::reference j)
{
    // list to hold leafs
    std::list<std::string> l;

    _traverse(j, &l);

    return l;
}


int32_t serialize_extension_proof(uint8_t *proof_str, uint8_t *old_tree, uint8_t *new_tree)
{
    // Parse full proof
    json j = json::parse(proof_str);

    std::list<std::string> old_proof, new_proof;
    std::string old_rth, new_rth;

    old_proof = flatten_tree(j.at("/OldProof"_json_pointer));
    new_proof = flatten_tree(j.at("/NewProof"_json_pointer));

    old_rth = j.at("/OldRTH"_json_pointer).get<std::string>();
    new_rth = j.at("/NewRTH"_json_pointer).get<std::string>();

    old_proof.push_front(old_rth);
    new_proof.push_front(new_rth);

    uint32_t buf_len = old_proof.size() + new_proof.size();
    uint8_t *buf = (uint8_t *)malloc(SHA256_DIGEST_LENGTH * buf_len);


    std::cout << "Old RTH: " << old_rth << "\n";
    for (std::string n : old_proof) {
        std::cout << n << ' ';
    }
    std::cout << "Len:" << old_proof.size() << "\n";

    std::cout << "New RTH: " << new_rth << "\n";
    for (std::string n : new_proof) {
        std::cout << n << ' ';
    }
    std::cout << "Len:" << new_proof.size() << "\n";

    return 0;
}




int32_t test_json()
{
    // create a JSON object
    // ifstream infile("app/app_utils/test_sets/extensionEmptyToSize6.JSON");
    // ifstream infile("app/app_utils/test_sets/extensionSize3ToSize8.JSON");
    ifstream infile("app/app_utils/test_sets/extensionSize7ToSize8.JSON");
  

    std::string str((std::istreambuf_iterator<char>(infile)), std::istreambuf_iterator<char>());

    std::cout << "JSON str" << str << '\n';

    uint8_t *old_flat = (uint8_t *)malloc(32 * 2);
    uint8_t *new_flat = (uint8_t *)malloc(32 * 2);

    serialize_extension_proof((uint8_t *) str.c_str(), old_flat, new_flat);
    


    // for (std::string n : new_proof) {
    //     std::cout << n << ' ';
    // }
    // std::cout << '\n';

    // // count elements
    // auto s = j.size();
    // j["size"] = s;

    // // pretty print with indent of 4 spaces
    // std::cout << std::setw(4) << new_proof << ' ';
    
}