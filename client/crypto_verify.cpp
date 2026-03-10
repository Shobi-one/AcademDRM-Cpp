#include "crypto_verify.hpp"

#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/err.h>

#if defined(_WIN32) && defined(_MSC_VER)
#include <openssl/applink.c>
#endif

#include <cstdlib>
#include <fstream>
#include <vector>

std::vector<unsigned char> hexToBytes(const std::string& hex) {
    std::vector<unsigned char> bytes;

    for (unsigned int i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        unsigned char byte = (unsigned char)strtol(byteString.c_str(), nullptr, 16);
        bytes.push_back(byte);
    }

    return bytes;
}

bool verifySignature(const std::string& data, const std::string& hexSignature) {
    FILE* pubFile = fopen("public.pem", "r");
    if (!pubFile) return false;

    RSA* rsa = PEM_read_RSA_PUBKEY(pubFile, NULL, NULL, NULL);
    fclose(pubFile);

    if (!rsa) return false;

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)data.c_str(), data.size(), hash);

    std::vector<unsigned char> sig = hexToBytes(hexSignature);

    int result = RSA_verify(
        NID_sha256,
        hash,
        SHA256_DIGEST_LENGTH,
        sig.data(),
        sig.size(),
        rsa
    );

    RSA_free(rsa);

    return result == 1;
}