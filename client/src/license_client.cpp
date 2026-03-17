#include "drm/license_client.hpp"
#include "drm/hardware_id.hpp"
#include "drm/crypto_verify.hpp"
#include "drm/string_obfuscation.hpp"

#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <iostream>
#include <ctime>
#include <random>
#include <algorithm>
#include <vector>

using json = nlohmann::json;

namespace {
constexpr const char* GREEN = "\033[32m";
constexpr const char* RED = "\033[31m";
constexpr const char* RESET = "\033[0m";
}

static std::string canonicalizeJsonForSignature(const json& value) {
    if (!value.is_object()) {
        return value.dump();
    }

    std::vector<std::string> keys;
    keys.reserve(value.size());

    for (auto it = value.begin(); it != value.end(); ++it) {
        keys.push_back(it.key());
    }

    std::sort(keys.begin(), keys.end());

    json canonical = json::object();
    for (const auto& key : keys) {
        canonical[key] = value.at(key);
    }

    return canonical.dump();
}

static size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* output) {
    output->append((char*)contents, size * nmemb);
    return size * nmemb;
}

std::string generateNonce() {
    std::random_device rd;
    std::uniform_int_distribution<int> dist(0, 15);

    std::string nonce;
    for (int i = 0; i < 16; i++)
        nonce += "0123456789abcdef"[dist(rd)];

    return nonce;
}

bool validateLicense(const std::string& licenseKey) {

    std::string hardware = getHardwareID();
    std::string nonce = generateNonce();
    long timestamp = std::time(nullptr);

    json request = {
        {"license_key", licenseKey},
        {"hardware_id", hardware},
        {"nonce", nonce},
        {"timestamp", timestamp}
    };

    CURL* curl = curl_easy_init();
    if (!curl) return false;

    std::string response;

    const std::string endpoint = drm::obf::decode(
        { 0x35, 0x1E, 0x03, 0xF4, 0xAB, 0xB1, 0x84, 0x89, 0xF7, 0xE5, 0xF1, 0xDC, 0xD7, 0x36, 0x3D, 0x11, 0x17, 0x0F, 0x77, 0x64, 0x51, 0x41, 0x0D, 0xE9, 0xF9, 0xCB, 0xCB, 0xDD, 0xBD, 0xB3 },
        0x5D
    );
    curl_easy_setopt(curl, CURLOPT_URL, endpoint.c_str());
    curl_easy_setopt(curl, CURLOPT_POST, 1L);

    std::string body = request.dump();
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());

    struct curl_slist* headers = NULL;
    const std::string content_type = drm::obf::decode(
        { 0x1E, 0x05, 0x19, 0xF0, 0xF4, 0xF0, 0xDF, 0x95, 0x91, 0xAB, 0xAF, 0x89, 0xC3, 0x26, 0x72, 0x50, 0x5D, 0x56, 0x2E, 0x37, 0x00, 0x1A, 0x12, 0xE7, 0xFB, 0x8D, 0xC5, 0xCF, 0xA6, 0xB8 },
        0x5D
    );
    headers = curl_slist_append(headers, content_type.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        std::cout << RED << "[FAIL] HTTP request failed\n" << RESET;
        return false;
    }

    json jsonResp;
    try {
        jsonResp = json::parse(response);
    } catch (...) {
        std::cout << RED << "[FAIL] Invalid JSON response\n" << RESET;
        return false;
    }

    if (!jsonResp.contains("data") || !jsonResp.contains("signature")) {
        std::cout << RED << "[FAIL] License server returned an error\n" << RESET;
        return false;
    }

    auto payload = jsonResp["data"];
    std::string signature = jsonResp["signature"];

    std::string payloadStr = canonicalizeJsonForSignature(payload);

    if (!verifySignature(payloadStr, signature)) {
        std::cout << RED << "[FAIL] Signature verification failed\n" << RESET;
        return false;
    }

    if (payload["status"] != "valid") {
        std::cout << RED << "[FAIL] License status is invalid\n" << RESET;
        return false;
    }

    if (payload["nonce"] != nonce) {
        std::cout << RED << "[FAIL] Nonce check failed\n" << RESET;
        return false;
    }

    std::cout << GREEN << "[OK] License checks complete\n" << RESET;

    return true;
}