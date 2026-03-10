#include "license_client.hpp"
#include "hardware_id.hpp"
#include "crypto_verify.hpp"

#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <iostream>
#include <ctime>
#include <random>
#include <algorithm>
#include <vector>

using json = nlohmann::json;

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

    curl_easy_setopt(curl, CURLOPT_URL, "http://127.0.0.1:5000/validate");
    curl_easy_setopt(curl, CURLOPT_POST, 1L);

    std::string body = request.dump();
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());

    struct curl_slist* headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        std::cout << "HTTP request failed\n";
        return false;
    }

    json jsonResp;
    try {
        jsonResp = json::parse(response);
    } catch (...) {
        std::cout << "Invalid JSON response\n";
        return false;
    }

    if (!jsonResp.contains("data") || !jsonResp.contains("signature")) {
        std::cout << "License server returned an error\n";
        return false;
    }

    auto payload = jsonResp["data"];
    std::string signature = jsonResp["signature"];

    std::string payloadStr = canonicalizeJsonForSignature(payload);

    if (!verifySignature(payloadStr, signature)) {
        std::cout << "Signature verification failed\n";
        return false;
    }

    if (payload["status"] != "valid")
        return false;

    if (payload["nonce"] != nonce)
        return false;

    return true;
}