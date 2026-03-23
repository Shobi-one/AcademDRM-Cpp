#include "license_check.h"

#include <array>
#include <cctype>
#include <cstdint>
#include <string>

namespace ghost_license {
namespace {

constexpr std::array<std::uint8_t, 12> kTransformedTarget = {
    0x2C, 0xC0, 0x3A, 0xFA, 0x08, 0x12, 0xFE, 0x04, 0xD4, 0x68, 0xBE, 0x78};

constexpr std::array<std::uint8_t, 41> kEncodedFlag = {
    0x0F, 0x2B, 0x17, 0x01, 0x45, 0x28, 0x3A, 0x37, 0x0F, 0x10, 0x12, 0x4D,
    0xF3, 0xF7, 0xD9, 0xE5, 0xBD, 0xEC, 0xF7, 0xFB, 0xEB, 0xFE, 0xC1, 0xCC,
    0xD1, 0xCB, 0xDE, 0x9C, 0xD3, 0xDB, 0x85, 0xDA, 0xD7, 0xE0, 0xA0, 0xBC,
    0xB8, 0xFF, 0xBD, 0xA2, 0xA9};

constexpr std::uint16_t kChecksumTarget = 0x1A77;

std::uint8_t rol8(std::uint8_t value, unsigned shift) {
    const unsigned normalized = shift & 7U;
    if (normalized == 0U) {
        return value;
    }
    return static_cast<std::uint8_t>((value << normalized) | (value >> (8U - normalized)));
}

bool has_valid_shape(const std::string& key) {
    if (key.size() != 19U) {
        return false;
    }
    if (key.rfind("GLIC", 0) != 0) {
        return false;
    }
    if (key[4] != '-' || key[9] != '-' || key[14] != '-') {
        return false;
    }

    for (std::size_t i = 5; i < key.size(); ++i) {
        if (key[i] == '-') {
            continue;
        }
        const unsigned char ch = static_cast<unsigned char>(key[i]);
        if (!std::isdigit(ch) && !(ch >= 'A' && ch <= 'Z')) {
            return false;
        }
    }

    return true;
}

std::string extract_payload(const std::string& key) {
    std::string payload;
    payload.reserve(12);

    for (std::size_t i = 5; i < key.size(); ++i) {
        if (key[i] != '-') {
            payload.push_back(key[i]);
        }
    }

    return payload;
}

bool matches_transform(const std::string& payload) {
    if (payload.size() != kTransformedTarget.size()) {
        return false;
    }

    for (std::size_t i = 0; i < payload.size(); ++i) {
        const auto c = static_cast<std::uint8_t>(payload[i]);
        const auto x = static_cast<std::uint8_t>(c ^ static_cast<std::uint8_t>(0x21U + (7U * i)));
        const auto transformed = rol8(x, 1);
        if (transformed != kTransformedTarget[i]) {
            return false;
        }
    }

    return true;
}

std::uint16_t compute_checksum(const std::string& payload) {
    std::uint16_t acc = 0;

    for (std::size_t i = 0; i < payload.size(); ++i) {
        const std::uint16_t c = static_cast<std::uint8_t>(payload[i]);
        const std::uint16_t term = static_cast<std::uint16_t>((c * static_cast<std::uint16_t>(i + 3U)) ^
                                                               static_cast<std::uint16_t>(0x5AU + i));
        acc = static_cast<std::uint16_t>(acc + term);
    }

    return acc;
}

}  // namespace

bool run_decoy_check(const std::string& key) {
    int score = 0;
    for (char ch : key) {
        if (ch == '-') {
            score += 3;
        } else if (ch >= 'A' && ch <= 'Z') {
            score += 2;
        } else if (ch >= '0' && ch <= '9') {
            score += 1;
        }
    }
    return (score % 7) == 0;
}

bool check_license_key(const std::string& key) {
    if (!has_valid_shape(key)) {
        return false;
    }

    const std::string payload = extract_payload(key);
    if (!matches_transform(payload)) {
        return false;
    }

    return compute_checksum(payload) == kChecksumTarget;
}

std::string decode_flag() {
    std::string decoded;
    decoded.reserve(kEncodedFlag.size());

    for (std::size_t i = 0; i < kEncodedFlag.size(); ++i) {
        const auto mask = static_cast<std::uint8_t>(0x5CU + static_cast<std::uint8_t>(3U * i));
        decoded.push_back(static_cast<char>(kEncodedFlag[i] ^ mask));
    }

    return decoded;
}

}  // namespace ghost_license
