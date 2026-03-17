#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace drm::obf {

inline std::string decode(const std::vector<std::uint8_t>& encoded, std::uint8_t key) {
    std::string out;
    out.resize(encoded.size());

    for (std::size_t i = 0; i < encoded.size(); ++i) {
        const std::uint8_t mask = static_cast<std::uint8_t>(key + static_cast<std::uint8_t>((i * 13u) & 0xFFu));
        out[i] = static_cast<char>(encoded[i] ^ mask);
    }

    return out;
}

} // namespace drm::obf
