#pragma once

#include <string>

namespace ghost_license {

bool check_license_key(const std::string& key);
std::string decode_flag();
bool run_decoy_check(const std::string& key);

}  // namespace ghost_license
