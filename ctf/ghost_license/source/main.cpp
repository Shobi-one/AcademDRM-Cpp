#include "license_check.h"

#include <iostream>
#include <string>

int main() {
    std::cout << "Ghost License Validator v1.3\n";
    std::cout << "Enter license key: ";

    std::string key;
    std::getline(std::cin, key);

    if (ghost_license::run_decoy_check(key)) {
        std::cout << "[legacy] entropy check: passed\n";
    } else {
        std::cout << "[legacy] entropy check: failed\n";
    }

    if (ghost_license::check_license_key(key)) {
        std::cout << "License accepted.\n";
        std::cout << "Flag: " << ghost_license::decode_flag() << "\n";
        return 0;
    }

    std::cout << "License rejected.\n";
    return 1;
}
