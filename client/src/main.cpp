#include <iostream>
#include "drm/license_client.hpp"

namespace {
constexpr const char* GREEN = "\033[32m";
constexpr const char* RED = "\033[31m";
constexpr const char* RESET = "\033[0m";
}

int main() {
    std::string license_key = "TEST-1234-ABCD";

    if (!validateLicense(license_key)) {
        std::cout << RED << "License validation failed.\n" << RESET;
        return 1;
    }

    std::cout << GREEN << "License valid. Protected logic unlocked.\n" << RESET;

    // Later this will trigger VM execution
    // runProtectedLogic();

    return 0;
}