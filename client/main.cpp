#include <iostream>
#include "license_client.hpp"

int main() {
    std::string license_key = "TEST-1234-ABCD";

    if (!validateLicense(license_key)) {
        std::cout << "License validation failed.\n";
        return 1;
    }

    std::cout << "License valid. Protected logic unlocked.\n";

    // Later this will trigger VM execution
    // runProtectedLogic();

    return 0;
}