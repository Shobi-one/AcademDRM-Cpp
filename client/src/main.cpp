#include <iostream>
#include <limits>
#include <string>

#include "drm/license_client.hpp"
#include "drm/crypto_verify.hpp"
#include "drm/hardware_id.hpp"
#include "drm/protected_logic.hpp"
#include "drm/startup_protections.hpp"

namespace {
constexpr const char* GREEN = "\033[32m";
constexpr const char* RED = "\033[31m";
constexpr const char* CYAN = "\033[36m";
constexpr const char* RESET = "\033[0m";

class ConsoleApp {
public:
    int run() {
        while (true) {
            printMenu();

            int choice = -1;
            if (!(std::cin >> choice)) {
                std::cin.clear();
                std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                std::cout << RED << "Invalid input. Enter a number from the menu.\n" << RESET;
                continue;
            }

            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

            if (dispatchChoice(choice)) {
                return 0;
            }
        }
    }

private:
    void printMenu() const {
        std::cout << "\n" << CYAN << "==== AcademDRM Client Test Console ====\n" << RESET;
        std::cout << "1) Validate default test license\n";
        std::cout << "2) Validate custom license key\n";
        std::cout << "3) Show hardware ID\n";
        std::cout << "4) Verify payload/signature manually\n";
        std::cout << "5) Run protected logic (donut animation)\n";
        std::cout << "6) Validate custom license and run protected logic\n";
        std::cout << "0) Exit\n";
        std::cout << "Select an option: ";
    }

    static bool readLine(const std::string& prompt, std::string& out) {
        std::cout << prompt;
        if (!std::getline(std::cin, out)) {
            return false;
        }
        return true;
    }

    bool dispatchChoice(int choice) {
        switch (choice) {
            case 1:
                runDefaultValidation();
                return false;
            case 2:
                runCustomValidation();
                return false;
            case 3:
                runShowHardwareId();
                return false;
            case 4:
                runManualSignatureVerification();
                return false;
            case 5:
                runProtectedFeature();
                return false;
            case 6:
                runValidateAndProtected();
                return false;
            case 0:
                std::cout << "Exiting test console.\n";
                return true;
            default:
                std::cout << RED << "Unknown option. Try again.\n" << RESET;
                return false;
        }
    }

    void runDefaultValidation() const {
        const std::string license_key = "TEST-1234-ABCD";

        std::cout << "Using default key: " << license_key << "\n";
        if (validateLicense(license_key)) {
            std::cout << GREEN << "[PASS] Default license is valid\n" << RESET;
        } else {
            std::cout << RED << "[FAIL] Default license validation failed\n" << RESET;
        }
    }

    void runCustomValidation() const {
        std::string license_key;
        if (!readLine("Enter license key: ", license_key)) {
            return;
        }

        if (license_key.empty()) {
            std::cout << RED << "License key cannot be empty\n" << RESET;
            return;
        }

        if (validateLicense(license_key)) {
            std::cout << GREEN << "[PASS] License is valid\n" << RESET;
        } else {
            std::cout << RED << "[FAIL] License validation failed\n" << RESET;
        }
    }

    void runShowHardwareId() const {
        const std::string hardware_id = getHardwareID();
        std::cout << "Hardware ID: " << hardware_id << "\n";
    }

    void runManualSignatureVerification() const {
        std::string payload;
        std::string signature;

        if (!readLine("Enter payload string to verify: ", payload)) {
            return;
        }
        if (!readLine("Enter hex signature: ", signature)) {
            return;
        }

        if (payload.empty() || signature.empty()) {
            std::cout << RED << "Payload and signature are required\n" << RESET;
            return;
        }

        if (verifySignature(payload, signature)) {
            std::cout << GREEN << "[PASS] Signature verified\n" << RESET;
        } else {
            std::cout << RED << "[FAIL] Signature verification failed\n" << RESET;
        }
    }

    void runProtectedFeature() const {
        std::cout << "Press Enter to start the protected ASCII donut animation...";
        std::cout.flush();
        std::string ignored;
        std::getline(std::cin, ignored);
        runProtectedLogic();
    }

    void runValidateAndProtected() const {
        std::string license_key;
        if (!readLine("Enter license key: ", license_key)) {
            return;
        }

        if (license_key.empty()) {
            std::cout << RED << "License key cannot be empty\n" << RESET;
            return;
        }

        if (!validateLicense(license_key)) {
            std::cout << RED << "[FAIL] License validation failed, protected logic locked\n" << RESET;
            return;
        }

        std::cout << GREEN << "License valid. Protected logic unlocked.\n" << RESET;
        runProtectedFeature();
    }
};
}

int main() {
    drm::security::StartupProtections protections;
    std::string failure_reason;
    if (!protections.run(failure_reason)) {
        std::cout << RED << failure_reason << "\n" << RESET;
        return 1;
    }

    ConsoleApp app;
    return app.run();
}