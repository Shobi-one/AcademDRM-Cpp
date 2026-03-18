#include <iostream>
#include <limits>
#include <string>
#include <vector>
#include <cstdlib>

#include "drm/vm/bytecode_compiler.hpp"
#include "drm/license_client.hpp"
#include "drm/crypto_verify.hpp"
#include "drm/hardware_id.hpp"
#include "drm/protected_logic.hpp"
#include "drm/security/startup_protections.hpp"
#include "drm/vm/virtual_machine.hpp"

namespace {
constexpr const char* GREEN = "\033[32m";
constexpr const char* RED = "\033[31m";
constexpr const char* CYAN = "\033[36m";
constexpr const char* YELLOW = "\033[33m";
constexpr const char* RESET = "\033[0m";

bool runStartupDiagnostics() {
    drm::security::AntiDebugDetector anti_debug;
    drm::security::TextSectionIntegrityChecker integrity_checker;

    const bool debugger_detected = anti_debug.detectDebugger();
    const bool text_integrity_ok = integrity_checker.verifyCurrentModuleTextIntegrity();

    std::cout << "\n" << CYAN << "[DRM Diagnostics] Startup Protections" << RESET << "\n";
    const char* anti_color = debugger_detected ? RED : GREEN;
    const char* anti_status = debugger_detected ? "DETECTED" : "CLEAR";
    std::cout << "- Anti-debug detector: " << anti_color << anti_status << RESET << "\n";

    const char* integrity_color = text_integrity_ok ? GREEN : RED;
    const char* integrity_status = text_integrity_ok ? "PASS" : "FAIL";
    std::cout << "- .text integrity check (SHA-256): " << integrity_color << integrity_status << RESET << "\n";

    if (debugger_detected || !text_integrity_ok) {
        std::cout << YELLOW << "Startup protections would block execution under this environment." << RESET << "\n";
        return false;
    }

    return true;
}

bool runVmPipelineSelfTest() {
    static const std::string script =
        "PUSH 40\n"
        "PUSH 2\n"
        "ADD\n"
        "STORE r0\n"
        "LOAD r0\n"
        "PUSH 42\n"
        "CMP_EQ\n"
        "JMP_IF_FALSE fail\n"
        "PUSH 1337\n"
        "CALL host0\n"
        "HALT\n"
        "fail:\n"
        "PUSH -1\n"
        "CALL host0\n"
        "HALT\n";

    std::cout << "\n" << CYAN << "[VM Diagnostics] Compiler -> Encrypt -> Decrypt -> Execute" << RESET << "\n";

    try {
        const drm::vm::BytecodeProgram bytecode = drm::vm::ScriptBytecodeCompiler::compile(script);
        const std::vector<std::uint8_t> key = { 0x21, 0x44, 0x52, 0x4D, 0x13, 0xAF, 0x90, 0x55, 0x1C, 0xE2 };
        const drm::vm::EncryptedBytecodeProgram encrypted =
            drm::vm::BytecodeEncryption::encrypt(bytecode, key, drm::vm::EncryptionAlgorithm::XOR);
        const drm::vm::BytecodeProgram decrypted = drm::vm::BytecodeEncryption::decrypt(encrypted, key);

        drm::vm::VirtualMachine vm(2);
        double result = 0.0;
        vm.setHostCallbacks({
            [&result](drm::vm::VirtualMachine& local_vm) {
                result = local_vm.pop();
            }
        });
        vm.loadBytecodeProgram(decrypted);
        vm.run();

        const bool pass = (result == 1337.0);
        const char* vm_color = pass ? GREEN : RED;
        const char* vm_status = pass ? "PASS" : "FAIL";
        std::cout << "- VM pipeline result: "
              << vm_color << vm_status << RESET << " (value=" << result << ")\n";
        return pass;
    } catch (const std::exception& ex) {
        std::cout << RED << "- VM pipeline error: " << ex.what() << RESET << "\n";
        return false;
    }
}

class ConsoleApp {
public:
    int run() {
        printMenu();

        while (true) {
            std::string input;
            if (!readLine("Select option (m=menu, c=clear, 0=exit): ", input)) {
                std::cout << "\nInput stream closed. Exiting test console.\n";
                return 0;
            }

            if (input == "m" || input == "M") {
                printMenu();
                continue;
            }

            if (input == "c" || input == "C") {
                clearConsole();
                printMenu();
                continue;
            }

            int choice = -1;
            if (!parseChoice(input, choice)) {
                std::cout << RED << "Invalid input. Enter a number, or 'm' to show menu.\n" << RESET;
                continue;
            }

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
        std::cout << "7) Run DRM startup diagnostics (anti-debug + integrity)\n";
        std::cout << "8) Run VM pipeline diagnostics (DSL -> bytecode -> decrypt -> execute)\n";
        std::cout << "9) Run all local diagnostics\n";
        std::cout << "10) Run full DRM journey (startup -> HWID -> license -> unlock)\n";
        std::cout << "0) Exit\n";
    }

    static bool readLine(const std::string& prompt, std::string& out) {
        std::cout << prompt;
        if (!std::getline(std::cin, out)) {
            return false;
        }
        return true;
    }

    static void clearConsole() {
#if defined(_WIN32)
        std::system("cls");
#else
        std::cout << "\033[2J\033[H";
#endif
    }

    static bool parseChoice(const std::string& input, int& choice) {
        const std::size_t first = input.find_first_not_of(" \t\r\n");
        if (first == std::string::npos) {
            return false;
        }

        const std::size_t last = input.find_last_not_of(" \t\r\n");
        const std::string trimmed = input.substr(first, last - first + 1);

        try {
            std::size_t consumed = 0;
            const int value = std::stoi(trimmed, &consumed);
            if (consumed != trimmed.size()) {
                return false;
            }
            choice = value;
            return true;
        } catch (const std::exception&) {
            return false;
        }
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
            case 7:
                runDrmDiagnostics();
                return false;
            case 8:
                runVmDiagnostics();
                return false;
            case 9:
                runAllDiagnostics();
                return false;
            case 10:
                runFullDrmJourney();
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

    void runDrmDiagnostics() const {
        const bool pass = runStartupDiagnostics();
        if (pass) {
            std::cout << GREEN << "[PASS] DRM startup diagnostics succeeded\n" << RESET;
        } else {
            std::cout << RED << "[FAIL] DRM startup diagnostics failed\n" << RESET;
        }
    }

    void runVmDiagnostics() const {
        const bool pass = runVmPipelineSelfTest();
        if (pass) {
            std::cout << GREEN << "[PASS] VM diagnostics succeeded\n" << RESET;
        } else {
            std::cout << RED << "[FAIL] VM diagnostics failed\n" << RESET;
        }
    }

    void runAllDiagnostics() const {
        std::cout << "\n" << CYAN << "==== Full Local Diagnostics ====" << RESET << "\n";
        runShowHardwareId();

        const bool drm_ok = runStartupDiagnostics();
        const bool vm_ok = runVmPipelineSelfTest();

        std::cout << "\n";
        const char* drm_color = drm_ok ? GREEN : RED;
        const char* drm_status = drm_ok ? "PASS" : "FAIL";
        const char* vm_color = vm_ok ? GREEN : RED;
        const char* vm_status = vm_ok ? "PASS" : "FAIL";
        std::cout << "Summary: DRM=" << drm_color << drm_status << RESET
              << ", VM=" << vm_color << vm_status << RESET << "\n";

        if (drm_ok && vm_ok) {
            std::cout << GREEN << "All local diagnostics passed.\n" << RESET;
        } else {
            std::cout << RED << "One or more diagnostics failed.\n" << RESET;
        }
    }

    void runFullDrmJourney() const {
        std::cout << "\n" << CYAN << "==== Full DRM Journey Test ====" << RESET << "\n";
        std::cout << "Using test key: TEST-1234-ABCD\n";

        const bool startup_ok = runStartupDiagnostics();
        const std::string hardware_id = getHardwareID();
        const bool hardware_ok = !hardware_id.empty();
        bool license_ok = false;

        std::cout << "\n" << CYAN << "[DRM Flow] Hardware Binding" << RESET << "\n";
        std::cout << "- Hardware ID: " << (hardware_ok ? hardware_id : std::string("<empty>")) << "\n";

        if (startup_ok && hardware_ok) {
            std::cout << "\n" << CYAN << "[DRM Flow] License Validation" << RESET << "\n";
            license_ok = validateLicense("TEST-1234-ABCD");
        }

        const bool unlock_ok = startup_ok && hardware_ok && license_ok;

        std::cout << "\n" << CYAN << "[DRM Flow] Summary" << RESET << "\n";
        std::cout << "- Startup protections: " << (startup_ok ? GREEN : RED)
            << (startup_ok ? "PASS" : "FAIL") << RESET << "\n";
        std::cout << "- Hardware fingerprint: " << (hardware_ok ? GREEN : RED)
            << (hardware_ok ? "PASS" : "FAIL") << RESET << "\n";
        std::cout << "- License handshake: " << (license_ok ? GREEN : RED)
            << (license_ok ? "PASS" : "FAIL") << RESET << "\n";
        std::cout << "- Content unlock gate: " << (unlock_ok ? GREEN : RED)
            << (unlock_ok ? "PASS" : "FAIL") << RESET << "\n";

        if (!unlock_ok) {
            std::cout << RED << "Full DRM journey failed before protected execution.\n" << RESET;
            return;
        }

        std::string choice;
        if (!readLine("Run protected logic now? (y/N): ", choice)) {
            return;
        }

        if (choice == "y" || choice == "Y") {
            std::cout << GREEN << "DRM checks passed. Launching protected logic...\n" << RESET;
            runProtectedFeature();
        } else {
            std::cout << GREEN << "DRM checks passed. Protected logic launch skipped.\n" << RESET;
        }
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