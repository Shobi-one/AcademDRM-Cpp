#include "drm/protected_logic.hpp"
#include "drm/vm/bytecode_compiler.hpp"
#include "drm/hardware_id.hpp"
#include "drm/security/startup_protections.hpp"
#include "drm/vm/virtual_machine.hpp"

#include <cmath>
#include <chrono>
#include <atomic>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#if defined(_WIN32)
#include <windows.h>
#endif

namespace {
constexpr int kWidth = 80;
constexpr int kHeight = 24;
constexpr double kMaxFrames = 800.0;
constexpr bool kUseAesBytecodeEncryption = false;

enum VmRegister : std::size_t {
    REG_ANGLE = 0,
    REG_FRAME = 1,
    REG_MAX_FRAME = 2,
    REG_COUNT = 3
};

enum HostCall : std::size_t {
    HOST_RENDER_FRAME = 0,
    HOST_SLEEP,
    HOST_POLL_STOP
};

std::vector<std::uint8_t> buildRuntimeVmKey() {
    const std::string hardware_id = getHardwareID();

    // Blend static key fragments with machine-specific material.
    static const std::vector<std::uint8_t> kKeyPartA = { 0x21, 0x44, 0x52, 0x4D, 0x6B, 0x39 };
    static const std::vector<std::uint8_t> kKeyPartB = { 0x13, 0xAF, 0x90, 0x55, 0x1C, 0xE2 };

    std::vector<std::uint8_t> key;
    key.reserve(kKeyPartA.size() + kKeyPartB.size() + 8);
    key.insert(key.end(), kKeyPartA.begin(), kKeyPartA.end());
    key.insert(key.end(), kKeyPartB.begin(), kKeyPartB.end());

    std::uint32_t seed = 2166136261u;
    for (char c : hardware_id) {
        seed ^= static_cast<std::uint8_t>(c);
        seed *= 16777619u;
    }

    for (int i = 0; i < 8; ++i) {
        seed ^= static_cast<std::uint32_t>((i + 1) * 0x9E3779B1u);
        seed *= 16777619u;
        key.push_back(static_cast<std::uint8_t>((seed >> ((i % 4) * 8)) & 0xFFu));
    }

    return key;
}

drm::vm::EncryptedBytecodeProgram buildProtectedProgramBytecode(const std::vector<std::uint8_t>& key) {
    static const std::string script =
        "# Mini DSL for DRM VM\n"
        "PUSH 0\n"
        "STORE r0\n"
        "PUSH 0\n"
        "STORE r1\n"
        "PUSH 800\n"
        "STORE r2\n"
        "loop_start:\n"
        "LOAD r1\n"
        "LOAD r2\n"
        "CMP_LT\n"
        "JMP_IF_FALSE end\n"
        "LOAD r0\n"
        "CALL host0\n"
        "CALL host1\n"
        "CALL host2\n"
        "JMP_IF_TRUE end\n"
        "LOAD r0\n"
        "PUSH 0.08\n"
        "ADD\n"
        "STORE r0\n"
        "LOAD r1\n"
        "PUSH 1\n"
        "ADD\n"
        "STORE r1\n"
        "JMP loop_start\n"
        "end:\n"
        "HALT\n";

    const drm::vm::BytecodeProgram bytecode = drm::vm::ScriptBytecodeCompiler::compile(script);

    const drm::vm::EncryptionAlgorithm algorithm = kUseAesBytecodeEncryption
        ? drm::vm::EncryptionAlgorithm::AES_256_CBC
        : drm::vm::EncryptionAlgorithm::XOR;

    return drm::vm::BytecodeEncryption::encrypt(bytecode, key, algorithm);
}

void renderFrame(double angle) {
    const float a = static_cast<float>(angle);
    const float b = static_cast<float>(angle * 0.5);

    std::string output(kWidth * kHeight, ' ');
    float zBuffer[kWidth * kHeight] = { 0.0f };

    for (float j = 0.0f; j < 6.28f; j += 0.07f) {
        for (float i = 0.0f; i < 6.28f; i += 0.02f) {
            float sinA = std::sin(a);
            float cosA = std::cos(a);
            float sinB = std::sin(b);
            float cosB = std::cos(b);
            float sinI = std::sin(i);
            float cosI = std::cos(i);
            float sinJ = std::sin(j);
            float cosJ = std::cos(j);

            float circleX = cosJ + 2.0f;
            float invZ = 1.0f / (sinI * circleX * sinA + sinJ * cosA + 5.0f);
            float circleY = sinI * circleX * cosA - sinJ * sinA;

            int x = static_cast<int>(kWidth / 2 + 30 * invZ * (cosI * circleX * cosB - circleY * sinB));
            int y = static_cast<int>(kHeight / 2 + 15 * invZ * (cosI * circleX * sinB + circleY * cosB));
            int idx = x + kWidth * y;

            int luminance = static_cast<int>(8 * ((sinJ * sinA - sinI * cosJ * cosA) * cosB - sinI * cosJ * sinA - sinJ * cosA - cosI * cosJ * sinB));
            constexpr const char* shades = ".,-~:;=!*#$@";

            if (y >= 0 && y < kHeight && x >= 0 && x < kWidth && invZ > zBuffer[idx]) {
                zBuffer[idx] = invZ;
                int shadeIndex = luminance > 0 ? luminance : 0;
                if (shadeIndex > 11) {
                    shadeIndex = 11;
                }
                output[idx] = shades[shadeIndex];
            }
        }
    }

    std::cout << "\x1b[H";
    for (int row = 0; row < kHeight; ++row) {
        for (int col = 0; col < kWidth; ++col) {
            std::cout << output[row * kWidth + col];
        }
        std::cout << '\n';
    }
    std::cout.flush();
}

void enableVirtualTerminalIfNeeded() {
#if defined(_WIN32)
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut == INVALID_HANDLE_VALUE) {
        return;
    }

    DWORD mode = 0;
    if (!GetConsoleMode(hOut, &mode)) {
        return;
    }

    SetConsoleMode(hOut, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
#endif
}
}

void runProtectedLogic() {
    enableVirtualTerminalIfNeeded();

    drm::security::StartupProtections runtime_protections;
    std::string protection_failure_reason;
    if (!runtime_protections.run(protection_failure_reason)) {
        std::cout << protection_failure_reason << "\n";
        return;
    }

    std::atomic<bool> stopRequested(false);
    std::thread stopListener([&stopRequested]() {
        std::string line;
        std::getline(std::cin, line);
        stopRequested.store(true);
    });

    std::cout << "\x1b[2J";
    std::cout << "Press Enter again to stop the animation.\n";

    drm::vm::VirtualMachine vm(REG_COUNT);
    vm.setHostCallbacks({
        [](drm::vm::VirtualMachine& localVm) {
            renderFrame(localVm.pop());
        },
        [](drm::vm::VirtualMachine&) {
            std::this_thread::sleep_for(std::chrono::milliseconds(25));
        },
        [&stopRequested](drm::vm::VirtualMachine& localVm) {
            localVm.push(stopRequested.load() ? 1.0 : 0.0);
        }
    });
    const std::vector<std::uint8_t> key = buildRuntimeVmKey();
    const drm::vm::EncryptedBytecodeProgram encrypted = buildProtectedProgramBytecode(key);
    const drm::vm::BytecodeProgram decrypted = drm::vm::BytecodeEncryption::decrypt(encrypted, key);
    vm.loadBytecodeProgram(decrypted);

    try {
        vm.run();
    } catch (const std::exception& ex) {
        std::cout << "\nVM execution error: " << ex.what() << "\n";
    }

    if (stopListener.joinable()) {
        stopListener.join();
    }

    std::cout << "\nAnimation stopped.\n";
}
