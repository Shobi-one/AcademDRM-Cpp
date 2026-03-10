#include "drm/protected_logic.hpp"

#include <cmath>
#include <chrono>
#include <atomic>
#include <iostream>
#include <string>
#include <thread>

#if defined(_WIN32)
#include <windows.h>
#endif

namespace {
constexpr int kWidth = 80;
constexpr int kHeight = 24;

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

    std::atomic<bool> stopRequested(false);
    std::thread stopListener([&stopRequested]() {
        std::string line;
        std::getline(std::cin, line);
        stopRequested.store(true);
    });

    float a = 0.0f;
    float b = 0.0f;

    std::cout << "\x1b[2J";
    std::cout << "Press Enter again to stop the animation.\n";

    while (!stopRequested.load()) {
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

        a += 0.04f;
        b += 0.02f;

        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }

    if (stopListener.joinable()) {
        stopListener.join();
    }

    std::cout << "\nAnimation stopped.\n";
}
