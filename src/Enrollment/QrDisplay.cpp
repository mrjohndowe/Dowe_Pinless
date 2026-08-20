#include "QrDisplay.h"
#include "third_party/qrcodegen/qrcodegen.hpp"
#include <Windows.h>
#include <stdexcept>
#include <string>

namespace dowe::enrollment {
namespace {
constexpr int kQuietZone = 4;

bool IsDark(const qrcodegen::QrCode& qr, int x, int y) noexcept {
    return x >= 0 && y >= 0 && x < qr.getSize() && y < qr.getSize() && qr.getModule(x, y);
}

WORD CellAttributes(bool topDark, bool bottomDark) noexcept {
    constexpr WORD whiteForeground = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY;
    constexpr WORD whiteBackground = BACKGROUND_RED | BACKGROUND_GREEN | BACKGROUND_BLUE | BACKGROUND_INTENSITY;
    return static_cast<WORD>((topDark ? 0 : whiteForeground) | (bottomDark ? 0 : whiteBackground));
}
} // namespace

void PrintQrCode(std::string_view payload) {
    if (payload.empty() || payload.find('\0') != std::string_view::npos)
        throw std::invalid_argument("QR payload is empty or contains a null byte");

    const std::string text(payload);
    const auto qr = qrcodegen::QrCode::encodeText(text.c_str(), qrcodegen::QrCode::Ecc::MEDIUM);
    HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO info{};
    if (output == INVALID_HANDLE_VALUE || !GetConsoleScreenBufferInfo(output, &info))
        throw std::runtime_error("QR display requires an interactive Windows console");

    const int width = qr.getSize() + (kQuietZone * 2);
    if (info.dwSize.X < width)
        throw std::runtime_error("console is too narrow for the QR code; widen it and retry enrollment");

    const WORD originalAttributes = info.wAttributes;
    const wchar_t upperHalfBlock = L'\x2580';
    DWORD written{};
    for (int y = -kQuietZone; y < qr.getSize() + kQuietZone; y += 2) {
        for (int x = -kQuietZone; x < qr.getSize() + kQuietZone; ++x) {
            SetConsoleTextAttribute(output, CellAttributes(IsDark(qr, x, y), IsDark(qr, x, y + 1)));
            if (!WriteConsoleW(output, &upperHalfBlock, 1, &written, nullptr) || written != 1) {
                SetConsoleTextAttribute(output, originalAttributes);
                throw std::runtime_error("failed to render QR code in the console");
            }
        }
        SetConsoleTextAttribute(output, originalAttributes);
        WriteConsoleW(output, L"\r\n", 2, &written, nullptr);
    }
    SetConsoleTextAttribute(output, originalAttributes);
}

} // namespace dowe::enrollment
