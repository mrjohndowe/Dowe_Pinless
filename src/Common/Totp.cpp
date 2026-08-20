#include "Totp.h"
#include <Windows.h>
#include <bcrypt.h>
#include <array>
#include <chrono>
#include <cstdio>
#include <stdexcept>

namespace dowe::totp {
std::wstring Generate(security::BytesView secret, std::uint64_t counter) {
    std::array<std::uint8_t, 8> message{};
    for (int i = 7; i >= 0; --i) { message[i] = static_cast<std::uint8_t>(counter); counter >>= 8; }
    BCRYPT_ALG_HANDLE alg{}; BCRYPT_HASH_HANDLE hash{}; DWORD objectSize = 0, actual = 0;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA1_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG) < 0 ||
        BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectSize),
                          sizeof(objectSize), &actual, 0) < 0) throw std::runtime_error("HMAC init failed");
    security::Bytes object(objectSize); std::array<std::uint8_t, 20> digest{};
    NTSTATUS status = BCryptCreateHash(alg, &hash, object.data(), objectSize,
        const_cast<PUCHAR>(secret.data()), static_cast<ULONG>(secret.size()), 0);
    if (status >= 0) status = BCryptHashData(hash, message.data(), static_cast<ULONG>(message.size()), 0);
    if (status >= 0) status = BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0);
    if (hash) BCryptDestroyHash(hash); BCryptCloseAlgorithmProvider(alg, 0);
    security::SecureClear(object.data(), object.size());
    if (status < 0) throw std::runtime_error("HMAC-SHA1 failed");
    const int offset = digest.back() & 0x0f;
    const std::uint32_t binary = ((digest[offset] & 0x7f) << 24) |
        (digest[offset + 1] << 16) | (digest[offset + 2] << 8) | digest[offset + 3];
    wchar_t output[7]{}; swprintf_s(output, L"%06u", binary % 1000000);
    security::SecureClear(digest.data(), digest.size()); return output;
}

bool ParseSixDigits(std::wstring_view text, std::array<std::uint8_t, 6>& digits) noexcept {
    if (text.size() != digits.size()) return false;
    for (std::size_t i = 0; i < digits.size(); ++i) {
        if (text[i] < L'0' || text[i] > L'9') return false;
        digits[i] = static_cast<std::uint8_t>(text[i] - L'0');
    }
    return true;
}
std::uint64_t CurrentCounter() noexcept {
    using namespace std::chrono;
    return duration_cast<seconds>(system_clock::now().time_since_epoch()).count() / kPeriodSeconds;
}
} // namespace dowe::totp
