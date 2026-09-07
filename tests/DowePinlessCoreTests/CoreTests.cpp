#include "../../src/Common/Security.h"
#include "../../src/Common/Totp.h"

#include <array>
#include <iostream>
#include <string>

namespace {

int failures = 0;

void Check(bool condition, const char* name) {
    if (condition) {
        std::cout << "PASS: " << name << "\n";
    } else {
        std::cerr << "FAIL: " << name << "\n";
        ++failures;
    }
}

void TestRfc6238Sha1Vectors() {
    // RFC 6238 Appendix B uses this public HMAC-SHA-1 test key.  Dowe Pinless
    // intentionally emits six digits, so each expected value is the RFC value mod 1,000,000.
    constexpr char key[] = "12345678901234567890";
    const dowe::security::Bytes secret(key, key + sizeof(key) - 1);
    struct Vector { std::uint64_t counter; const wchar_t* expected; };
    constexpr std::array<Vector, 6> vectors{{
        {1, L"287082"},
        {37037036, L"081804"},
        {37037037, L"050471"},
        {41152263, L"005924"},
        {66666666, L"279037"},
        {666666666, L"353130"},
    }};
    for (const auto& vector : vectors) {
        const auto generated = dowe::totp::Generate(secret, vector.counter);
        Check(generated == vector.expected, "RFC 6238 SHA-1 six-digit vector");
    }
}

void TestInputAndRecoveryComparison() {
    std::array<std::uint8_t, 6> valid{};
    std::array<std::uint8_t, 6> invalid{};
    Check(dowe::totp::ParseSixDigits(L"004201", valid), "six-digit TOTP accepts leading zeroes");
    Check(!dowe::totp::ParseSixDigits(L"00420", invalid), "short TOTP is rejected");
    Check(!dowe::totp::ParseSixDigits(L"00420A", invalid), "non-numeric TOTP is rejected");

    const dowe::security::Bytes salt{0x31, 0x78, 0xA4, 0x52, 0x09, 0xCD, 0xE1, 0x7B,
                                     0x2E, 0xB0, 0x45, 0xD8, 0x64, 0x90, 0x1A, 0xFE};
    const auto stored = dowe::security::HashRecoveryCode(L"ABCDE-FGHJK", salt);
    const auto normalized = dowe::security::HashRecoveryCode(L"abcde fghjk", salt);
    const auto different = dowe::security::HashRecoveryCode(L"ABCDE-FGHJL", salt);
    Check(dowe::security::ConstantTimeEqual(stored, normalized), "normalized recovery code matches");
    Check(!dowe::security::ConstantTimeEqual(stored, different), "different recovery code is rejected");
}

} // namespace

int wmain() {
    TestRfc6238Sha1Vectors();
    TestInputAndRecoveryComparison();
    return failures == 0 ? 0 : 1;
}
