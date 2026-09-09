#include "../../src/Common/Security.h"
#include "../../src/Common/Store.h"
#include "../../src/Common/Totp.h"
#include "../../src/Common/Protocol.h"

#include <array>
#include <iostream>
#include <string>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <Windows.h>
#include <Lmcons.h>

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

void TestDdp2RoundTripAndTamperRejection() {
    dowe::store::Record original;
    original.account = L"Dowe Pinless Core Test " + std::to_wstring(GetCurrentProcessId());
    original.protectedSecret = dowe::security::ProtectMachine(
        dowe::security::Bytes{0x11, 0x22, 0x33, 0x44, 0x55});
    original.recoverySalt = dowe::security::Bytes{0xA1, 0xB2, 0xC3, 0xD4};
    original.lastAcceptedCounter = 123456;
    original.consecutiveFailures = 2;
    original.lockedUntilUnixSeconds = 987654321;
    original.recovery.push_back({dowe::security::HashRecoveryCode(L"TEST-CODE", original.recoverySalt), false});

    const auto path = dowe::store::RecordPath(original.account);
    try {
        dowe::store::Save(original);
        dowe::store::Record loaded;
        Check(dowe::store::Load(original.account, loaded), "DDP2 record round-trip loads");
        Check(loaded.account == original.account &&
              loaded.lastAcceptedCounter == original.lastAcceptedCounter &&
              loaded.recovery.size() == original.recovery.size(),
              "DDP2 record state round-trips");

        auto bytes = std::vector<std::uint8_t>{};
        {
            std::ifstream input(path, std::ios::binary);
            bytes.assign(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
        }
        Check(bytes.size() > 8, "DDP2 record has an envelope");
        if (bytes.size() > 8) {
            bytes.back() ^= 0x01;
            {
                std::ofstream output(path, std::ios::binary | std::ios::trunc);
                output.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
            }
            dowe::store::Record rejected;
            Check(!dowe::store::Load(original.account, rejected), "tampered DDP2 record is rejected");
            dowe::store::Save(original);
            Check(dowe::store::Load(original.account, loaded), "record remains usable after restoration");
        }
    } catch (const std::exception& error) {
        std::cerr << "Storage test error: " << error.what() << "\n";
        ++failures;
    }
    std::error_code ignored;
    std::filesystem::remove(path, ignored);
    dowe::security::SecureClear(original.protectedSecret.data(), original.protectedSecret.size());
}

void TestIpcRejectsMismatchedSid() {
    wchar_t user[UNLEN + 1]{}, computer[MAX_COMPUTERNAME_LENGTH + 1]{};
    DWORD userChars = UNLEN + 1, computerChars = MAX_COMPUTERNAME_LENGTH + 1;
    if (!GetUserNameW(user, &userChars) || !GetComputerNameW(computer, &computerChars)) {
        Check(false, "IPC test identity lookup");
        return;
    }
    dowe::ipc::Request request{};
    dowe::ipc::InitializeRequest(request, dowe::ipc::RequestType::Validate);
    const std::wstring account = std::wstring(computer) + L"\\" + user;
    wcsncpy_s(request.account.data(), request.account.size(), account.c_str(), _TRUNCATE);
    wcsncpy_s(request.code.data(), request.code.size(), L"000000", _TRUNCATE);
    wcsncpy_s(request.sid.data(), request.sid.size(), L"S-1-5-18", _TRUNCATE);
    dowe::ipc::Response response{};
    const bool sent = dowe::ipc::SendRequest(request, response);
    Check(sent && response.result == dowe::ipc::Result::BadRequest,
          "IPC rejects mismatched caller SID");
}

} // namespace

int wmain() {
    TestRfc6238Sha1Vectors();
    TestInputAndRecoveryComparison();
    TestDdp2RoundTripAndTamperRejection();
    wchar_t integration[8]{};
    const auto length = GetEnvironmentVariableW(L"DOWE_PINLESS_RUN_IPC_TEST", integration, _countof(integration));
    if (length > 0 && _wcsicmp(integration, L"1") == 0) {
        TestIpcRejectsMismatchedSid();
    } else {
        std::cout << "SKIP: service-dependent IPC SID test (set DOWE_PINLESS_RUN_IPC_TEST=1)\n";
    }
    return failures == 0 ? 0 : 1;
}
