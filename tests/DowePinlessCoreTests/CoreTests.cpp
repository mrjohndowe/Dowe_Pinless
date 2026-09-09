#include "../../src/Common/Security.h"
#include "../../src/Common/Store.h"
#include "../../src/Common/Totp.h"
#include "../../src/Common/Protocol.h"
#include "../../src/Common/Observability.h"

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

void TestObservabilityRedaction() {
    dowe::observability::Event safe{"validation-result", "rejected", "0.1", "corr-1", 2};
    const auto serialized = dowe::observability::Serialize(safe);
    Check(!serialized.empty(), "safe observability event serializes");
    Check(serialized.find("corr-1") != std::string::npos, "safe event keeps correlation ID");

    const std::array<std::string, 5> forbidden{{"seed", "123456", "RECOVERY", "dpapi", "pipe"}};
    for (const auto& value : forbidden) {
        auto sensitive = safe;
        sensitive.secret = value;
        Check(dowe::observability::Serialize(sensitive).empty(), "secret-bearing event is rejected");
    }
}

void TestParserHardening() {
    dowe::ipc::Request request{};
    dowe::ipc::InitializeRequest(request, dowe::ipc::RequestType::Validate);
    request.magic = 0;
    request.version = 99;
    request.type = static_cast<dowe::ipc::RequestType>(99);
    const auto detail = dowe::ipc::InspectRequest(request, dowe::ipc::RequestType::Validate);
    Check((detail & dowe::ipc::BadMagic) != 0 && (detail & dowe::ipc::BadVersion) != 0 &&
          (detail & dowe::ipc::BadType) != 0, "malformed IPC header is rejected");

    dowe::ipc::Request fields{};
    dowe::ipc::InitializeRequest(fields, dowe::ipc::RequestType::Validate);
    fields.account.fill(L'A');
    fields.code.fill(L'1');
    fields.sid.fill(L'S');
    const auto unterminated = dowe::ipc::InspectRequest(fields, dowe::ipc::RequestType::Validate);
    Check((unterminated & dowe::ipc::UnterminatedAccount) != 0 &&
          (unterminated & dowe::ipc::UnterminatedCode) != 0 &&
          (unterminated & dowe::ipc::UnterminatedSid) != 0,
          "unterminated IPC fields are rejected");

    fields = {};
    dowe::ipc::InitializeRequest(fields, dowe::ipc::RequestType::Validate);
    fields.account[0] = L'A';
    fields.code[0] = L'1';
    fields.sid[0] = L'S';
    const auto validFields = dowe::ipc::InspectRequest(fields, dowe::ipc::RequestType::Validate);
    Check(validFields == 0, "terminated IPC fields are accepted by framing inspection");
}

void TestIdentityFormats() {
    struct Identity { const wchar_t* account; const wchar_t* sid; };
    constexpr Identity identities[] = {
        {L"TESTMACHINE\\mrjohndowe", L"S-1-5-21-2707993183-3876861637-4217379716-1000"},
        {L"CONTOSO\\alice", L"S-1-5-21-111111111-222222222-333333333-1104"},
        {L"alice@contoso.example", L"S-1-12-1-123456789-234567890-345678901-456789012"}
    };
    for (const auto& identity : identities) {
        dowe::ipc::Request request{};
        dowe::ipc::InitializeRequest(request, dowe::ipc::RequestType::Validate);
        wcsncpy_s(request.account.data(), request.account.size(), identity.account, _TRUNCATE);
        wcsncpy_s(request.code.data(), request.code.size(), L"000000", _TRUNCATE);
        wcsncpy_s(request.sid.data(), request.sid.size(), identity.sid, _TRUNCATE);
        Check(dowe::ipc::InspectRequest(request, dowe::ipc::RequestType::Validate) == 0,
              "local/domain/managed identity framing is accepted");
    }
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

            {
                std::ofstream output(path, std::ios::binary | std::ios::trunc);
                output.write(reinterpret_cast<const char*>(bytes.data()), 5);
            }
            dowe::store::Record truncated;
            Check(!dowe::store::Load(original.account, truncated), "truncated DDP2 record is rejected");
            dowe::store::Save(original);
            Check(dowe::store::Load(original.account, loaded), "known-good record survives truncated replacement");

            const auto temporaryPath = path + L".tmp";
            {
                std::ofstream output(temporaryPath, std::ios::binary | std::ios::trunc);
                output.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size() / 2));
            }
            Check(dowe::store::Load(original.account, loaded), "interrupted temp write does not replace known-good record");
            std::error_code tempIgnored;
            std::filesystem::remove(temporaryPath, tempIgnored);
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
    TestObservabilityRedaction();
    TestParserHardening();
    TestIdentityFormats();
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
