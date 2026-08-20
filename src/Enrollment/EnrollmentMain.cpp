#include "QrDisplay.h"
#include "../Common/Protocol.h"
#include "../Common/Security.h"
#include "../Common/Store.h"
#include "../Common/Totp.h"
#include <Windows.h>
#include <Lmcons.h>
#include <array>
#include <iostream>
#include <string>
#include <vector>

namespace {

std::wstring CurrentAccount() {
    wchar_t user[UNLEN + 1]{}, computer[MAX_COMPUTERNAME_LENGTH + 1]{};
    DWORD userCharacters = UNLEN + 1, computerCharacters = MAX_COMPUTERNAME_LENGTH + 1;
    if (!GetUserNameW(user, &userCharacters) || !GetComputerNameW(computer, &computerCharacters))
        throw std::runtime_error("identity lookup failed");
    return std::wstring(computer) + L"\\" + user;
}

std::wstring RecoveryCode() {
    auto bytes = dowe::security::RandomBytes(10);
    static constexpr wchar_t alphabet[] = L"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    std::wstring out;
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        if (i == 5) out.push_back(L'-');
        out.push_back(alphabet[bytes[i] & 31]);
    }
    dowe::security::SecureClear(bytes.data(), bytes.size());
    return out;
}

std::string Utf8(std::wstring_view input) {
    if (input.empty()) return {};
    const int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, input.data(),
        static_cast<int>(input.size()), nullptr, 0, nullptr, nullptr);
    if (size <= 0) throw std::runtime_error("UTF-8 conversion failed");
    std::string result(static_cast<std::size_t>(size), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, input.data(),
        static_cast<int>(input.size()), result.data(), size, nullptr, nullptr) != size)
        throw std::runtime_error("UTF-8 conversion failed");
    return result;
}

std::string UriEscape(std::wstring_view input) {
    static constexpr char hex[] = "0123456789ABCDEF";
    const auto utf8 = Utf8(input);
    std::string result;
    result.reserve(utf8.size() * 3);
    for (const unsigned char c : utf8) {
        const bool unreserved = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' || c == '~';
        if (unreserved)
            result.push_back(static_cast<char>(c));
        else {
            result.push_back('%');
            result.push_back(hex[c >> 4]);
            result.push_back(hex[c & 15]);
        }
    }
    return result;
}

std::string OtpAuthUri(std::wstring_view account, std::string_view base32) {
    return "otpauth://totp/" + UriEscape(std::wstring(L"Dowe Pinless:") + std::wstring(account)) +
        "?secret=" + std::string(base32) +
        "&issuer=Dowe%20Pinless&algorithm=SHA1&digits=6&period=30";
}

void ShowManualSetup(std::wstring_view account, std::string_view base32) {
    std::wcout << L"\nManual authenticator setup\n"
               << L"  Issuer:     Dowe Pinless\n"
               << L"  Account:    " << account << L"\n"
               << L"  Secret key: " << std::wstring(base32.begin(), base32.end()) << L"\n"
               << L"  Type:       Time based\n"
               << L"  Algorithm:  SHA-1\n"
               << L"  Digits:     6\n"
               << L"  Period:     30 seconds\n\n";
}

char SetupChoice() {
    std::wcout << L"\nChoose authenticator setup method:\n"
               << L"  1. Show QR code (recommended)\n"
               << L"  2. Show secret key for manual setup\n"
               << L"  3. Show both QR code and secret key\n"
               << L"Selection [1]: ";
    std::wstring input;
    std::getline(std::wcin, input);
    if (input.empty()) return '1';
    if (input == L"1" || input == L"2" || input == L"3") return static_cast<char>(input.front());
    throw std::invalid_argument("setup selection must be 1, 2, or 3");
}

bool ConfirmAuthenticator(dowe::security::BytesView secret) {
    for (int attempt = 1; attempt <= 3; ++attempt) {
        std::wcout << L"Enter the current six-digit code from the newly configured authenticator: ";
        std::wstring code;
        std::getline(std::wcin, code);
        std::array<std::uint8_t, 6> supplied{};
        bool matched = false;
        if (dowe::totp::ParseSixDigits(code, supplied)) {
            const auto current = dowe::totp::CurrentCounter();
            for (int drift = -1; drift <= 1; ++drift) {
                const auto counter = static_cast<std::int64_t>(current) + drift;
                if (counter < 0) continue;
                auto expectedText = dowe::totp::Generate(secret, static_cast<std::uint64_t>(counter));
                std::array<std::uint8_t, 6> expected{};
                dowe::totp::ParseSixDigits(expectedText, expected);
                matched = dowe::security::ConstantTimeEqual(supplied, expected) || matched;
                dowe::security::SecureClear(expected.data(), expected.size());
                dowe::security::SecureClear(expectedText.data(), expectedText.size() * sizeof(wchar_t));
            }
        }
        dowe::security::SecureClear(supplied.data(), supplied.size());
        dowe::security::SecureClear(code.data(), code.size() * sizeof(wchar_t));
        if (matched) return true;
        std::wcerr << L"That code did not match this enrollment (attempt " << attempt << L" of 3).\n";
    }
    return false;
}

int Verify(const std::wstring& account) {
    std::wcout << L"Enter current TOTP or unused recovery code: ";
    std::wstring code;
    std::getline(std::wcin, code);
    dowe::ipc::Request request{};
    dowe::ipc::InitializeRequest(request, dowe::ipc::RequestType::Validate);
    wcsncpy_s(request.account.data(), request.account.size(), account.c_str(), _TRUNCATE);
    wcsncpy_s(request.code.data(), request.code.size(), code.c_str(), _TRUNCATE);
    const auto localDetail = dowe::ipc::InspectRequest(request, dowe::ipc::RequestType::Validate);
    if (localDetail != 0) {
        std::wcerr << L"Local IPC request framing failed (detail 0x" << std::hex << localDetail << L").\n";
        return 4;
    }
    dowe::ipc::Response response{};
    const bool sent = dowe::ipc::SendRequest(request, response);
    dowe::security::SecureClear(code.data(), code.size() * sizeof(wchar_t));
    dowe::security::SecureClear(request.code.data(), request.code.size() * sizeof(wchar_t));
    if (!sent) { std::wcerr << L"Dowe Pinless service is unavailable.\n"; return 2; }
    if (response.result == dowe::ipc::Result::Success) { std::wcout << L"Validation succeeded.\n"; return 0; }
    std::wcerr << L"Validation failed (result " << static_cast<unsigned>(response.result);
    if (response.result == dowe::ipc::Result::BadRequest)
        std::wcerr << L", request detail 0x" << std::hex << response.reserved;
    std::wcerr << L").\n";
    return 3;
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    try {
        const auto account = CurrentAccount();
        if (argc > 1 && _wcsicmp(argv[1], L"--verify") == 0) return Verify(account);

        std::wcout << L"Dowe Pinless enrollment for " << account << L"\n\n"
                   << L"This proof-of-concept does not disable Windows password or PIN providers.\n"
                   << L"The existing enrollment will remain active until the new authenticator is confirmed.\n"
                   << L"Type ENROLL to begin: ";
        std::wstring consent;
        std::getline(std::wcin, consent);
        if (consent != L"ENROLL") { std::wcout << L"Enrollment cancelled.\n"; return 1; }

        auto secret = dowe::security::RandomBytes(20);
        auto base32 = dowe::security::Base32Encode(secret);
        auto uri = OtpAuthUri(account, base32);
        const char choice = SetupChoice();

        if (choice == '1' || choice == '3') {
            std::wcout << L"\nScan this QR code with a standards-compatible authenticator:\n\n";
            dowe::enrollment::PrintQrCode(uri);
            std::wcout << L"\nThe QR code was generated locally; no seed was uploaded or written to an image file.\n";
        }
        if (choice == '2' || choice == '3') ShowManualSetup(account, base32);

        if (!ConfirmAuthenticator(secret)) {
            dowe::security::SecureClear(secret.data(), secret.size());
            dowe::security::SecureClear(base32.data(), base32.size());
            dowe::security::SecureClear(uri.data(), uri.size());
            std::wcerr << L"Enrollment cancelled. The previous Dowe Pinless enrollment was not changed.\n";
            return 3;
        }

        dowe::store::Record record;
        record.account = account;
        record.protectedSecret = dowe::security::ProtectMachine(secret);
        record.recoverySalt = dowe::security::RandomBytes(16);
        std::vector<std::wstring> recovery;
        for (int i = 0; i < 10; ++i) {
            auto code = RecoveryCode();
            record.recovery.push_back({dowe::security::HashRecoveryCode(code, record.recoverySalt), false});
            recovery.push_back(std::move(code));
        }
        dowe::store::Save(record);
        dowe::security::SecureClear(secret.data(), secret.size());
        dowe::security::SecureClear(base32.data(), base32.size());
        dowe::security::SecureClear(uri.data(), uri.size());

        std::wcout << L"\nAuthenticator confirmed. Dowe Pinless enrollment is now active.\n\n"
                   << L"Single-use recovery codes (store offline; they will not be shown again):\n";
        for (const auto& code : recovery) std::wcout << L"  " << code << L"\n";
        std::wcout << L"\nRun DowePinlessEnroll.exe --verify twice with consecutive authenticator codes.\n";
        for (auto& code : recovery)
            dowe::security::SecureClear(code.data(), code.size() * sizeof(wchar_t));
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Dowe Pinless enrollment failed: " << error.what() << "\n";
        return 1;
    }
}
