#include "Security.h"
#include <bcrypt.h>
#include <dpapi.h>
#include <sddl.h>
#include <stdexcept>
#include <cwctype>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")

namespace dowe::security {
namespace {
[[noreturn]] void WinError(const char* what) { throw std::runtime_error(what); }
}

Bytes RandomBytes(std::size_t count) {
    Bytes out(count);
    if (BCryptGenRandom(nullptr, out.data(), static_cast<ULONG>(out.size()),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) WinError("random generation failed");
    return out;
}

Bytes ProtectMachine(BytesView plaintext) {
    DATA_BLOB in{static_cast<DWORD>(plaintext.size()), const_cast<BYTE*>(plaintext.data())}, out{};
    static const wchar_t description[] = L"Dowe Pinless TOTP secret";
    if (!CryptProtectData(&in, description, nullptr, nullptr, nullptr,
                          CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN, &out))
        WinError("DPAPI protection failed");
    Bytes result(out.pbData, out.pbData + out.cbData);
    SecureZeroMemory(out.pbData, out.cbData);
    LocalFree(out.pbData);
    return result;
}

Bytes UnprotectMachine(BytesView ciphertext) {
    DATA_BLOB in{static_cast<DWORD>(ciphertext.size()), const_cast<BYTE*>(ciphertext.data())}, out{};
    if (!CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr,
                            CRYPTPROTECT_UI_FORBIDDEN, &out)) WinError("DPAPI unprotect failed");
    Bytes result(out.pbData, out.pbData + out.cbData);
    SecureZeroMemory(out.pbData, out.cbData);
    LocalFree(out.pbData);
    return result;
}

Hash Sha256(BytesView value) {
    BCRYPT_ALG_HANDLE algorithm{}; BCRYPT_HASH_HANDLE hash{};
    DWORD objectBytes = 0, actual = 0;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0 ||
        BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
                          reinterpret_cast<PUCHAR>(&objectBytes), sizeof(objectBytes), &actual, 0) < 0)
        WinError("SHA-256 initialization failed");
    Bytes object(objectBytes); Hash result{};
    if (BCryptCreateHash(algorithm, &hash, object.data(), objectBytes, nullptr, 0, 0) < 0 ||
        BCryptHashData(hash, const_cast<PUCHAR>(value.data()), static_cast<ULONG>(value.size()), 0) < 0 ||
        BCryptFinishHash(hash, result.data(), static_cast<ULONG>(result.size()), 0) < 0) {
        if (hash) BCryptDestroyHash(hash); BCryptCloseAlgorithmProvider(algorithm, 0);
        WinError("SHA-256 failed");
    }
    BCryptDestroyHash(hash); BCryptCloseAlgorithmProvider(algorithm, 0);
    SecureClear(object.data(), object.size()); return result;
}

Hash HashRecoveryCode(std::wstring_view code, BytesView salt) {
    const auto normalized = NormalizeRecoveryCode(code);
    Bytes input(salt.begin(), salt.end());
    const auto* p = reinterpret_cast<const std::uint8_t*>(normalized.data());
    input.insert(input.end(), p, p + normalized.size() * sizeof(wchar_t));
    auto result = Sha256(input); SecureClear(input.data(), input.size()); return result;
}

bool ConstantTimeEqual(BytesView a, BytesView b) noexcept {
    std::size_t n = a.size() > b.size() ? a.size() : b.size();
    std::uint8_t diff = static_cast<std::uint8_t>(a.size() ^ b.size());
    for (std::size_t i = 0; i < n; ++i) {
        std::uint8_t av = i < a.size() ? a[i] : 0, bv = i < b.size() ? b[i] : 0;
        diff |= av ^ bv;
    }
    return diff == 0;
}

void SecureClear(void* value, std::size_t bytes) noexcept { if (value && bytes) SecureZeroMemory(value, bytes); }

std::string Base32Encode(BytesView value) {
    static constexpr char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    std::string out; unsigned buffer = 0; int bits = 0;
    for (auto byte : value) { buffer = (buffer << 8) | byte; bits += 8;
        while (bits >= 5) { bits -= 5; out.push_back(alphabet[(buffer >> bits) & 31]); }
    }
    if (bits) out.push_back(alphabet[(buffer << (5 - bits)) & 31]);
    return out;
}

Bytes Base32Decode(std::string_view value) {
    Bytes out; unsigned buffer = 0; int bits = 0;
    for (char c : value) { if (c == '=' || c == ' ' || c == '-') continue;
        c = static_cast<char>(toupper(static_cast<unsigned char>(c)));
        int v = c >= 'A' && c <= 'Z' ? c - 'A' : c >= '2' && c <= '7' ? c - '2' + 26 : -1;
        if (v < 0) throw std::invalid_argument("invalid base32");
        buffer = (buffer << 5) | static_cast<unsigned>(v); bits += 5;
        if (bits >= 8) { bits -= 8; out.push_back(static_cast<std::uint8_t>((buffer >> bits) & 255)); }
    }
    return out;
}

std::wstring NormalizeRecoveryCode(std::wstring_view value) {
    std::wstring out; out.reserve(value.size());
    for (wchar_t c : value) if (iswalnum(c)) out.push_back(static_cast<wchar_t>(towupper(c)));
    return out;
}

std::wstring TokenSidString(HANDLE token) {
    DWORD bytes = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &bytes);
    if (!bytes) WinError("token SID lookup failed");
    Bytes buffer(bytes);
    if (!GetTokenInformation(token, TokenUser, buffer.data(), bytes, &bytes))
        WinError("token SID lookup failed");
    auto* user = reinterpret_cast<const TOKEN_USER*>(buffer.data());
    LPWSTR sid = nullptr;
    if (!ConvertSidToStringSidW(user->User.Sid, &sid)) WinError("SID conversion failed");
    std::wstring result(sid);
    LocalFree(sid);
    return result;
}

std::wstring CurrentUserSidString() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        WinError("current token lookup failed");
    try {
        auto result = TokenSidString(token);
        CloseHandle(token);
        return result;
    } catch (...) { CloseHandle(token); throw; }
}

std::wstring AccountSidString(std::wstring_view account) {
    DWORD sidBytes = 0, domainChars = 0; SID_NAME_USE use{};
    LookupAccountNameW(nullptr, std::wstring(account).c_str(), nullptr, &sidBytes,
                       nullptr, &domainChars, &use);
    if (!sidBytes) WinError("account SID lookup failed");
    Bytes sid(sidBytes); std::wstring domain(domainChars, L'\0');
    if (!LookupAccountNameW(nullptr, std::wstring(account).c_str(), sid.data(), &sidBytes,
                            domain.data(), &domainChars, &use))
        WinError("account SID lookup failed");
    LPWSTR text = nullptr;
    if (!ConvertSidToStringSidW(reinterpret_cast<PSID>(sid.data()), &text))
        WinError("SID conversion failed");
    std::wstring result(text); LocalFree(text); return result;
}
} // namespace dowe::security
