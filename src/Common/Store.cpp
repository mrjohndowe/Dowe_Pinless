#include "Store.h"
#include <Windows.h>
#include <ShlObj.h>
#include <sddl.h>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")
namespace dowe::store {
namespace {
constexpr std::uint32_t kFileMagic = 0x31504444; // DDP1
constexpr std::uint32_t kEnvelopeMagic = 0x32504444; // DDP2
constexpr std::uint32_t kMaxEnvelopeBytes = 64 * 1024;
template<class T> void Write(std::ostream& f, const T& v) { f.write(reinterpret_cast<const char*>(&v), sizeof(v)); }
template<class T> void Read(std::istream& f, T& v) { f.read(reinterpret_cast<char*>(&v), sizeof(v)); }
std::wstring SafeName(std::wstring_view value) {
    auto bytes = security::BytesView(reinterpret_cast<const std::uint8_t*>(value.data()), value.size()*sizeof(wchar_t));
    auto hash = security::Sha256(bytes); static constexpr wchar_t hex[] = L"0123456789abcdef";
    std::wstring out; out.reserve(64); for (auto b : hash) { out.push_back(hex[b >> 4]); out.push_back(hex[b & 15]); }
    return out;
}
void ApplyProtectedAcl(const std::wstring& path) {
    PSECURITY_DESCRIPTOR descriptor{};
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:P(A;;FA;;;SY)(A;;FA;;;BA)", SDDL_REVISION_1, &descriptor, nullptr))
        throw std::runtime_error("record ACL creation failed");
    const BOOL secured = SetFileSecurityW(path.c_str(),
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, descriptor);
    LocalFree(descriptor);
    if (!secured) throw std::runtime_error("record ACL application failed");
}
bool ReadPayload(std::istream& f, Record& r) {
    std::uint32_t magic{}, accountChars{}, secretBytes{}, saltBytes{}, recoveryCount{};
    Read(f, magic); Read(f, accountChars); Read(f, secretBytes); Read(f, saltBytes); Read(f, recoveryCount);
    if (magic != kFileMagic || accountChars > 256 || secretBytes > 8192 || saltBytes > 256 || recoveryCount > 32)
        return false;
    r.account.resize(accountChars); r.protectedSecret.resize(secretBytes); r.recoverySalt.resize(saltBytes);
    f.read(reinterpret_cast<char*>(r.account.data()), accountChars*sizeof(wchar_t));
    f.read(reinterpret_cast<char*>(r.protectedSecret.data()), secretBytes);
    f.read(reinterpret_cast<char*>(r.recoverySalt.data()), saltBytes);
    r.recovery.resize(recoveryCount);
    for (auto& e : r.recovery) { f.read(reinterpret_cast<char*>(e.hash.data()), e.hash.size()); std::uint8_t used{}; Read(f, used); e.used = used != 0; }
    Read(f, r.lastAcceptedCounter); Read(f, r.consecutiveFailures); Read(f, r.lockedUntilUnixSeconds);
    return f.good();
}
}
std::wstring DataDirectory() {
    PWSTR base{}; if (FAILED(SHGetKnownFolderPath(FOLDERID_ProgramData, 0, nullptr, &base)))
        throw std::runtime_error("ProgramData unavailable");
    std::filesystem::path path(base); CoTaskMemFree(base); path /= L"Dowe Pinless"; path /= L"Records";
    std::filesystem::create_directories(path);

    // Enrollment is deliberately an elevated operation.  The service runs as LocalSystem,
    // so the record directory needs no access for ordinary interactive users.  Do not rely
    // on the inherited ProgramData ACL here: it can be changed by local configuration.
    ApplyProtectedAcl(path.wstring());
    return path.wstring();
}
std::wstring RecordPath(std::wstring_view account) {
    return (std::filesystem::path(DataDirectory()) / (SafeName(account) + L".bin")).wstring();
}
bool Load(std::wstring_view account, Record& r) {
    std::ifstream f(RecordPath(account), std::ios::binary); if (!f) return false;
    std::uint32_t magic{}; Read(f, magic);
    if (!f) return false;
    if (magic == kFileMagic) {
        // Legacy records are accepted only for one-way migration. Save() always writes DDP2.
        f.seekg(0, std::ios::beg);
        return ReadPayload(f, r) && _wcsicmp(r.account.c_str(), std::wstring(account).c_str()) == 0;
    }
    if (magic != kEnvelopeMagic) return false;
    std::uint32_t envelopeBytes{}; Read(f, envelopeBytes);
    if (!f || envelopeBytes == 0 || envelopeBytes > kMaxEnvelopeBytes) return false;
    security::Bytes envelope(envelopeBytes); f.read(reinterpret_cast<char*>(envelope.data()), envelope.size());
    if (!f) return false;
    try {
        const auto plaintext = security::UnprotectMachine(envelope);
        std::string payload(reinterpret_cast<const char*>(plaintext.data()), plaintext.size());
        security::SecureClear(envelope.data(), envelope.size());
        auto stream = std::istringstream(payload, std::ios::binary);
        const bool parsed = ReadPayload(stream, r) && stream.peek() == std::char_traits<char>::eof();
        security::SecureClear(payload.data(), payload.size());
        security::SecureClear(const_cast<std::uint8_t*>(plaintext.data()), plaintext.size());
        return parsed && _wcsicmp(r.account.c_str(), std::wstring(account).c_str()) == 0;
    } catch (...) {
        security::SecureClear(envelope.data(), envelope.size());
        return false;
    }
}
void Save(const Record& r) {
    const auto path = RecordPath(r.account), temp = path + L".tmp";
    std::ostringstream payload(std::ios::out | std::ios::binary);
    Write(payload, kFileMagic); auto ac=static_cast<std::uint32_t>(r.account.size()), sb=static_cast<std::uint32_t>(r.protectedSecret.size()),
        ss=static_cast<std::uint32_t>(r.recoverySalt.size()), rc=static_cast<std::uint32_t>(r.recovery.size());
    Write(payload, ac); Write(payload, sb); Write(payload, ss); Write(payload, rc);
    payload.write(reinterpret_cast<const char*>(r.account.data()), ac*sizeof(wchar_t));
    payload.write(reinterpret_cast<const char*>(r.protectedSecret.data()), sb); payload.write(reinterpret_cast<const char*>(r.recoverySalt.data()), ss);
    for (const auto& e : r.recovery) { payload.write(reinterpret_cast<const char*>(e.hash.data()), e.hash.size()); std::uint8_t used=e.used?1:0; Write(payload, used); }
    Write(payload, r.lastAcceptedCounter); Write(payload, r.consecutiveFailures); Write(payload, r.lockedUntilUnixSeconds);
    auto plain = payload.str();
    auto envelope = security::ProtectMachine(security::BytesView(reinterpret_cast<const std::uint8_t*>(plain.data()), plain.size()));
    if (envelope.empty() || envelope.size() > kMaxEnvelopeBytes) throw std::runtime_error("record envelope too large");
    std::ofstream f(temp, std::ios::binary | std::ios::trunc); if (!f) throw std::runtime_error("record open failed");
    Write(f, kEnvelopeMagic); auto bytes=static_cast<std::uint32_t>(envelope.size()); Write(f, bytes);
    f.write(reinterpret_cast<const char*>(envelope.data()), envelope.size());
    f.flush(); if (!f) throw std::runtime_error("record write failed"); f.close();
    ApplyProtectedAcl(temp);
    security::SecureClear(plain.data(), plain.size());
    security::SecureClear(envelope.data(), envelope.size());
    if (!MoveFileExW(temp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        throw std::runtime_error("record commit failed");
}
} // namespace dowe::store
