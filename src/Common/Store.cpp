#include "Store.h"
#include <Windows.h>
#include <ShlObj.h>
#include <sddl.h>
#include <filesystem>
#include <fstream>
#include <stdexcept>

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")
namespace dowe::store {
namespace {
constexpr std::uint32_t kFileMagic = 0x31504444; // DDP1
template<class T> void Write(std::ofstream& f, const T& v) { f.write(reinterpret_cast<const char*>(&v), sizeof(v)); }
template<class T> void Read(std::ifstream& f, T& v) { f.read(reinterpret_cast<char*>(&v), sizeof(v)); }
std::wstring SafeName(std::wstring_view value) {
    auto bytes = security::BytesView(reinterpret_cast<const std::uint8_t*>(value.data()), value.size()*sizeof(wchar_t));
    auto hash = security::Sha256(bytes); static constexpr wchar_t hex[] = L"0123456789abcdef";
    std::wstring out; out.reserve(64); for (auto b : hash) { out.push_back(hex[b >> 4]); out.push_back(hex[b & 15]); }
    return out;
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
    PSECURITY_DESCRIPTOR descriptor{};
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:P(A;;FA;;;SY)(A;;FA;;;BA)", SDDL_REVISION_1, &descriptor, nullptr))
        throw std::runtime_error("record ACL creation failed");
    const BOOL secured = SetFileSecurityW(path.c_str(),
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, descriptor);
    LocalFree(descriptor);
    if (!secured) throw std::runtime_error("record ACL application failed");
    return path.wstring();
}
std::wstring RecordPath(std::wstring_view account) {
    return (std::filesystem::path(DataDirectory()) / (SafeName(account) + L".bin")).wstring();
}
bool Load(std::wstring_view account, Record& r) {
    std::ifstream f(RecordPath(account), std::ios::binary); if (!f) return false;
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
    return f.good() && _wcsicmp(r.account.c_str(), std::wstring(account).c_str()) == 0;
}
void Save(const Record& r) {
    const auto path = RecordPath(r.account), temp = path + L".tmp";
    std::ofstream f(temp, std::ios::binary | std::ios::trunc); if (!f) throw std::runtime_error("record open failed");
    Write(f, kFileMagic); auto ac=static_cast<std::uint32_t>(r.account.size()), sb=static_cast<std::uint32_t>(r.protectedSecret.size()),
        ss=static_cast<std::uint32_t>(r.recoverySalt.size()), rc=static_cast<std::uint32_t>(r.recovery.size());
    Write(f, ac); Write(f, sb); Write(f, ss); Write(f, rc);
    f.write(reinterpret_cast<const char*>(r.account.data()), ac*sizeof(wchar_t));
    f.write(reinterpret_cast<const char*>(r.protectedSecret.data()), sb); f.write(reinterpret_cast<const char*>(r.recoverySalt.data()), ss);
    for (const auto& e : r.recovery) { f.write(reinterpret_cast<const char*>(e.hash.data()), e.hash.size()); std::uint8_t used=e.used?1:0; Write(f, used); }
    Write(f, r.lastAcceptedCounter); Write(f, r.consecutiveFailures); Write(f, r.lockedUntilUnixSeconds);
    f.flush(); if (!f) throw std::runtime_error("record write failed"); f.close();
    if (!MoveFileExW(temp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        throw std::runtime_error("record commit failed");
}
} // namespace dowe::store
