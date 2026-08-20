#pragma once
#include "Security.h"
#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace dowe::store {
struct RecoveryEntry { security::Hash hash{}; bool used{}; };
struct Record {
    std::wstring account;
    security::Bytes protectedSecret;
    security::Bytes recoverySalt;
    std::vector<RecoveryEntry> recovery;
    std::int64_t lastAcceptedCounter{-1};
    std::uint32_t consecutiveFailures{};
    std::uint64_t lockedUntilUnixSeconds{};
};

std::wstring DataDirectory();
std::wstring RecordPath(std::wstring_view account);
bool Load(std::wstring_view account, Record& record);
void Save(const Record& record);
} // namespace dowe::store
