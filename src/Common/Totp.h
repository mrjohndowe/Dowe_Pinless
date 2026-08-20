#pragma once
#include "Security.h"
#include <cstdint>
#include <string>

namespace dowe::totp {
inline constexpr std::uint64_t kPeriodSeconds = 30;
inline constexpr int kDigits = 6;
std::wstring Generate(security::BytesView secret, std::uint64_t counter);
bool ParseSixDigits(std::wstring_view text, std::array<std::uint8_t, 6>& digits) noexcept;
std::uint64_t CurrentCounter() noexcept;
} // namespace dowe::totp
