#pragma once

#include <Windows.h>
#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace dowe::security {

using Bytes = std::vector<std::uint8_t>;
using Hash = std::array<std::uint8_t, 32>;

class BytesView {
public:
    BytesView(const std::uint8_t* data, std::size_t size) noexcept : data_(data), size_(size) {}
    template<std::size_t N> BytesView(const std::array<std::uint8_t, N>& value) noexcept : data_(value.data()), size_(N) {}
    BytesView(const Bytes& value) noexcept : data_(value.data()), size_(value.size()) {}
    const std::uint8_t* data() const noexcept { return data_; }
    std::size_t size() const noexcept { return size_; }
    const std::uint8_t* begin() const noexcept { return data_; }
    const std::uint8_t* end() const noexcept { return data_ + size_; }
    std::uint8_t operator[](std::size_t index) const noexcept { return data_[index]; }
private: const std::uint8_t* data_; std::size_t size_;
};

Bytes RandomBytes(std::size_t count);
Bytes ProtectMachine(BytesView plaintext);
Bytes UnprotectMachine(BytesView ciphertext);
Hash Sha256(BytesView value);
Hash HashRecoveryCode(std::wstring_view normalizedCode,
                      BytesView salt);
bool ConstantTimeEqual(BytesView left, BytesView right) noexcept;
void SecureClear(void* value, std::size_t bytes) noexcept;
std::string Base32Encode(BytesView value);
Bytes Base32Decode(std::string_view value);
std::wstring NormalizeRecoveryCode(std::wstring_view value);

} // namespace dowe::security
