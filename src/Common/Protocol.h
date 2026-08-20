#pragma once

#include <Windows.h>
#include <algorithm>
#include <array>
#include <cstdint>

namespace dowe::ipc {

inline constexpr wchar_t kPipeName[] = LR"(\\.\pipe\DowePinless.Validator.v1)";
inline constexpr std::uint32_t kMagic = 0x45574F44; // "DOWE" little endian
inline constexpr std::uint16_t kVersion = 1;
inline constexpr std::size_t kMaxCodeCharacters = 64;

enum class RequestType : std::uint16_t { Validate = 1, Status = 2 };
enum class Result : std::uint32_t {
    Success = 0,
    Invalid = 1,
    Replay = 2,
    LockedOut = 3,
    NotEnrolled = 4,
    BadRequest = 5,
    InternalError = 6,
};

enum BadRequestDetail : std::uint16_t {
    BadMagic = 1u << 0,
    BadVersion = 1u << 1,
    BadType = 1u << 2,
    EmptyAccount = 1u << 3,
    UnterminatedAccount = 1u << 4,
    EmptyCode = 1u << 5,
    UnterminatedCode = 1u << 6,
};

#pragma pack(push, 1)
struct Request {
    std::uint32_t magic{kMagic};
    std::uint16_t version{kVersion};
    RequestType type{RequestType::Validate};
    std::array<wchar_t, kMaxCodeCharacters> account{}; // SAM-compatible name
    std::array<wchar_t, kMaxCodeCharacters> code{};
};

struct Response {
    std::uint32_t magic{kMagic};
    std::uint16_t version{kVersion};
    std::uint16_t reserved{};
    Result result{Result::InternalError};
    std::uint32_t retryAfterSeconds{};
};
#pragma pack(pop)

static_assert(sizeof(Request) <= 1024);
static_assert(sizeof(Response) == 16);

inline void InitializeRequest(Request& request, RequestType type) noexcept {
    request.magic = kMagic;
    request.version = kVersion;
    request.type = type;
    request.account.fill(L'\0');
    request.code.fill(L'\0');
}

inline std::uint16_t InspectRequest(const Request& request, RequestType expectedType) noexcept {
    std::uint16_t detail{};
    if (request.magic != kMagic) detail |= BadMagic;
    if (request.version != kVersion) detail |= BadVersion;
    if (request.type != expectedType) detail |= BadType;
    if (request.account.front() == L'\0') detail |= EmptyAccount;
    if (std::find(request.account.begin(), request.account.end(), L'\0') == request.account.end()) detail |= UnterminatedAccount;
    if (request.code.front() == L'\0') detail |= EmptyCode;
    if (std::find(request.code.begin(), request.code.end(), L'\0') == request.code.end()) detail |= UnterminatedCode;
    return detail;
}

bool SendRequest(const Request& request, Response& response) noexcept;

} // namespace dowe::ipc
