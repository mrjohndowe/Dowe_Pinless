#pragma once

#include <Windows.h>
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

bool SendRequest(const Request& request, Response& response) noexcept;

} // namespace dowe::ipc
