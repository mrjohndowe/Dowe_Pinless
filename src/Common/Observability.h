#pragma once

#include <cstdint>
#include <string>

namespace dowe::observability {
struct Event {
    std::string category;
    std::string result;
    std::string version;
    std::string correlationId;
    std::uint32_t detailCode{};
    std::string secret;
    std::string enteredCode;
    std::string recoveryCode;
    std::string rawPayload;
};

// Returns an allowlisted, non-secret serialization. Empty means the event is rejected.
std::string Serialize(const Event& event);
}
