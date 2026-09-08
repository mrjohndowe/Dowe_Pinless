#pragma once
#include "../Common/Protocol.h"
#include <mutex>
#include <string_view>

namespace dowe::service {
class Validator {
public: ipc::Response Validate(const ipc::Request& request, std::wstring_view callerSid) noexcept;
private: std::mutex mutex_;
};
} // namespace dowe::service
