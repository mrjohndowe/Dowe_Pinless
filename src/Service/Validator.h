#pragma once
#include "../Common/Protocol.h"
#include <mutex>

namespace dowe::service {
class Validator {
public: ipc::Response Validate(const ipc::Request& request) noexcept;
private: std::mutex mutex_;
};
} // namespace dowe::service
