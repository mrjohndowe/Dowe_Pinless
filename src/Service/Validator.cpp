#include "Validator.h"
#include "../Common/Security.h"
#include "../Common/Store.h"
#include "../Common/Totp.h"
#include <chrono>

namespace dowe::service {
namespace {
std::uint64_t UnixNow() { using namespace std::chrono; return duration_cast<seconds>(system_clock::now().time_since_epoch()).count(); }
void Failure(store::Record& r) {
    if (++r.consecutiveFailures >= 5) { r.lockedUntilUnixSeconds = UnixNow() + 30; r.consecutiveFailures = 0; }
    store::Save(r);
}
}
ipc::Response Validator::Validate(const ipc::Request& q) noexcept {
    ipc::Response out{};
    try {
        if (q.magic != ipc::kMagic || q.version != ipc::kVersion || q.type != ipc::RequestType::Validate ||
            q.account.back() != 0 || q.code.back() != 0 || q.account.front() == 0 || q.code.front() == 0) {
            out.result=ipc::Result::BadRequest; return out;
        }
        std::scoped_lock lock(mutex_); store::Record r;
        const std::wstring account(q.account.data()), code(q.code.data());
        if (!store::Load(account, r)) { out.result=ipc::Result::NotEnrolled; return out; }
        auto now=UnixNow(); if (r.lockedUntilUnixSeconds > now) { out.result=ipc::Result::LockedOut; out.retryAfterSeconds=static_cast<std::uint32_t>(r.lockedUntilUnixSeconds-now); return out; }
        std::array<std::uint8_t,6> supplied{};
        if (totp::ParseSixDigits(code, supplied)) {
            auto secret=security::UnprotectMachine(r.protectedSecret); const auto current=totp::CurrentCounter();
            bool matched=false, replay=false; std::int64_t accepted=-1;
            for (int drift=-1; drift<=1; ++drift) {
                const auto counter=static_cast<std::int64_t>(current)+drift; if (counter < 0) continue;
                auto expectedText=totp::Generate(secret, static_cast<std::uint64_t>(counter)); std::array<std::uint8_t,6> expected{};
                totp::ParseSixDigits(expectedText, expected);
                if (security::ConstantTimeEqual(supplied, expected)) { matched=true; accepted=counter; replay=counter<=r.lastAcceptedCounter; }
                security::SecureClear(expected.data(), expected.size()); security::SecureClear(expectedText.data(), expectedText.size()*sizeof(wchar_t));
            }
            security::SecureClear(secret.data(), secret.size()); security::SecureClear(supplied.data(), supplied.size());
            if (matched && replay) { Failure(r); out.result=ipc::Result::Replay; return out; }
            if (matched) { r.lastAcceptedCounter=accepted; r.consecutiveFailures=0; r.lockedUntilUnixSeconds=0; store::Save(r); out.result=ipc::Result::Success; return out; }
        }
        const auto candidate=security::HashRecoveryCode(code, r.recoverySalt); int match=-1;
        for (std::size_t i=0;i<r.recovery.size();++i) if (security::ConstantTimeEqual(candidate,r.recovery[i].hash) && !r.recovery[i].used) match=static_cast<int>(i);
        if (match>=0) { r.recovery[match].used=true; r.consecutiveFailures=0; store::Save(r); out.result=ipc::Result::Success; return out; }
        Failure(r); out.result=ipc::Result::Invalid; return out;
    } catch (...) { out.result=ipc::Result::InternalError; return out; }
}
} // namespace dowe::service
