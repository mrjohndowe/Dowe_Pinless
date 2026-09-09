#include "Observability.h"
#include <sstream>

namespace dowe::observability {
std::string Serialize(const Event& event) {
    if (event.category.empty() || event.result.empty() || !event.secret.empty() ||
        !event.enteredCode.empty() || !event.recoveryCode.empty() || !event.rawPayload.empty())
        return {};
    std::ostringstream output;
    output << "category=" << event.category << ";result=" << event.result
           << ";version=" << event.version << ";correlation=" << event.correlationId
           << ";detail=" << event.detailCode;
    return output.str();
}
}
