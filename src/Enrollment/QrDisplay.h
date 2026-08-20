#pragma once

#include <string_view>

namespace dowe::enrollment {

// Renders a QR code directly in the interactive Windows console. No image file is created and
// the payload is never sent outside the local process.
void PrintQrCode(std::string_view payload);

} // namespace dowe::enrollment
