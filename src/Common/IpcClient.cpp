#include "Protocol.h"

namespace dowe::ipc {

bool SendRequest(const Request& request, Response& response) noexcept {
    if (!WaitNamedPipeW(kPipeName, 3000)) return false;
    HANDLE pipe = CreateFileW(kPipeName, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) return false;
    DWORD mode = PIPE_READMODE_MESSAGE;
    bool ok = SetNamedPipeHandleState(pipe, &mode, nullptr, nullptr) != FALSE;
    DWORD written = 0, read = 0;
    ok = ok && WriteFile(pipe, &request, sizeof(request), &written, nullptr) &&
         written == sizeof(request);
    ok = ok && ReadFile(pipe, &response, sizeof(response), &read, nullptr) &&
         read == sizeof(response);
    CloseHandle(pipe);
    return ok && response.magic == kMagic && response.version == kVersion;
}

} // namespace dowe::ipc
