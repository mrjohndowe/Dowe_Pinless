#include "Validator.h"
#include "../Common/Protocol.h"
#include <Windows.h>
#include <sddl.h>

#pragma comment(lib, "advapi32.lib")
namespace {
SERVICE_STATUS_HANDLE statusHandle{}; HANDLE stopEvent{}; dowe::service::Validator validator;
void Report(DWORD state, DWORD error=NO_ERROR) { SERVICE_STATUS s{SERVICE_WIN32_OWN_PROCESS,state,SERVICE_ACCEPT_STOP,error,0,0,0}; if(state==SERVICE_START_PENDING) s.dwControlsAccepted=0; SetServiceStatus(statusHandle,&s); }
void WINAPI Control(DWORD code) {
    if(code==SERVICE_CONTROL_STOP){
        Report(SERVICE_STOP_PENDING); SetEvent(stopEvent);
        // Wake a blocking ConnectNamedPipe so the server loop can observe stopEvent.
        HANDLE wake=CreateFileW(dowe::ipc::kPipeName,GENERIC_WRITE,0,nullptr,OPEN_EXISTING,0,nullptr);
        if(wake!=INVALID_HANDLE_VALUE){dowe::ipc::Request q{};q.magic=0;DWORD written{};WriteFile(wake,&q,sizeof(q),&written,nullptr);CloseHandle(wake);}
    }
}
DWORD WINAPI ClientThread(void* parameter) {
    HANDLE pipe=static_cast<HANDLE>(parameter); dowe::ipc::Request q{}; DWORD read=0,written=0;
    if(ReadFile(pipe,&q,sizeof(q),&read,nullptr)&&read==sizeof(q)){ auto r=validator.Validate(q); WriteFile(pipe,&r,sizeof(r),&written,nullptr); FlushFileBuffers(pipe); }
    DisconnectNamedPipe(pipe); CloseHandle(pipe); return 0;
}
void RunPipeServer() {
    PSECURITY_DESCRIPTOR sd{};
    // SYSTEM and Administrators full access; authenticated users may read/write the pipe.
    ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)",SDDL_REVISION_1,&sd,nullptr);
    SECURITY_ATTRIBUTES sa{sizeof(sa),sd,FALSE};
    while(WaitForSingleObject(stopEvent,0)!=WAIT_OBJECT_0){
        HANDLE pipe=CreateNamedPipeW(dowe::ipc::kPipeName,PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE|PIPE_READMODE_MESSAGE|PIPE_WAIT|PIPE_REJECT_REMOTE_CLIENTS,16,sizeof(dowe::ipc::Response),sizeof(dowe::ipc::Request),3000,&sa);
        if(pipe==INVALID_HANDLE_VALUE){Sleep(250);continue;}
        BOOL connected=ConnectNamedPipe(pipe,nullptr)?TRUE:(GetLastError()==ERROR_PIPE_CONNECTED);
        if(connected){ HANDLE thread=CreateThread(nullptr,0,ClientThread,pipe,0,nullptr); if(thread) CloseHandle(thread); else CloseHandle(pipe); } else CloseHandle(pipe);
    }
    LocalFree(sd);
}
void WINAPI ServiceMain(DWORD, wchar_t**) {
    statusHandle=RegisterServiceCtrlHandlerW(L"DowePinless",Control); if(!statusHandle)return;
    Report(SERVICE_START_PENDING); stopEvent=CreateEventW(nullptr,TRUE,FALSE,nullptr); if(!stopEvent){Report(SERVICE_STOPPED,GetLastError());return;}
    Report(SERVICE_RUNNING); RunPipeServer(); CloseHandle(stopEvent); Report(SERVICE_STOPPED);
}
}
int wmain(){ SERVICE_TABLE_ENTRYW table[]={{const_cast<LPWSTR>(L"DowePinless"),ServiceMain},{nullptr,nullptr}}; return StartServiceCtrlDispatcherW(table)?0:static_cast<int>(GetLastError()); }
