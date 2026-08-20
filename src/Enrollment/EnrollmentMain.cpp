#include "../Common/Protocol.h"
#include "../Common/Security.h"
#include "../Common/Store.h"
#include <Windows.h>
#include <Lmcons.h>
#include <iostream>
#include <iomanip>
#include <sstream>

namespace {
std::wstring CurrentAccount() {
    wchar_t user[UNLEN+1]{}, computer[MAX_COMPUTERNAME_LENGTH+1]{}; DWORD un=UNLEN+1, cn=MAX_COMPUTERNAME_LENGTH+1;
    if(!GetUserNameW(user,&un)||!GetComputerNameW(computer,&cn)) throw std::runtime_error("identity lookup failed");
    return std::wstring(computer)+L"\\"+user;
}
std::wstring RecoveryCode() {
    auto bytes=dowe::security::RandomBytes(10); static constexpr wchar_t alphabet[]=L"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    std::wstring out; for(std::size_t i=0;i<bytes.size();++i){if(i==5)out.push_back(L'-');out.push_back(alphabet[bytes[i]&31]);}
    dowe::security::SecureClear(bytes.data(),bytes.size()); return out;
}
std::wstring UriEscape(std::wstring_view input) {
    std::wostringstream out; out<<std::uppercase<<std::hex;
    for(wchar_t c:input) if((c>=L'a'&&c<=L'z')||(c>=L'A'&&c<=L'Z')||(c>=L'0'&&c<=L'9')||c==L'-'||c==L'.'||c==L'_') out<<c;
        else { auto bytes=std::string(reinterpret_cast<const char*>(&c),reinterpret_cast<const char*>(&c)+sizeof(c)); for(unsigned char b:bytes) if(b) out<<L'%'<<std::setw(2)<<std::setfill(L'0')<<static_cast<int>(b); }
    return out.str();
}
int Verify(const std::wstring& account) {
    std::wcout<<L"Enter current TOTP or unused recovery code: "; std::wstring code; std::getline(std::wcin,code);
    dowe::ipc::Request q{}; wcsncpy_s(q.account.data(),q.account.size(),account.c_str(),_TRUNCATE); wcsncpy_s(q.code.data(),q.code.size(),code.c_str(),_TRUNCATE);
    dowe::ipc::Response r{}; bool sent=dowe::ipc::SendRequest(q,r); dowe::security::SecureClear(code.data(),code.size()*sizeof(wchar_t));
    if(!sent){std::wcerr<<L"Dowe Pinless service is unavailable.\n";return 2;}
    if(r.result==dowe::ipc::Result::Success){std::wcout<<L"Validation succeeded.\n";return 0;}
    std::wcerr<<L"Validation failed (result "<<static_cast<unsigned>(r.result)<<L").\n";return 3;
}
}
int wmain(int argc,wchar_t** argv) {
 try {
    const auto account=CurrentAccount(); if(argc>1&&_wcsicmp(argv[1],L"--verify")==0)return Verify(account);
    std::wcout<<L"Dowe Pinless enrollment for "<<account<<L"\n\n";
    std::wcout<<L"This proof-of-concept does not disable Windows password or PIN providers.\n";
    std::wcout<<L"Type ENROLL to replace any existing Dowe Pinless enrollment: "; std::wstring consent; std::getline(std::wcin,consent);
    if(consent!=L"ENROLL"){std::wcout<<L"Enrollment cancelled.\n";return 1;}
    auto secret=dowe::security::RandomBytes(20); dowe::store::Record record; record.account=account;
    record.protectedSecret=dowe::security::ProtectMachine(secret); record.recoverySalt=dowe::security::RandomBytes(16);
    std::vector<std::wstring> recovery;
    for(int i=0;i<10;++i){auto code=RecoveryCode();record.recovery.push_back({dowe::security::HashRecoveryCode(code,record.recoverySalt),false});recovery.push_back(std::move(code));}
    dowe::store::Save(record); const auto base32=dowe::security::Base32Encode(secret); dowe::security::SecureClear(secret.data(),secret.size());
    std::wcout<<L"\nScan/import this standard authenticator URI (SHA1, 6 digits, 30 seconds):\n\n";
    std::wcout<<L"otpauth://totp/Dowe%20Pinless:"<<UriEscape(account)<<L"?secret="<<std::wstring(base32.begin(),base32.end())<<L"&issuer=Dowe%20Pinless&algorithm=SHA1&digits=6&period=30\n\n";
    std::wcout<<L"Single-use recovery codes (store offline; they will not be shown again):\n";
    for(const auto& code:recovery)std::wcout<<L"  "<<code<<L"\n";
    std::wcout<<L"\nStart the service, then run DowePinlessEnroll.exe --verify twice with consecutive codes.\n";
    for(auto& code:recovery)dowe::security::SecureClear(code.data(),code.size()*sizeof(wchar_t));
    return 0;
 } catch(const std::exception& e){std::cerr<<"Dowe Pinless enrollment failed: "<<e.what()<<"\n";return 1;}
}
