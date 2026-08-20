#include "Credential.h"
#include "../Common/Protocol.h"
#include "../Common/Security.h"
#include <combaseapi.h>
#include <shlwapi.h>
#include <propkey.h>
#pragma comment(lib, "shlwapi.lib")

enum FieldId:DWORD{FID_TILE_IMAGE,FID_TITLE,FID_USER,FID_CODE,FID_SUBMIT,FID_STATUS,FID_COUNT};
DoweCredential::DoweCredential()=default; DoweCredential::~DoweCredential(){if(events_)events_->Release();dowe::security::SecureClear(code_.data(),code_.size()*sizeof(wchar_t));}
HRESULT DoweCredential::Initialize(ICredentialProviderUser* user){PWSTR s{},q{};HRESULT hr=user->GetSid(&s);if(SUCCEEDED(hr))hr=user->GetStringValue(PKEY_Identity_QualifiedUserName,&q);if(SUCCEEDED(hr)){sid_=s;qualifiedUser_=q;}CoTaskMemFree(s);CoTaskMemFree(q);return hr;}
HRESULT DoweCredential::QueryInterface(REFIID id,void** out){if(!out)return E_POINTER;*out=nullptr;if(id==IID_IUnknown||id==IID_ICredentialProviderCredential||id==IID_ICredentialProviderCredential2)*out=static_cast<ICredentialProviderCredential2*>(this);else return E_NOINTERFACE;AddRef();return S_OK;}
ULONG DoweCredential::AddRef(){return InterlockedIncrement(&refs_);} ULONG DoweCredential::Release(){ULONG n=InterlockedDecrement(&refs_);if(!n)delete this;return n;}
HRESULT DoweCredential::Advise(ICredentialProviderCredentialEvents* e){if(events_)events_->Release();events_=e;if(events_)events_->AddRef();return S_OK;} HRESULT DoweCredential::UnAdvise(){if(events_){events_->Release();events_=nullptr;}return S_OK;}
HRESULT DoweCredential::SetSelected(BOOL* autoLogon){*autoLogon=FALSE;return S_OK;} HRESULT DoweCredential::SetDeselected(){dowe::security::SecureClear(code_.data(),code_.size()*sizeof(wchar_t));code_.clear();return S_OK;}
HRESULT DoweCredential::GetFieldState(DWORD id,CREDENTIAL_PROVIDER_FIELD_STATE* state,CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* interactive){if(!state||!interactive||id>=FID_COUNT)return E_INVALIDARG;*state=CPFS_DISPLAY_IN_SELECTED_TILE;*interactive=id==FID_CODE?CPFIS_FOCUSED:CPFIS_NONE;if(id==FID_STATUS)*state=CPFS_DISPLAY_IN_SELECTED_TILE;return S_OK;}
HRESULT DoweCredential::GetStringValue(DWORD id,PWSTR* value){if(!value)return E_POINTER;PCWSTR text=L"";switch(id){case FID_TITLE:text=L"Dowe Pinless";break;case FID_USER:text=qualifiedUser_.c_str();break;case FID_CODE:text=code_.c_str();break;case FID_STATUS:text=L"Enter a TOTP or recovery code";break;default:break;}return SHStrDupW(text,value);}
HRESULT DoweCredential::GetBitmapValue(DWORD,HBITMAP*){return E_NOTIMPL;} HRESULT DoweCredential::GetCheckboxValue(DWORD,BOOL*,PWSTR*){return E_NOTIMPL;} HRESULT DoweCredential::GetSubmitButtonValue(DWORD id,DWORD* adjacent){if(id!=FID_SUBMIT||!adjacent)return E_INVALIDARG;*adjacent=FID_CODE;return S_OK;}
HRESULT DoweCredential::GetComboBoxValueCount(DWORD,DWORD*,DWORD*){return E_NOTIMPL;} HRESULT DoweCredential::GetComboBoxValueAt(DWORD,DWORD,PWSTR*){return E_NOTIMPL;}
HRESULT DoweCredential::SetStringValue(DWORD id,PCWSTR value){if(id!=FID_CODE)return E_INVALIDARG;code_=value?value:L"";return S_OK;} HRESULT DoweCredential::SetCheckboxValue(DWORD,BOOL){return E_NOTIMPL;} HRESULT DoweCredential::SetComboBoxSelectedValue(DWORD,DWORD){return E_NOTIMPL;} HRESULT DoweCredential::CommandLinkClicked(DWORD){return E_NOTIMPL;}
HRESULT DoweCredential::GetSerialization(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* response,CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* serialization,PWSTR* status,CREDENTIAL_PROVIDER_STATUS_ICON* icon){
 if(!response||!serialization||!status||!icon)return E_POINTER;*response=CPGSR_NO_CREDENTIAL_NOT_FINISHED;ZeroMemory(serialization,sizeof(*serialization));*icon=CPSI_ERROR;
 dowe::ipc::Request q{};wcsncpy_s(q.account.data(),q.account.size(),qualifiedUser_.c_str(),_TRUNCATE);wcsncpy_s(q.code.data(),q.code.size(),code_.c_str(),_TRUNCATE);dowe::ipc::Response r{};
 bool sent=dowe::ipc::SendRequest(q,r);dowe::security::SecureClear(code_.data(),code_.size()*sizeof(wchar_t));code_.clear();
 PCWSTR message=!sent?L"Dowe Pinless service is unavailable.":r.result==dowe::ipc::Result::Success?L"Dowe Pinless code accepted. POC validation succeeded; use a built-in Windows provider to finish sign-in.":r.result==dowe::ipc::Result::Replay?L"That code was already used.":r.result==dowe::ipc::Result::LockedOut?L"Too many attempts. Wait and try again.":L"The Dowe Pinless code was not accepted.";
 if(r.result==dowe::ipc::Result::Success)*icon=CPSI_SUCCESS;return SHStrDupW(message,status);
}
HRESULT DoweCredential::ReportResult(NTSTATUS,NTSTATUS,PWSTR*,CREDENTIAL_PROVIDER_STATUS_ICON*){return S_OK;} HRESULT DoweCredential::GetUserSid(PWSTR* sid){return sid?SHStrDupW(sid_.c_str(),sid):E_POINTER;}
