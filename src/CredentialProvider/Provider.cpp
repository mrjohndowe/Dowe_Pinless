#include "Provider.h"
#include <shlwapi.h>

namespace {
const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR fields[]={{0,CPFT_TILE_IMAGE,const_cast<PWSTR>(L"Dowe Pinless"),GUID_NULL},{1,CPFT_LARGE_TEXT,const_cast<PWSTR>(L"Dowe Pinless"),GUID_NULL},{2,CPFT_SMALL_TEXT,const_cast<PWSTR>(L"Account"),GUID_NULL},{3,CPFT_PASSWORD_TEXT,const_cast<PWSTR>(L"TOTP or recovery code"),GUID_NULL},{4,CPFT_SUBMIT_BUTTON,const_cast<PWSTR>(L"Validate"),GUID_NULL},{5,CPFT_SMALL_TEXT,const_cast<PWSTR>(L"Status"),GUID_NULL}};
HRESULT CopyField(const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR& source,CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** out){auto p=static_cast<CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*>(CoTaskMemAlloc(sizeof(CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR)));if(!p)return E_OUTOFMEMORY;*p=source;p->pszLabel=nullptr;HRESULT hr=SHStrDupW(source.pszLabel,&p->pszLabel);if(FAILED(hr)){CoTaskMemFree(p);return hr;}*out=p;return S_OK;}
}
DoweProvider::~DoweProvider(){if(users_)users_->Release();if(credential_)credential_->Release();}
HRESULT DoweProvider::QueryInterface(REFIID id,void** out){if(!out)return E_POINTER;*out=nullptr;if(id==IID_IUnknown||id==IID_ICredentialProvider)*out=static_cast<ICredentialProvider*>(this);else if(id==IID_ICredentialProviderSetUserArray)*out=static_cast<ICredentialProviderSetUserArray*>(this);else return E_NOINTERFACE;AddRef();return S_OK;}
ULONG DoweProvider::AddRef(){return InterlockedIncrement(&refs_);} ULONG DoweProvider::Release(){ULONG n=InterlockedDecrement(&refs_);if(!n)delete this;return n;}
HRESULT DoweProvider::SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,DWORD){return cpus==CPUS_LOGON||cpus==CPUS_UNLOCK_WORKSTATION?S_OK:E_NOTIMPL;} HRESULT DoweProvider::SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*){return E_NOTIMPL;}
HRESULT DoweProvider::Advise(ICredentialProviderEvents*,UINT_PTR){return S_OK;} HRESULT DoweProvider::UnAdvise(){return S_OK;}
HRESULT DoweProvider::GetFieldDescriptorCount(DWORD* count){if(!count)return E_POINTER;*count=_countof(fields);return S_OK;} HRESULT DoweProvider::GetFieldDescriptorAt(DWORD id,CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** out){if(id>=_countof(fields)||!out)return E_INVALIDARG;return CopyField(fields[id],out);}
HRESULT DoweProvider::GetCredentialCount(DWORD* count,DWORD* def,BOOL* autoLogon){if(!count||!def||!autoLogon)return E_POINTER;*count=credential_?1:0;*def=CREDENTIAL_PROVIDER_NO_DEFAULT;*autoLogon=FALSE;return S_OK;}
HRESULT DoweProvider::GetCredentialAt(DWORD index,ICredentialProviderCredential** out){if(index||!credential_||!out)return E_INVALIDARG;return credential_->QueryInterface(IID_PPV_ARGS(out));}
HRESULT DoweProvider::SetUserArray(ICredentialProviderUserArray* users){if(users_)users_->Release();users_=users;if(users_)users_->AddRef();if(credential_){credential_->Release();credential_=nullptr;}DWORD count=0;if(!users||FAILED(users->GetCount(&count))||!count)return S_OK;ICredentialProviderUser* user{};HRESULT hr=users->GetAt(0,&user);if(SUCCEEDED(hr)){credential_=new(std::nothrow)DoweCredential();if(!credential_)hr=E_OUTOFMEMORY;else hr=credential_->Initialize(user);user->Release();}return hr;}
