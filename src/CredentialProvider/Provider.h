#pragma once
#include <Windows.h>
#include <credentialprovider.h>
#include "Credential.h"

class DoweProvider final : public ICredentialProvider, public ICredentialProviderSetUserArray {
public:
 IFACEMETHODIMP QueryInterface(REFIID,void**) override; IFACEMETHODIMP_(ULONG) AddRef() override; IFACEMETHODIMP_(ULONG) Release() override;
 IFACEMETHODIMP SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO,DWORD) override; IFACEMETHODIMP SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*) override;
 IFACEMETHODIMP Advise(ICredentialProviderEvents*,UINT_PTR) override; IFACEMETHODIMP UnAdvise() override;
 IFACEMETHODIMP GetFieldDescriptorCount(DWORD*) override; IFACEMETHODIMP GetFieldDescriptorAt(DWORD,CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR**) override;
 IFACEMETHODIMP GetCredentialCount(DWORD*,DWORD*,BOOL*) override; IFACEMETHODIMP GetCredentialAt(DWORD,ICredentialProviderCredential**) override;
 IFACEMETHODIMP SetUserArray(ICredentialProviderUserArray*) override;
private: ~DoweProvider(); LONG refs_{1}; ICredentialProviderUserArray* users_{}; DoweCredential* credential_{};
};
