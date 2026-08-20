#pragma once
#include <Windows.h>
#include <credentialprovider.h>
#include <string>
#include <vector>

class DoweCredential final : public ICredentialProviderCredential2 {
public:
 DoweCredential();
 HRESULT Initialize(ICredentialProviderUser* user);
 IFACEMETHODIMP QueryInterface(REFIID,void**) override; IFACEMETHODIMP_(ULONG) AddRef() override; IFACEMETHODIMP_(ULONG) Release() override;
 IFACEMETHODIMP Advise(ICredentialProviderCredentialEvents*) override; IFACEMETHODIMP UnAdvise() override;
 IFACEMETHODIMP SetSelected(BOOL*) override; IFACEMETHODIMP SetDeselected() override;
 IFACEMETHODIMP GetFieldState(DWORD,CREDENTIAL_PROVIDER_FIELD_STATE*,CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE*) override;
 IFACEMETHODIMP GetStringValue(DWORD,PWSTR*) override; IFACEMETHODIMP GetBitmapValue(DWORD,HBITMAP*) override;
 IFACEMETHODIMP GetCheckboxValue(DWORD,BOOL*,PWSTR*) override; IFACEMETHODIMP GetSubmitButtonValue(DWORD,DWORD*) override;
 IFACEMETHODIMP GetComboBoxValueCount(DWORD,DWORD*,DWORD*) override; IFACEMETHODIMP GetComboBoxValueAt(DWORD,DWORD,PWSTR*) override;
 IFACEMETHODIMP SetStringValue(DWORD,PCWSTR) override; IFACEMETHODIMP SetCheckboxValue(DWORD,BOOL) override;
 IFACEMETHODIMP SetComboBoxSelectedValue(DWORD,DWORD) override; IFACEMETHODIMP CommandLinkClicked(DWORD) override;
 IFACEMETHODIMP GetSerialization(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE*,CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*,PWSTR*,CREDENTIAL_PROVIDER_STATUS_ICON*) override;
 IFACEMETHODIMP ReportResult(NTSTATUS,NTSTATUS,PWSTR*,CREDENTIAL_PROVIDER_STATUS_ICON*) override;
 IFACEMETHODIMP GetUserSid(PWSTR*) override;
private: ~DoweCredential(); LONG refs_{1}; ICredentialProviderCredentialEvents* events_{}; std::wstring sid_,qualifiedUser_,code_;
};
