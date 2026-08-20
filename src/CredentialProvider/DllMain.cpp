#include "Provider.h"
#include "Guids.h"
#include <new>

HINSTANCE module{}; long objects{};
class Factory final:public IClassFactory{LONG refs_{1};public:HRESULT QueryInterface(REFIID id,void** out)override{if(!out)return E_POINTER;*out=nullptr;if(id==IID_IUnknown||id==IID_IClassFactory)*out=this;else return E_NOINTERFACE;AddRef();return S_OK;}ULONG AddRef()override{return InterlockedIncrement(&refs_);}ULONG Release()override{ULONG n=InterlockedDecrement(&refs_);if(!n)delete this;return n;}HRESULT CreateInstance(IUnknown* outer,REFIID id,void** out)override{if(outer)return CLASS_E_NOAGGREGATION;auto p=new(std::nothrow)DoweProvider();if(!p)return E_OUTOFMEMORY;auto hr=p->QueryInterface(id,out);p->Release();return hr;}HRESULT LockServer(BOOL lock)override{if(lock)InterlockedIncrement(&objects);else InterlockedDecrement(&objects);return S_OK;}};
BOOL WINAPI DllMain(HINSTANCE h,DWORD reason,LPVOID){if(reason==DLL_PROCESS_ATTACH){module=h;DisableThreadLibraryCalls(h);}return TRUE;}
// LogonUI owns provider and credential references on separate paths. Conservatively keep the
// small DLL loaded for the lifetime of the host process instead of risking premature unload.
STDAPI DllCanUnloadNow(){return S_FALSE;}
STDAPI DllGetClassObject(REFCLSID clsid,REFIID iid,void** out){if(clsid!=CLSID_DowePinlessProvider)return CLASS_E_CLASSNOTAVAILABLE;auto f=new(std::nothrow)Factory();if(!f)return E_OUTOFMEMORY;auto hr=f->QueryInterface(iid,out);f->Release();return hr;}
