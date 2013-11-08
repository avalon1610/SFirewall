#pragma once

#define celems(_x) (sizeof(_x)/sizeof(_x[0]))

#define LOCK_TIME_OUT 5000
VOID ReleaseRef(IN IUnknown *punk);
HRESULT HrGetINetCfg(IN BOOL fGetWriteLock, IN LPCTSTR lpszAppName, OUT INetCfg **ppnc, __deref_opt_out_opt LPTSTR *lpszLockedBy);
HRESULT HrReleaseINetCfg(IN INetCfg *pnc,IN BOOL fHasWriteLock);
HRESULT HrInstallNetComponent(IN INetCfg *pnc, IN LPCTSTR lpszComponentId, IN const GUID *pguidClass, IN LPCTSTR lpszInfFullPath);
HRESULT HrInstallComponent(IN INetCfg *pnc,IN LPCTSTR szComponentId,IN const GUID *pguidClass);