#include "stdafx.h"
#include "NetCfgAPI.h"


HRESULT HrGetINetCfg(IN BOOL fGetWriteLock,
					 IN LPCTSTR lpszAppName,
					 OUT INetCfg **ppnc,
					 __deref_opt_out_opt LPTSTR *lpszLockedBy)
{
	INetCfg *pnc = NULL;
	INetCfgLock *pncLock = NULL;
	HRESULT hr = S_OK;

	//Initialize the output parameters
	*ppnc = NULL;
	if (lpszLockedBy)
		*lpszLockedBy = NULL;

	//Initialize COM
	hr = CoInitialize(NULL);
	if (hr == S_OK)
	{
		// Create the object implementing INetCfg.
		hr = CoCreateInstance(CLSID_CNetCfg,NULL,CLSCTX_INPROC_SERVER,IID_INetCfg,(void **)&pnc);
		if (hr == S_OK)
		{
			if (fGetWriteLock)
			{
				// Get the locking reference
				hr = pnc->QueryInterface(IID_INetCfgLock,(LPVOID *)&pncLock);
				if (hr == S_OK)
				{
					// Attempt to lock the INetCfg for read/write
					hr = pncLock->AcquireWriteLock(LOCK_TIME_OUT,lpszAppName,lpszLockedBy);
					if (hr == S_FALSE)
						hr = NETCFG_E_NO_WRITE_LOCK;
				}
			}

			if (hr == S_OK)
			{
				// Initialize the INetCfg object.
				hr = pnc->Initialize(NULL);
				if (hr == S_OK)
				{
					*ppnc = pnc;
					pnc->AddRef();
				}
				else
				{
					// Initialize failed,if obtained lock,release it
					if (pncLock)
						pncLock->ReleaseWriteLock();
				}
			}

			ReleaseRef(pncLock);
			ReleaseRef(pnc);
		}

		// In case of error, uninitialize COM.
		if (hr != S_OK)
			CoUninitialize();
	}

	return hr;
}

VOID ReleaseRef(IN IUnknown *punk)
{
	if (punk)
		punk->Release();
	return;
}

HRESULT HrInstallNetComponent(IN INetCfg *pnc,
							  IN LPCTSTR lpszComponentId,
							  IN const GUID *pguidClass,
							  IN LPCTSTR lpszInfFullPath)
{
	HRESULT hr = S_OK;
	TCHAR *Drive = NULL;
	TCHAR *Dir = NULL;
	TCHAR *DirWithDrive = NULL;

	do 
	{
		// If full path to INF has been specified, the INF
		// needs to be copied using Setup API to ensure that any other files
		// that the primary INF copies will be correctly found by Setup API
		if (lpszInfFullPath)
		{
			// Allocate memory to hold the strings
			Drive = (TCHAR *)CoTaskMemAlloc(_MAX_DRIVE * sizeof(TCHAR));
			if (NULL == Drive)
			{
				hr = E_OUTOFMEMORY;
				break;
			}
			ZeroMemory(Drive,_MAX_DRIVE * sizeof(TCHAR));

			Dir = (WCHAR *)CoTaskMemAlloc(_MAX_DIR *sizeof(TCHAR));
			if (NULL == Dir)
			{
				hr = E_OUTOFMEMORY;
				break;
			}
			ZeroMemory(Dir,_MAX_DIR * sizeof(TCHAR));

			DirWithDrive = (TCHAR *)CoTaskMemAlloc((_MAX_DRIVE + _MAX_DIR) * sizeof(TCHAR));
			if (NULL == DirWithDrive)
			{
				hr = E_OUTOFMEMORY;
				break;
			}
			ZeroMemory(DirWithDrive,(_MAX_DRIVE + _MAX_DIR) * sizeof(TCHAR));

			// Get the path where the INF file is
			_tsplitpath_s(lpszInfFullPath,Drive,_MAX_DRIVE,Dir,_MAX_DIR,NULL,0,NULL,0);
			StringCchCopy(DirWithDrive,_MAX_DRIVE+_MAX_DIR,Drive);
			StringCchCat(DirWithDrive,_MAX_DRIVE+_MAX_DIR,Dir);

			// Copy the INF file and other files referenced in the INF file.

			if (!SetupCopyOEMInf(lpszInfFullPath,
								 DirWithDrive,	// Other files are in the same dir. as primary INF
								 SPOST_PATH,	// First param is path to INF 
								 0,				// Default copy style
								 NULL,			// Name of the INF after it's copied to %windir%\inf
								 0,				// Max buf. size for the above
								 NULL,			// Required size if non-null
								 NULL))			// Optionally get the filename part of Inf name after it is copied.
			{
				hr = HRESULT_FROM_WIN32(GetLastError());
			}
		}

		if (S_OK == hr)
		{
			// Install the network component.
			hr = HrInstallComponent(pnc,lpszComponentId,pguidClass);
			if (hr == S_OK)
				hr = pnc->Apply();
		}

#pragma warning(disable:4217) // Conditional expression is constant
	} while (false);

	if (Drive != NULL)
	{
		CoTaskMemFree(Drive);
		Drive = NULL;
	}
	if (Dir != NULL)
	{
		CoTaskMemFree(Dir);
		Dir = NULL;
	}
	if (DirWithDrive != NULL)
	{
		CoTaskMemFree(DirWithDrive);
		DirWithDrive = NULL;
	}   

	return hr;
}

HRESULT HrReleaseINetCfg(IN INetCfg *pnc,IN BOOL fHasWriteLock)
{
	INetCfgLock *pncLock = NULL;
	HRESULT hr = S_OK;

	// Uninitialize INetCfg
	hr = pnc->Uninitialize();

	// If write lock is present,unlock it
	if (hr == S_OK && fHasWriteLock)
	{
		// Get the locking reference
		hr = pnc->QueryInterface(IID_INetCfgLock,(LPVOID *)&pncLock);
		if (hr == S_OK)
		{
			hr = pncLock->ReleaseWriteLock();
			ReleaseRef(pncLock);
		}
	}

	ReleaseRef(pnc);
	// Uninitialize COM.
	CoUninitialize();
	return hr;
}

HRESULT HrInstallComponent(IN INetCfg *pnc,IN LPCTSTR szComponentId,IN const GUID *pguidClass)
{
	INetCfgClassSetup *pncClassSetup = NULL;
	INetCfgComponent *pncc = NULL;
	OBO_TOKEN OboToken;
	HRESULT hr = S_OK;

	// OBO_TOKEN specifies on whose behalf this component is being installed.
	// Set it to OBO_USER so that szComponentId will be installed 
	// on behalf of the user.
	ZeroMemory(&OboToken,sizeof(OboToken));
	OboToken.Type = OBO_USER;

	// Get component's setup class reference.
	hr = pnc->QueryNetCfgClass(pguidClass,IID_INetCfgClassSetup,(void **)&pncClassSetup);
	if (hr == S_OK)
	{
		hr = pncClassSetup->Install(szComponentId,
									&OboToken,
									0,
									0,		// Upgrade from build number.
									NULL,	// Answerfile name
									NULL,	// Answerfile section name
									&pncc);	// Reference after the component is installed.
		if (S_OK == hr)
			// don't need to use pncc (INetCfgComponent),release it
			ReleaseRef(pncc);
		
		ReleaseRef(pncClassSetup);
	}

	return hr;
}