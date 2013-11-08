#include "stdafx.h"
#include "LoadSys.h"

#pragma comment(lib,"Setupapi.lib")

enum TYPE
{
	INSTALL = 0,
	START,
	STOP,
	DELETE
};

VOID ErrMsg (HRESULT hr,LPCTSTR  lpFmt,...)
{
	LPTSTR   lpSysMsg;
	TCHAR    buf[400];
	size_t   offset;
	va_list  vArgList;

	if ( hr != 0 ) 
		StringCchPrintf(buf,celems(buf),_T("Error %#lx: "),hr);
	else 
		buf[0] = 0;

	offset = _tcslen( buf );

	va_start(vArgList,lpFmt);
	StringCchVPrintf(buf+offset,celems(buf)-offset,lpFmt,vArgList);
	va_end(vArgList);

	if ( hr != 0 ) 
	{
		FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_IGNORE_INSERTS,
					  NULL,
					  hr,
					  MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
					  (LPTSTR)&lpSysMsg,
					  0,
					  NULL);
		if (lpSysMsg)
		{
			offset = _tcslen(buf);
			StringCchPrintf(buf+offset,celems(buf)-offset,_T("\n\nPossible cause:\n\n"));
			offset = _tcslen(buf);
			StringCchCat(buf+offset,celems(buf)-offset,lpSysMsg);
			LocalFree((HLOCAL)lpSysMsg);
		}

		MessageBox(NULL,buf,_T("Error"),MB_ICONERROR | MB_OK );
	}
	else
	{
		MessageBox(NULL,buf,_T("LoadSys"),MB_ICONINFORMATION | MB_OK );
	}

	return;
}

// for scm
BOOL operate(TCHAR *szFullPath,TCHAR *szName,int iType,TCHAR *msg,int msg_len)
{
	SC_HANDLE shOSCM = NULL,shCS = NULL;
	SERVICE_STATUS ss;
	DWORD dwErrorCode = 0;
	BOOL bSuccess = FALSE;

	shOSCM = OpenSCManager(NULL,NULL,SC_MANAGER_ALL_ACCESS);
	if (!shOSCM)
	{
		_stprintf_s(msg,msg_len,_T("OpenSCManager Error:%d"),GetLastError());
		return FALSE;
	}

	if (iType) // type is not install service
	{
		shCS = OpenService(shOSCM,szName,SERVICE_ALL_ACCESS);
		if (!shCS)
		{
			dwErrorCode = GetLastError();
			if (ERROR_INVALID_NAME == dwErrorCode)
				_stprintf_s(msg,msg_len,_T("Service Name ERROR!"));
			else if (ERROR_SERVICE_DOES_NOT_EXIST == dwErrorCode)
				_stprintf_s(msg,msg_len,_T("Service Does not exist!"));
			else
				_stprintf_s(msg,msg_len,_T("OpenService Error:%d"),dwErrorCode);
			CloseServiceHandle(shOSCM);
			return FALSE;
		}
	}

	switch(iType)
	{
	case INSTALL:		//install service
		shCS = CreateService(shOSCM,szName,szName,SERVICE_ALL_ACCESS,SERVICE_KERNEL_DRIVER,
							SERVICE_DEMAND_START,SERVICE_ERROR_NORMAL,szFullPath,NULL,NULL,
							NULL,NULL,NULL);
		if (!shCS)
		{
			if (ERROR_SERVICE_EXISTS == GetLastError())
			{
				_stprintf_s(msg,msg_len,_T("Service already Exist!"));
				bSuccess = TRUE;
			}
			else
			{
				_stprintf_s(msg,msg_len,_T("CreateService Error:%d"),GetLastError());
				bSuccess = FALSE;
			}
			break;
		}

		_stprintf_s(msg,msg_len,_T("Install Service Success."));
		bSuccess = TRUE;
		break;
	case START:		// Start service
		if (StartService(shCS,0,NULL))
			_stprintf_s(msg,msg_len,_T("Start Service Success."));
		else
		{
			dwErrorCode = GetLastError();
			if (ERROR_SERVICE_ALREADY_RUNNING == dwErrorCode)
			{
				_stprintf_s(msg,msg_len,_T("Service already running!"));
				bSuccess = TRUE;
			}
			else
			{
				_stprintf_s(msg,msg_len,_T("Start Service Error:%d"),dwErrorCode);
				bSuccess = FALSE;
			}
			break;
		}
		bSuccess = TRUE;
		break;
	case STOP:
		if (!ControlService(shCS,SERVICE_CONTROL_STOP,&ss))
		{
			dwErrorCode = GetLastError();
			if (ERROR_SERVICE_NOT_ACTIVE == dwErrorCode)
				_stprintf_s(msg,msg_len,_T("Service not running."));
			else
				_stprintf_s(msg,msg_len,_T("Stop Service Error:%d"),dwErrorCode);
			bSuccess = FALSE;
			break;
		}
		_stprintf_s(msg,msg_len,_T("Stop Service Success."));
		bSuccess = TRUE;
		break;
	case DELETE:
		if (!DeleteService(shCS))
		{
			_stprintf_s(msg,msg_len,_T("Can't remove Service"));
			bSuccess = FALSE;
			break;
		}
		_stprintf_s(msg,msg_len,_T("Remove Service Success."));
		bSuccess = TRUE;
		break;
	default:
		break;
	}

	if (shCS)
		CloseServiceHandle(shCS);
	if (shOSCM)
		CloseServiceHandle(shOSCM);
	return bSuccess;
}

// for minifilter
BOOL SetupInfo(TCHAR *szName,TCHAR *msg,int msg_len)
{
	TCHAR szTempStr[MAX_PATH] = {0};
	DWORD dwData;
	HKEY hKey;
	TCHAR lpszAltitude[32] = _T("370000");
	_tcscpy_s(szTempStr,sizeof(szTempStr),_T("SYSTEM\\CurrentControlSet\\Services\\"));
	_tcscat_s(szTempStr,sizeof(szTempStr),szName);
	_tcscat_s(szTempStr,sizeof(szTempStr),_T("\\Instances"));
	if (RegCreateKeyEx(HKEY_LOCAL_MACHINE,
					   szTempStr,
					   0,
					   _T(""),
					   TRUE,
					   KEY_ALL_ACCESS,
					   NULL,
					   &hKey,
					   (LPDWORD)&dwData) != ERROR_SUCCESS)
	{
		_stprintf_s(msg,msg_len,_T("RegCreateKeyEx 1 failed:%d"),GetLastError());
		return FALSE;
	}

	_tcscpy_s(szTempStr,sizeof(szTempStr),szName);
	_tcscat_s(szTempStr,sizeof(szTempStr),_T(" Instance"));
	if (RegSetValueEx(hKey,
					  _T("DefaultInstance"),
					  0,
					  REG_SZ,
					  (CONST BYTE*)szTempStr,
					  (DWORD)_tcslen(szTempStr)) != ERROR_SUCCESS)
	{
		_stprintf_s(msg,msg_len,_T("RegSetValueEx 1 failed:%d"),GetLastError());
		return FALSE;
	}
	RegFlushKey(hKey);
	RegCloseKey(hKey);

	_tcscpy_s(szTempStr,sizeof(szTempStr),_T("SYSTEM\\CurrentControlSet\\Services\\"));
	_tcscat_s(szTempStr,sizeof(szTempStr),szName);
	_tcscat_s(szTempStr,sizeof(szTempStr),_T("\\Instances\\"));
	_tcscat_s(szTempStr,sizeof(szTempStr),szName);
	_tcscat_s(szTempStr,sizeof(szTempStr),_T(" Instance"));
	if (RegCreateKeyEx(HKEY_LOCAL_MACHINE,
					   szTempStr,
					   0,
					   _T(""),
					   TRUE,
					   KEY_ALL_ACCESS,
					   NULL,
					   &hKey,
					   (LPDWORD)&dwData) != ERROR_SUCCESS)
	{
		_stprintf_s(msg,msg_len,_T("RegCreateKeyEx 2 failed:%d"),GetLastError());
		return FALSE;
	}

	_tcscpy_s(szTempStr,sizeof(szTempStr),lpszAltitude);
	if (RegSetValueEx(hKey,_T("Altitude"),0,REG_SZ,(CONST BYTE*)szTempStr,(DWORD)_tcslen(szTempStr)) != ERROR_SUCCESS)
	{
		_stprintf_s(msg,msg_len,_T("RegSetValueEx 2 failed:%d"),GetLastError());
		return FALSE;
	}

	dwData = 0;
	if (RegSetValueEx(hKey,_T("Flags"),0,REG_DWORD,(CONST BYTE*)&dwData,sizeof(DWORD)) != ERROR_SUCCESS)
	{
		_stprintf_s(msg,msg_len,_T("RegSetValueEx 3 failed:%d"),GetLastError());
		return FALSE;
	}

	RegFlushKey(hKey);
	RegCloseKey(hKey);

	return TRUE;
}


// for NDIS IM inf 

HRESULT GetKeyValue(HINF hInf,__in LPCTSTR lpszSection,__in_opt LPCTSTR lpszKey,
					DWORD dwIndex,__deref_out_opt LPTSTR*lppszValue)
{
	INFCONTEXT infCtx;
	__range(0,512) DWORD dwSizeNeeded;
	HRESULT hr;

	*lppszValue = NULL;
	if (SetupFindFirstLine(hInf,lpszSection,lpszKey,&infCtx) == FALSE)
		return HRESULT_FROM_WIN32(GetLastError());
	if (SetupGetStringField(&infCtx,dwIndex,NULL,0,&dwSizeNeeded))
	{
		*lppszValue = (LPTSTR)CoTaskMemAlloc(sizeof(TCHAR) * dwSizeNeeded);
		if (!*lppszValue)
			return HRESULT_FROM_WIN32(ERROR_NOT_ENOUGH_MEMORY);
		if (SetupGetStringField(&infCtx,dwIndex,*lppszValue,dwSizeNeeded,NULL) == FALSE)
		{
			hr = HRESULT_FROM_WIN32(GetLastError());
			CoTaskMemFree(*lppszValue);
			*lppszValue = NULL;
		}
		else
			hr = S_OK;
	}
	else
		hr = HRESULT_FROM_WIN32(GetLastError());

	return hr;
}

HRESULT GetPnpID(__in LPTSTR lpszInfFile,__deref_out_opt LPTSTR *lppszPnpID)
{
	HINF hInf;
	LPTSTR lpszModelSection;
	HRESULT hr;

	*lppszPnpID = NULL;
	hInf = SetupOpenInfFile(lpszInfFile,NULL,INF_STYLE_WIN4,NULL);
	if (hInf == INVALID_HANDLE_VALUE)
		return HRESULT_FROM_WIN32(GetLastError());
	hr = GetKeyValue(hInf,_T("Manufacturer"),NULL,1,&lpszModelSection);
	if (hr == S_OK)
	{
		hr = GetKeyValue(hInf,lpszModelSection,NULL,2,lppszPnpID);
		CoTaskMemFree(lpszModelSection);
	}

	SetupCloseInfFile(hInf);
	return hr;
}

const GUID *pguidNetClass[] = 
{
	&GUID_DEVCLASS_NETCLIENT,
	&GUID_DEVCLASS_NETSERVICE,
	&GUID_DEVCLASS_NETTRANS,
	&GUID_DEVCLASS_NET
};

VOID InstallSelectedComponent(__in_opt LPTSTR lpszInfFile)
{
	LPTSTR lpszPnpID;
	HRESULT hr;
	if (!lpszInfFile)
		return;
	hr = GetPnpID(lpszInfFile,&lpszPnpID);
	if (hr == S_OK)
	{
		hr = InstallSpecifiedComponent(lpszInfFile,lpszPnpID,pguidNetClass[1]);
		CoTaskMemFree(lpszPnpID);
	}
	else
	{
		ErrMsg(hr,_T("Error reading the INF file %s."),lpszInfFile);
	}

	switch(hr)
	{
	case S_OK:
		//ErrMsg(hr,_T("Component installed successfully."));
		break;
	case NETCFG_S_REBOOT:
		ErrMsg(hr,_T("Component installed successfully:Reboot required."));
		break;
	}
}

BOOL MByteToWChar(LPCSTR lpcszStr, LPWSTR lpwszStr, DWORD dwSize)
{
	// Get the required size of the buffer that receives the Unicode 
	// string. 
	DWORD dwMinSize;
	dwMinSize = MultiByteToWideChar (CP_ACP, 0, lpcszStr, -1, NULL, 0);
	if(dwSize < dwMinSize)
		return FALSE;

	// Convert headers from ASCII to Unicode.
	MultiByteToWideChar (CP_ACP, 0, lpcszStr, -1, lpwszStr, dwMinSize);  
	return TRUE;
}

BOOL load_driver(char *szFullPath,char *szName,char *msg,int msg_len)
{
	TCHAR FullPath[MAX_PATH] = {0};
	TCHAR Name[32] = {0};
	TCHAR Msg[128] = {0};

	MByteToWChar(szFullPath,FullPath,sizeof(FullPath)/sizeof(TCHAR));
	MByteToWChar(szName,Name,sizeof(Name)/sizeof(TCHAR));
	MByteToWChar(msg,Msg,sizeof(Msg)/sizeof(TCHAR));
	
	if (!operate(FullPath,Name,INSTALL,Msg,msg_len))	
		return FALSE;
	if (!operate(FullPath,Name,START,Msg,msg_len))
		return FALSE;
	return TRUE;
}

VOID load_driver_inf(char *InfFile)
{
	TCHAR lpszInfFile[MAX_PATH] = {0};
	MByteToWChar(InfFile,lpszInfFile,sizeof(lpszInfFile)/sizeof(TCHAR));
	InstallSelectedComponent(lpszInfFile);
}