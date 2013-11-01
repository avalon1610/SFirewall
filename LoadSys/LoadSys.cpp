#include "stdafx.h"
#include "LoadSys.h"

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
				_stprintf_s(msg,msg_len,_T("Service already Exist!"));
			else
				_stprintf_s(msg,msg_len,_T("CreateService Error:%d"),GetLastError());
			bSuccess = FALSE;
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
				_stprintf_s(msg,msg_len,_T("Service already running!"));
			else
				_stprintf_s(msg,msg_len,_T("Start Service Error:%d"),dwErrorCode);
			bSuccess = FALSE;
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

BOOL Install(TCHAR *szFullPath,TCHAR *szName,int iType,TCHAR *msg,int msg_len)
{
	return FALSE;
}