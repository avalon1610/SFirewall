#include "stdafx.h"
#include "NetCfgAPI.h"
#include "LoadSys.h"

HRESULT InstallSpecifiedComponent(__in LPTSTR lpszInfFile,__in LPTSTR lpszPnpID,const GUID *pguidClass)
{
	INetCfg *pnc;
	LPTSTR lpszApp;
	HRESULT hr;

	hr = HrGetINetCfg(TRUE,APP_NAME,&pnc,&lpszApp);
	if (hr == S_OK)
	{
		// Install the network component
		hr = HrInstallNetComponent(pnc,lpszPnpID,pguidClass,lpszInfFile);
		if ((hr == S_OK) || (hr == NETCFG_S_REBOOT))
			hr = pnc->Apply();
		else
		{
			if (hr != HRESULT_FROM_WIN32(ERROR_CANCELLED))
			{
				ErrMsg(hr,_T("Couldn't install the network component."));
			}
		}

		HrReleaseINetCfg(pnc,TRUE);
	}
	else
	{
		if ((hr == NETCFG_E_NO_WRITE_LOCK) && lpszApp)
		{
			ErrMsg(hr,_T("%s currently holds the lock, try later."),lpszApp);
			CoTaskMemFree(lpszApp);
		}
		else
		{
			ErrMsg(hr,_T("Couldn't get the notify object interface."));
		}
	}

	return hr;
}