#pragma once
#ifdef DELETE
#undef DELETE
#endif
#include <stdio.h>
#include <windows.h>

#define celems(_x) (sizeof(_x)/sizeof(_x[0]))
#define APP_NAME _T("LoadSys")

HRESULT InstallSpecifiedComponent(__in LPTSTR lpszInfFile,__in LPTSTR lpszPnpID,const GUID *pguidClass);
VOID ErrMsg (HRESULT hr,LPCTSTR lpFmt,...);

#ifdef __cplusplus
extern "C" {
#endif
BOOL load_driver(char *szFullPath,char *szName,char *msg,int msg_len);
VOID load_driver_inf(char *InfFile);
#ifdef __cplusplus
};
#endif
