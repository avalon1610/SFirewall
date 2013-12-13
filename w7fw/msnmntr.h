#pragma once

typedef struct _FLOW_DATA
{
	UINT64 flowHandle;
	UINT64 flowContext;
	UINT64 calloutId;
	ULONG localAddressV4;
	USHORT localPort;
	USHORT ipProto;
	ULONG remoteAddressV4;
	USHORT remotePort;
	WCHAR *processPath;
	LIST_ENTRY listEntry;
	BOOLEAN deleting;
} FLOW_DATA;

NTSTATUS MonitorCoInitialize(PDEVICE_OBJECT deviceObject);
void MonitorCoUninitialize();
NTSTATUS MonitorCoEnableMonitoring(IN MONITOR_SETTING *monitorSettings);
void MonitorCoDisableMonitoring();