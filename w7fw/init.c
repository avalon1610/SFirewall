#include "ndis.h"
#include "ntddk.h"
#include "fwpmk.h"

#pragma warning(push)
#pragma warning(disable:4201)
#include "fwpsk.h"
#pragma warning(pop)

#include "ioctl.h"
#include "ctl.h"
#include "msnmntr.h"
#include "notify.h"

#define WPP_CONTROL_GUIDS \
	WPP_DEFINE_CONTROL_GUID(MsnMntrInit,(e7db16bb,41be,4c05,b73e,5feca06f8207),\
	WPP_DEFINE_BIT(TRACE_INIT)\
	WPP_DEFINE_BIT(TRACE_SHUTDOWN))\

#include "init.tmh"

PDEVICE_OBJECT monitorDeviceObject;
UNICODE_STRING monitorSymbolicLink;

DRIVER_INITIALIZE DriverEntry;
NTSTATUS DriverEntry(IN PDRIVER_OBJECT driverObject,IN PUNICODE_STRING registryPath);

DRIVER_UNLOAD DriverUnload;
VOID DriverUnload(IN PDRIVER_OBJECT driverObject);

NTSTATUS DriverEntry(IN PDRIVER_OBJECT driverObject,IN PUNICODE_STRING registryPath)
{
	NTSTATUS status;
	UNICODE_STRING deviceName;
	BOOLEAN validSymbolicLink = FALSE;
	BOOLEAN initializedCallouts = FALSE;

	WPP_INIT_TRACING(driverObject,registryPath);
	DoTraceMessage(TRACE_INIT,"Initializing MsnMonitor Driver");
	monitorDeviceObject = NULL;
	UNREFERENCED_PARAMETER(registryPath);
	driverObject->DriverUnload = DriverUnload;
	status = MonitorCtlDriverInit(driverObject);
	if (!NT_SUCCESS(status))
		goto cleanup;

	RtlInitUnicodeString(&deviceName,MONITOR_DEVICE_NAME);
	status = IoCreateDevice(driverObject,0,&deviceName,FILE_DEVICE_NETWORK,0,FALSE,&monitorDeviceObject);
	if (!NT_SUCCESS(status))
		goto cleanup;

	status = MonitorCoInitialize(monitorDeviceObject);
	if (!NT_SUCCESS(status))
		goto cleanup;
	initializedCallouts = TRUE;

	RtlInitUnicodeString(&monitorSymbolicLink,MONITOR_SYMBOLIC_NAME);
	status = IoCreateSymbolicLink(&monitorSymbolicLink,&deviceName);
	if (!NT_SUCCESS(status))
		goto cleanup;
	validSymbolicLink = TRUE;

	status = MonitorNfInitialize(monitorDeviceObject);
	if (!NT_SUCCESS(status))
		goto cleanup;

cleanup:
	if (!NT_SUCCESS(status))
	{
		DoTraceMessage(TRACE_INIT,"MsnMonitor Initialization Failed.");
		WPP_CLEANUP(driverObject);

		if (initializedCallouts)
		{
			if (validSymbolicLink)
				IoDeleteSymbolicLink(&monitorSymbolicLink);
			if (monitorDeviceObject)
				IoDeleteDevice(monitorDeviceObject);
		}
	}

	return status;
}

VOID DriverUnload(IN PDRIVER_OBJECT driverObject)
{
	UNREFERENCED_PARAMETER(driverObject);
	MonitorCoUninitialize();
	MonitorNfUninitialize();

	IoDeleteDevice(monitorDeviceObject);
	IoDeleteSymbolicLink(&monitorSymbolicLink);

	DoTraceMessage(TRACE_SHUTDOWN,"MsnMonitor Driver Shutting Down");

	WPP_CLEANUP(driverObject);
}