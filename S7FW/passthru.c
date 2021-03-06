/*++

Copyright (c) 1992-2000  Microsoft Corporation
 
Module Name:
 
    passthru.c

Abstract:

    Ndis Intermediate Miniport driver sample. This is a passthru driver.

Author:

Environment:


Revision History:


--*/


#include "precomp.h"
#pragma hdrstop

#pragma NDIS_INIT_FUNCTION(DriverEntry)

NDIS_HANDLE         ProtHandle = NULL;
NDIS_HANDLE         DriverHandle = NULL;
NDIS_MEDIUM         MediumArray[4] =
                    {
                        NdisMedium802_3,    // Ethernet
                        NdisMedium802_5,    // Token-ring
                        NdisMediumFddi,     // Fddi
                        NdisMediumWan       // NDISWAN
                    };

NDIS_SPIN_LOCK     GlobalLock;

PADAPT             pAdaptList = NULL;
LONG               MiniportCount = 0;

NDIS_HANDLE        NdisWrapperHandle;

PVOID			g_pSySAddr = NULL;
PMDL			g_pMdl = NULL;	// memory shared with ring3
PKEVENT			g_pEvent = NULL;// event created at user mode
PKEVENT			g_kEvent;		// event created at kernel mode
HANDLE			g_LogThread = NULL;
CLIENT_ID		g_LogClientId;
PKEVENT			g_ExitEvent;
BOOLEAN			b_ExitThread = FALSE;

NTSTATUS AddPktFltRule(PktFltRule *pkt_flt_item);
NTSTATUS RemovePktFltRule(PktFltRule *pkt_flt_item);
VOID CleanPktFltList();

//
// To support ioctls from user-mode:
//

#define LINKNAME_STRING     L"\\DosDevices\\s7fw"
#define NTDEVICE_STRING     L"\\Device\\s7fw"

NDIS_HANDLE     NdisDeviceHandle = NULL;
PDEVICE_OBJECT  ControlDeviceObject = NULL;

enum _DEVICE_STATE
{
    PS_DEVICE_STATE_READY = 0,    // ready for create/delete
    PS_DEVICE_STATE_CREATING,    // create operation in progress
    PS_DEVICE_STATE_DELETING    // delete operation in progress
} ControlDeviceState = PS_DEVICE_STATE_READY;



NTSTATUS
DriverEntry(
    IN PDRIVER_OBJECT        DriverObject,
    IN PUNICODE_STRING       RegistryPath
    )
/*++

Routine Description:

    First entry point to be called, when this driver is loaded.
    Register with NDIS as an intermediate driver.

Arguments:

    DriverObject - pointer to the system's driver object structure
        for this driver
    
    RegistryPath - system's registry path for this driver
    
Return Value:

    STATUS_SUCCESS if all initialization is successful, STATUS_XXX
    error code if not.

--*/
{
    NDIS_STATUS                        Status;
    NDIS_PROTOCOL_CHARACTERISTICS      PChars;
    NDIS_MINIPORT_CHARACTERISTICS      MChars;
    NDIS_STRING                        Name;
	HANDLE	exit_event_handle = NULL;
	UNICODE_STRING evtname;

	InitPktFltList();
	InitLogRecord();

    Status = NDIS_STATUS_SUCCESS;
    NdisAllocateSpinLock(&GlobalLock);

    NdisMInitializeWrapper(&NdisWrapperHandle, DriverObject, RegistryPath, NULL);

    do
    {
        //
        // Register the miniport with NDIS. Note that it is the miniport
        // which was started as a driver and not the protocol. Also the miniport
        // must be registered prior to the protocol since the protocol's BindAdapter
        // handler can be initiated anytime and when it is, it must be ready to
        // start driver instances.
        //

        NdisZeroMemory(&MChars, sizeof(NDIS_MINIPORT_CHARACTERISTICS));

        MChars.MajorNdisVersion = PASSTHRU_MAJOR_NDIS_VERSION;
        MChars.MinorNdisVersion = PASSTHRU_MINOR_NDIS_VERSION;

        MChars.InitializeHandler = MPInitialize;
        MChars.QueryInformationHandler = MPQueryInformation;
        MChars.SetInformationHandler = MPSetInformation;
        MChars.ResetHandler = NULL;
        MChars.TransferDataHandler = MPTransferData;
        MChars.HaltHandler = MPHalt;
#ifdef NDIS51_MINIPORT
        MChars.CancelSendPacketsHandler = MPCancelSendPackets;
        MChars.PnPEventNotifyHandler = MPDevicePnPEvent;
        MChars.AdapterShutdownHandler = MPAdapterShutdown;
#endif // NDIS51_MINIPORT

        //
        // We will disable the check for hang timeout so we do not
        // need a check for hang handler!
        //
        MChars.CheckForHangHandler = NULL;
        MChars.ReturnPacketHandler = MPReturnPacket;

        //
        // Either the Send or the SendPackets handler should be specified.
        // If SendPackets handler is specified, SendHandler is ignored
        //
        MChars.SendHandler = NULL;    // MPSend;
        MChars.SendPacketsHandler = MPSendPackets;

        Status = NdisIMRegisterLayeredMiniport(NdisWrapperHandle,
                                                  &MChars,
                                                  sizeof(MChars),
                                                  &DriverHandle);
        if (Status != NDIS_STATUS_SUCCESS)
        {
            break;
        }

#ifndef WIN9X
        NdisMRegisterUnloadHandler(NdisWrapperHandle, PtUnload);
#endif

        //
        // Now register the protocol.
        //
        NdisZeroMemory(&PChars, sizeof(NDIS_PROTOCOL_CHARACTERISTICS));
        PChars.MajorNdisVersion = PASSTHRU_PROT_MAJOR_NDIS_VERSION;
        PChars.MinorNdisVersion = PASSTHRU_PROT_MINOR_NDIS_VERSION;

        //
        // Make sure the protocol-name matches the service-name
        // (from the INF) under which this protocol is installed.
        // This is needed to ensure that NDIS can correctly determine
        // the binding and call us to bind to miniports below.
        //
        NdisInitUnicodeString(&Name, L"S7FW");    // Protocol name
        PChars.Name = Name;
        PChars.OpenAdapterCompleteHandler = PtOpenAdapterComplete;
        PChars.CloseAdapterCompleteHandler = PtCloseAdapterComplete;
        PChars.SendCompleteHandler = PtSendComplete;
        PChars.TransferDataCompleteHandler = PtTransferDataComplete;
    
        PChars.ResetCompleteHandler = PtResetComplete;
        PChars.RequestCompleteHandler = PtRequestComplete;
        PChars.ReceiveHandler = PtReceive;
        PChars.ReceiveCompleteHandler = PtReceiveComplete;
        PChars.StatusHandler = PtStatus;
        PChars.StatusCompleteHandler = PtStatusComplete;
        PChars.BindAdapterHandler = PtBindAdapter;
        PChars.UnbindAdapterHandler = PtUnbindAdapter;
        PChars.UnloadHandler = PtUnloadProtocol;

        PChars.ReceivePacketHandler = PtReceivePacket;
        PChars.PnPEventHandler= PtPNPHandler;

        NdisRegisterProtocol(&Status,
                             &ProtHandle,
                             &PChars,
                             sizeof(NDIS_PROTOCOL_CHARACTERISTICS));

        if (Status != NDIS_STATUS_SUCCESS)
        {
            NdisIMDeregisterLayeredMiniport(DriverHandle);
            break;
        }

        NdisIMAssociateMiniport(DriverHandle, ProtHandle);
    }
    while (FALSE);

    if (Status != NDIS_STATUS_SUCCESS)
    {
        NdisTerminateWrapper(NdisWrapperHandle, NULL);
    }

	
	RtlInitUnicodeString(&evtname,L"\\BaseNamedObjects\\exit_event");
	g_ExitEvent = IoCreateSynchronizationEvent(&evtname,&exit_event_handle);
	if (g_ExitEvent == NULL)
		DBGPRINT(("IoCreateSynchronizationEvent g_ExitEvent failed"));

    return(Status);
}


NDIS_STATUS
PtRegisterDevice(
    VOID
    )
/*++

Routine Description:

    Register an ioctl interface - a device object to be used for this
    purpose is created by NDIS when we call NdisMRegisterDevice.

    This routine is called whenever a new miniport instance is
    initialized. However, we only create one global device object,
    when the first miniport instance is initialized. This routine
    handles potential race conditions with PtDeregisterDevice via
    the ControlDeviceState and MiniportCount variables.

    NOTE: do not call this from DriverEntry; it will prevent the driver
    from being unloaded (e.g. on uninstall).

Arguments:

    None

Return Value:

    NDIS_STATUS_SUCCESS if we successfully register a device object.

--*/
{
    NDIS_STATUS            Status = NDIS_STATUS_SUCCESS;
    UNICODE_STRING         DeviceName;
    UNICODE_STRING         DeviceLinkUnicodeString;
    PDRIVER_DISPATCH       DispatchTable[IRP_MJ_MAXIMUM_FUNCTION+1];

    DBGPRINT(("==>PtRegisterDevice\n"));

    NdisAcquireSpinLock(&GlobalLock);

    ++MiniportCount;
    
    if (1 == MiniportCount)
    {
        ASSERT(ControlDeviceState != PS_DEVICE_STATE_CREATING);

        //
        // Another thread could be running PtDeregisterDevice on
        // behalf of another miniport instance. If so, wait for
        // it to exit.
        //
        while (ControlDeviceState != PS_DEVICE_STATE_READY)
        {
            NdisReleaseSpinLock(&GlobalLock);
            NdisMSleep(1);
            NdisAcquireSpinLock(&GlobalLock);
        }

        ControlDeviceState = PS_DEVICE_STATE_CREATING;

        NdisReleaseSpinLock(&GlobalLock);

    
        NdisZeroMemory(DispatchTable, (IRP_MJ_MAXIMUM_FUNCTION+1) * sizeof(PDRIVER_DISPATCH));

        DispatchTable[IRP_MJ_CREATE] = PtDispatch;
        DispatchTable[IRP_MJ_CLEANUP] = PtDispatch;
        DispatchTable[IRP_MJ_CLOSE] = PtDispatch;
        DispatchTable[IRP_MJ_DEVICE_CONTROL] = PtDispatch;
	 

        NdisInitUnicodeString(&DeviceName, NTDEVICE_STRING);
        NdisInitUnicodeString(&DeviceLinkUnicodeString, LINKNAME_STRING);

        //
        // Create a device object and register our dispatch handlers
        //
        
        Status = NdisMRegisterDevice(
                    NdisWrapperHandle, 
                    &DeviceName,
                    &DeviceLinkUnicodeString,
                    &DispatchTable[0],
                    &ControlDeviceObject,
                    &NdisDeviceHandle
                    );

        NdisAcquireSpinLock(&GlobalLock);

        ControlDeviceState = PS_DEVICE_STATE_READY;
    }

    NdisReleaseSpinLock(&GlobalLock);

    DBGPRINT(("<==PtRegisterDevice: %x\n", Status));

    return (Status);
}

void CleanUp()
{
	PETHREAD ethread;
	b_ExitThread = TRUE;
	if (g_ExitEvent == NULL)
		return;
	CleanPktFltList();
	KeSetEvent(g_ExitEvent,0,FALSE);
	if (PsLookupThreadByThreadId(g_LogClientId.UniqueThread,&ethread) == STATUS_SUCCESS)
	{
		KeWaitForSingleObject(ethread,SYNCHRONIZE,KernelMode,FALSE,NULL);
		if (g_kEvent)
		{
			ZwClose(g_kEvent);
			g_kEvent = NULL;
		}
		if (g_pEvent)
		{
			ZwClose(g_pEvent);
			g_pEvent = NULL;
		}
		if (g_pMdl)
		{
			IoFreeMdl(g_pMdl);
			g_pMdl = NULL;
		}
		if (g_pSySAddr)
		{
			ExFreePoolWithTag(g_pSySAddr,PACKET_FILTER_TAG);
			g_pSySAddr = NULL;
		}
	}
	else
	{
		DBGPRINT(("Fatal Error, Worker Thread Lost Control!\n"));
	}
}

NTSTATUS
PtDispatch(
    IN PDEVICE_OBJECT    DeviceObject,
    IN PIRP              Irp
    )
/*++
Routine Description:

    Process IRPs sent to this device.

Arguments:

    DeviceObject - pointer to a device object
    Irp      - pointer to an I/O Request Packet

Return Value:

    NTSTATUS - STATUS_SUCCESS always - change this when adding
    real code to handle ioctls.

--*/
{
    PIO_STACK_LOCATION  irpStack;
    NTSTATUS            status = STATUS_SUCCESS;
	OBJECT_HANDLE_INFORMATION objHandleInfo;

    UNREFERENCED_PARAMETER(DeviceObject);
    
    //DBGPRINT(("==>Pt Dispatch\n"));
    irpStack = IoGetCurrentIrpStackLocation(Irp);
      

    switch (irpStack->MajorFunction)
    {
        case IRP_MJ_CREATE:
			{
				b_ExitThread = FALSE;
				status = PsCreateSystemThread(&g_LogThread,0,NULL,NULL,&g_LogClientId,(PKSTART_ROUTINE)PushLogWorkerThread,NULL);
				if (!NT_SUCCESS(status))
					DBGPRINT(("Create PushLogWorkerThread failed:%08X\n",status));
				break;
			}
            
        case IRP_MJ_CLEANUP:
			CleanUp();
			break;
        case IRP_MJ_CLOSE:
            break;        
            
        case IRP_MJ_DEVICE_CONTROL:
			{
				//
				// Add code here to handle ioctl commands sent to passthru.
				//
				PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
				ULONG InputBufferLen = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
				//ULONG OutputBufferLen = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
				PVOID Buffer = Irp->AssociatedIrp.SystemBuffer;
				switch(IrpSp->Parameters.DeviceIoControl.IoControlCode)
				{
				case IOCTL_SET_EVENT:
					{
						HANDLE				hEvent;

						if (Buffer == NULL || InputBufferLen < sizeof(HANDLE))
						{
							status = STATUS_INVALID_BUFFER_SIZE;
							break;
						}

						hEvent = *(HANDLE *)Buffer;
						status = ObReferenceObjectByHandle(hEvent,
														   SYNCHRONIZE,
														   *ExEventObjectType,
														   KernelMode,
														   (PVOID *)&g_pEvent,
														   &objHandleInfo);
						if (!NT_SUCCESS(status))
							g_pEvent = NULL;
						Irp->IoStatus.Information = 0;
						status = STATUS_SUCCESS;
						DBGPRINT(("get g_pEvent:%p\n",g_pEvent));
						break;
					}
				case IOCTL_SET_EVENT_K:
					{
						HANDLE				kEvent;

						if (Buffer == NULL || InputBufferLen < sizeof(HANDLE))
						{
							status = STATUS_INVALID_BUFFER_SIZE;
							break;
						}

						kEvent = *(HANDLE *)Buffer;
						status = ObReferenceObjectByHandle(kEvent,
														   SYNCHRONIZE,
														   *ExEventObjectType,
														   KernelMode,
														   (PVOID *)&g_kEvent,
														   &objHandleInfo);
						if (!NT_SUCCESS(status))
							g_kEvent = NULL;
						Irp->IoStatus.Information = 0;
						status = STATUS_SUCCESS;
						DBGPRINT(("get g_kEvent:%p\n",g_kEvent));
						break;
					}
				case IOCTL_GET_SHARE_ADDR:
					{
						PVOID UserAddr;
						g_pSySAddr = ExAllocatePoolWithTag(NonPagedPool,LOG_BUFSIZE,PACKET_FILTER_TAG);
						g_pMdl = IoAllocateMdl(g_pSySAddr,LOG_BUFSIZE,FALSE,FALSE,NULL);
						MmBuildMdlForNonPagedPool(g_pMdl);
						UserAddr = MmMapLockedPages(g_pMdl,UserMode);
						*((PVOID *)(Irp->AssociatedIrp.SystemBuffer)) = UserAddr;
						Irp->IoStatus.Information = sizeof(UserAddr);
						DBGPRINT(("Share Memory addr in UserMode:%p\n",UserAddr));
						break;
					}
					
				case IOCTL_MANAGE_RULE:
					{
						PktFltRule rule;
						if (Buffer == NULL || InputBufferLen < sizeof(PktFltRule))
						{
							status = STATUS_INVALID_BUFFER_SIZE;
							break;
						}

						rule = *(PktFltRule *)Buffer;
						if (rule.manage == ADD_RULE)
						{
							status = AddPktFltRule(&rule);
							DBGPRINT(("Add Rule %p [%08X]\n",&rule,RtlNtStatusToDosError(status)))
						}
						else if (rule.manage == REMOVE_RULE)
						{
							status = RemovePktFltRule(&rule);
							DBGPRINT(("Remove Rule %p [%08X]\n",&rule,RtlNtStatusToDosError(status)));
						}
						else if (rule.manage == UPDATE_RULE)
						{
							status = RemovePktFltRule(&rule);
							status = AddPktFltRule(&rule);
							DBGPRINT(("Update Rule %p [%08X]\n",&rule,RtlNtStatusToDosError(status)));
						}
						else
						{
							status = STATUS_INVALID_PARAMETER;
							DBGPRINT(("Invalid PktFltRule Manage Type.\n"));
						}	

						Irp->IoStatus.Information = 0;
						break;
					}
				default:
					status = STATUS_INVALID_DEVICE_REQUEST;
					Irp->IoStatus.Information = 0;
					break;
				}
			}

            break;        
        default:
            break;
    }

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    //DBGPRINT(("<== Pt Dispatch\n"));

    return status;

} 


NDIS_STATUS
PtDeregisterDevice(
    VOID
    )
/*++

Routine Description:

    Deregister the ioctl interface. This is called whenever a miniport
    instance is halted. When the last miniport instance is halted, we
    request NDIS to delete the device object

Arguments:

    NdisDeviceHandle - Handle returned by NdisMRegisterDevice

Return Value:

    NDIS_STATUS_SUCCESS if everything worked ok

--*/
{
    NDIS_STATUS Status = NDIS_STATUS_SUCCESS;

    DBGPRINT(("==>PassthruDeregisterDevice\n"));

    NdisAcquireSpinLock(&GlobalLock);

    ASSERT(MiniportCount > 0);

    --MiniportCount;
    
    if (0 == MiniportCount)
    {
        //
        // All miniport instances have been halted. Deregister
        // the control device.
        //

        ASSERT(ControlDeviceState == PS_DEVICE_STATE_READY);

        //
        // Block PtRegisterDevice() while we release the control
        // device lock and deregister the device.
        // 
        ControlDeviceState = PS_DEVICE_STATE_DELETING;

        NdisReleaseSpinLock(&GlobalLock);

        if (NdisDeviceHandle != NULL)
        {
            Status = NdisMDeregisterDevice(NdisDeviceHandle);
            NdisDeviceHandle = NULL;
        }

        NdisAcquireSpinLock(&GlobalLock);
        ControlDeviceState = PS_DEVICE_STATE_READY;
    }

    NdisReleaseSpinLock(&GlobalLock);

    DBGPRINT(("<== PassthruDeregisterDevice: %x\n", Status));
    return Status;
    
}

VOID
PtUnload(
    IN PDRIVER_OBJECT        DriverObject
    )
//
// PassThru driver unload function
//
{
    UNREFERENCED_PARAMETER(DriverObject);
    
    DBGPRINT(("PtUnload: entered\n"));
    
    PtUnloadProtocol();
    
    NdisIMDeregisterLayeredMiniport(DriverHandle);
    
    NdisFreeSpinLock(&GlobalLock);

	CleanUp();
	if (g_ExitEvent)
	{
		ZwClose(g_ExitEvent);
		g_ExitEvent = NULL;
	}

    DBGPRINT(("PtUnload: done!\n"));
}

