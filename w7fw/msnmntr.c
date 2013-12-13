#include "ntddk.h"
#include "ntstrsafe.h"
#include "fwpmk.h"

#pragma warning(push)
#pragma warning(disable:4201)
#include "fwpsk.h"
#pragma warning(pop)

#include "ioctl.h"
#include "msnmntr.h"
#include "ctl.h"
#include "notify.h"

#define INITGUID
#include <guiddef.h>
#include "mntrguid.h"

#define WPP_CONTROL_GUIDS \
	WPP_DEFINE_CONTROL_GUID(MsnMntrMonitor,(dd65554d,9925,49d1,83b6,46125feb4207),\
	WPP_DEFINE_BIT(TRACE_FLOW_ESTABLISHED)\
	WPP_DEFINE_BIT(TRACE_STATE_CHANGE)\
	WPP_DEFINE_BIT(TRACE_LAYER_NOTIFY))
#include "msnmntr.tmh"

#define TAG_NAME_CALLOUT 'CnoM'

UINT32 flowEstablishedID = 0;
UINT32 streamId = 0;
long monitoringEnabled = 0;
LIST_ENTRY flowContextList;
KSPIN_LOCK flowContextListLock;

NTSTATUS MonitorCoFlowEstablishedNotifyV4(IN FWPS_CALLOUT_NOTIFY_TYPE notifyType,
										  IN const GUID *filterKey,
										  IN const FWPS_FILTER *filter);

NTSTATUS MonitorCoStreamNotifyV4(IN FWPS_CALLOUT_NOTIFY_TYPE notifyType,
								 IN const GUID *filterKey,
								 IN const FWPS_FILTER *filter);

VOID MonitorCoStreamFlowDeletion(IN UINT16 layerId,
								 IN UINT32 calloutId,
								 IN UINT64 flowContext);

#if(NTDDI_VERSION >= NTDDI_WIN7)
NTSTATUS MonitorCoFlowEstablishedCalloutV4(IN const FWPS_INCOMING_VALUES *inFixedValues,
										   IN const FWPS_INCOMING_METADATA_VALUES *inMetaValues,
										   IN VOID *packet,
										   IN const void *classifyContext,
										   IN const FWPS_FILTER *filter,
										   IN UINT64 flowContext,
										   OUT FWPS_CLASSIFY_OUT *classifyOut);
#else if(NTDDI_VERSION < NTDDI_WIN7)
NTSTATUS MonitorCoFlowEstablishedCalloutV4(IN const FWPS_INCOMING_VALUES *inFixedValues,
										   IN const FWPS_INCOMING_METADATA_VALUES *inMetaValues,
										   IN VOID *packet,
										   IN const FWPS_FILTER *filter,
										   IN UINT64 flowContext,
										   OUT FWPS_CLASSIFY_OUT *classifyOut);
#endif

#if(NTDDI_VERSION >= NTDDI_WIN7)
NTSTATUS MonitorCoStreamCalloutV4(IN const FWPS_INCOMING_VALUES *inFixedValues,
								  IN const FWPS_INCOMING_METADATA_VALUES *inMetaValues,
								  IN VOID *packet,
								  IN const void *classifyContext,
								  IN const FWPS_FILTER *filter,
								  IN UINT64 flowContext,
								  OUT FWPS_CLASSIFY_OUT *classifyOut);
#else if(NTDDI_VERSION < NTDDI_WIN7)
NTSTATUS MonitorCoStreamCalloutV4(IN const FWPS_INCOMING_VALUES *inFixedValues,
								  IN const FWPS_INCOMING_METADATA_VALUES *inMetaValues,
								  IN VOID *packet,
								  IN const FWPS_FILTER *filter,
								  IN UINT64 flowContext,
								  OUT FWPS_CLASSIFY_OUT *classifyOut);
#endif

NTSTATUS MonitorCoRegisterCallout(IN OUT void *deviceObject,
								  IN FWPS_CALLOUT_CLASSIFY_FN ClassifyFunction,
								  IN FWPS_CALLOUT_NOTIFY_FN NotifyFunction,
								  IN FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN FlowDeleteFunction,
								  IN GUID const *calloutKey,
								  IN UINT32 flags,
								  OUT UINT32 *calloutId)
{
	FWPS_CALLOUT sCallout;
	NTSTATUS status = STATUS_SUCCESS;

	RtlZeroMemory(&sCallout,sizeof(FWPS_CALLOUT));
	sCallout.calloutKey = *calloutKey;
	sCallout.flags = flags;
	sCallout.classifyFn = ClassifyFunction;
	sCallout.notifyFn = NotifyFunction;
	sCallout.flowDeleteFn = FlowDeleteFunction;

	status = FwpsCalloutRegister(deviceObject,&sCallout,calloutId);
	return status;
}


NTSTATUS MonitorCoRegisterCallouts(IN OUT void *deviceObject)
{
	NTSTATUS status;
	status = MonitorCoRegisterCallout(deviceObject,
									  MonitorCoFlowEstablishedCalloutV4,
									  MonitorCoFlowEstablishedNotifyV4,
									  NULL,	// need not a flow delete function at this layer.
									  &MSN_MONITOR_FLOW_ESTABLISHED_CALLOUT_V4,
									  0,	// NO flags
									  &flowEstablishedID);
	if (NT_SUCCESS(status))
	{
		status = MonitorCoRegisterCallout(deviceObject,
										  MonitorCoStreamCalloutV4,
										  MonitorCoStreamNotifyV4,
										  MonitorCoStreamFlowDeletion,
										  &MSN_MONITOR_STREAM_CALLOUT_V4,
										  FWP_CALLOUT_FLAG_CONDITIONAL_ON_FLOW,
										  &streamId);
	}
	return status;
}

NTSTATUS MonitorCoUnregisterCallout(IN GUID const *calloutKey)
{
	NTSTATUS status;
	status = FwpsCalloutUnregisterByKey(calloutKey);
	return status;
}

NTSTATUS MonitorCoUnregisterCallouts()
{
	NTSTATUS status;
	status = MonitorCoUnregisterCallout(&MSN_MONITOR_FLOW_ESTABLISHED_CALLOUT_V4);
	if (NT_SUCCESS(status))
		status = MonitorCoUnregisterCallout(&MSN_MONITOR_STREAM_CALLOUT_V4);
	return status;
}

NTSTATUS MonitorCoInitialize(PDEVICE_OBJECT deviceObject)
{
	NTSTATUS status;
	InitializeListHead(&flowContextList);
	KeInitializeSpinLock(&flowContextListLock);
	status = MonitorCoRegisterCallouts(deviceObject);
	return status;
}

void MonitorCoUninitialize()
{
	KLOCK_QUEUE_HANDLE lockHandle;
	// Make sure don't associate any more contexts to flows
	MonitorCoDisableMonitoring();

	KeAcquireInStackQueuedSpinLock(&flowContextListLock,&lockHandle);
	while (!IsListEmpty(&flowContextList))
	{
		FLOW_DATA *flowContext;
		LIST_ENTRY *entry;
		NTSTATUS status;

		entry = RemoveHeadList(&flowContextList);
		flowContext = CONTAINING_RECORD(entry,FLOW_DATA,listEntry);
		flowContext->deleting = TRUE;
		status = FwpsFlowRemoveContext(flowContext->flowHandle,FWPS_LAYER_STREAM_V4,streamId);
		ASSERT(NT_SUCCESS(status));
	}

	KeReleaseInStackQueuedSpinLock(&lockHandle);
	MonitorCoUnregisterCallouts();
}

NTSTATUS MonitorCoEnableMonitoring(IN MONITOR_SETTING *monitorSettings)
{
	KLOCK_QUEUE_HANDLE lockHandle;
	if (!monitorSettings)
		return STATUS_INVALID_PARAMETER;

	DoTraceMessage(TRACE_STATE_CHANGE,"Enabling monitoring.\r\n");
	KeAcquireInStackQueuedSpinLock(&flowContextListLock,&lockHandle);
	monitoringEnabled = 1;
	KeReleaseInStackQueuedSpinLock(&lockHandle);
	return STATUS_SUCCESS;
}

void MonitorCoDisableMonitoring()
{
	KLOCK_QUEUE_HANDLE lockHandle;
	DoTraceMessage(TRACE_STATE_CHANGE,"Disabling monitoring.\r\n");
	KeAcquireInStackQueuedSpinLock(&flowContextListLock,&lockHandle);
	monitoringEnabled = 0;
	KeReleaseInStackQueuedSpinLock(&lockHandle);
}

VOID MonitorCoRemoveFlowContext(IN FLOW_DATA *flowContext)
{
	KLOCK_QUEUE_HANDLE lockHandle;
	KeAcquireInStackQueuedSpinLock(&flowContextListLock,&lockHandle);
	RemoveEntryList(&flowContext->listEntry);
	KeReleaseInStackQueuedSpinLock(&lockHandle);
}

void MonitorCoCleanupFlowContext(IN FLOW_DATA *flowContext)
{
	if (!flowContext->deleting)
		MonitorCoRemoveFlowContext(flowContext);

	if (flowContext->processPath)
		ExFreePoolWithTag(flowContext->processPath,TAG_NAME_CALLOUT);

	ExFreePoolWithTag(flowContext,TAG_NAME_CALLOUT);
}

NTSTATUS MonitorCoInsertFlowContext(IN FLOW_DATA *flowContext)
{
	KLOCK_QUEUE_HANDLE lockHandle;
	NTSTATUS status;

	KeAcquireInStackQueuedSpinLock(&flowContextListLock,&lockHandle);
	// disabled monitoring after associate the context to the flow
	if (monitoringEnabled)
	{
		DoTraceMessage(TRACE_FLOW_ESTABLISHED,"Creating flow for traffic.\r\n");
		InsertTailList(&flowContextList,&flowContext->listEntry);
		status = STATUS_SUCCESS;
	}
	else
	{
		DoTraceMessage(TRACE_FLOW_ESTABLISHED,"Unable to create flow, driver shutting down.\r\n");
		status = STATUS_SHUTDOWN_IN_PROGRESS;
	}

	KeReleaseInStackQueuedSpinLock(&lockHandle);
	return status;
}

UINT64 MonitorCoCreateFlowContext(IN const FWPS_INCOMING_VALUES *inFixedValues,
								  IN const FWPS_INCOMING_METADATA_VALUES *inMetaValues,
								  OUT UINT64 *flowHandle)
{
	FLOW_DATA *flowContext = NULL;
	NTSTATUS status;
	FWP_BYTE_BLOB *processPath;
	UINT32 index;

	if (!FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues,FWPS_METADATA_FIELD_PROCESS_PATH))
	{
		status = STATUS_NOT_FOUND;
		goto cleanup;
	}

	processPath = inMetaValues->processPath;

	// Flow context is always created at the Flow established layer.

	// flowContext gets deleted in MonitorCoCleanupFlowContext
#pragma warning(suppress:28197)
	flowContext = ExAllocatePoolWithTag(NonPagedPool,sizeof(FLOW_DATA),TAG_NAME_CALLOUT);
	if (!flowContext)
		return (UINT64)NULL;

	RtlZeroMemory(flowContext,sizeof(FLOW_DATA));
	flowContext->deleting = FALSE;
	flowContext->flowHandle = inMetaValues->flowHandle;
	*flowHandle = flowContext->flowHandle;

	index = FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_ADDRESS;
	flowContext->localAddressV4 = inFixedValues->incomingValue[index].value.uint32;
	index = FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_PORT;
	flowContext->localPort = inFixedValues->incomingValue[index].value.uint16;
	index = FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_ADDRESS;
	flowContext->remoteAddressV4 = inFixedValues->incomingValue[index].value.uint32;
	index = FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_PORT;
	flowContext->remotePort = inFixedValues->incomingValue[index].value.uint16;
	index = FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_PROTOCOL;
	flowContext->ipProto = inFixedValues->incomingValue[index].value.uint16;

#pragma warning(suppress:28197)
	flowContext->processPath = ExAllocatePoolWithTag(NonPagedPool,processPath->size,TAG_NAME_CALLOUT);
	if (!flowContext->processPath)
	{
		status = STATUS_NOT_FOUND;
		goto cleanup;
	}

	RtlCopyMemory(flowContext->processPath,processPath->data,processPath->size);
	status = MonitorCoInsertFlowContext(flowContext);

cleanup:
	if (!NT_SUCCESS(status) && flowContext)
	{
		MonitorCoCleanupFlowContext(flowContext);
		flowContext = NULL;
	}

	return (UINT64) flowContext;
}

#if(NTDDI_VERSION >= NTDDI_WIN7)
NTSTATUS MonitorCoFlowEstablishedCalloutV4(IN const FWPS_INCOMING_VALUES *inFixedValues,
										   IN const FWPS_INCOMING_METADATA_VALUES *inMetaValues,
										   IN VOID *packet,
										   IN const void *classifyContext,
										   IN const FWPS_FILTER *filter,
										   IN UINT64 flowContext,
										   OUT FWPS_CLASSIFY_OUT *classifyOut)
#else if(NTDDI_VERSION < NTDDI_WIN7)
NTSTATUS MonitorCoFlowEstablishedCalloutV4(IN const FWPS_INCOMING_VALUES *inFixedValues,
										   IN const FWPS_INCOMING_METADATA_VALUES *inMetaValues,
										   IN VOID *packet,
										   IN const FWPS_FILTER *filter,
										   IN UINT64 flowContext,
										   OUT FWPS_CLASSIFY_OUT *classifyOut)
#endif
{
	NTSTATUS status = STATUS_SUCCESS;
	UINT64 flowHandle;
	UINT64 flowContextLocal;

	UNREFERENCED_PARAMETER(packet);
#if(NTDDI_VERSION >= NTDDI_WIN7)
	UNREFERENCED_PARAMETER(classifyContext);
#endif
	UNREFERENCED_PARAMETER(filter);
	UNREFERENCED_PARAMETER(flowContext);

	if (monitoringEnabled)
	{
		flowContextLocal = MonitorCoCreateFlowContext(inFixedValues,inMetaValues,&flowHandle);
		if (!flowContextLocal)
		{
			classifyOut->actionType = FWP_ACTION_CONTINUE;
			goto cleanup;
		}

		status = FwpsFlowAssociateContext(flowHandle,
										  FWPS_LAYER_STREAM_V4,
										  streamId,
										  flowContextLocal);
		if (!NT_SUCCESS(status))
		{
			classifyOut->actionType = FWP_ACTION_CONTINUE;
			goto cleanup;
		}
	}

	classifyOut->actionType = FWP_ACTION_PERMIT;

cleanup:
	return status;
}

#if(NTDDI_VERSION >= NTDDI_WIN7)
NTSTATUS MonitorCoStreamCalloutV4(IN const FWPS_INCOMING_VALUES *inFixedValues,
								  IN const FWPS_INCOMING_METADATA_VALUES *inMetaValues,
								  IN VOID *packet,
								  IN const void *classifyContext,
								  IN const FWPS_FILTER *filter,
								  IN UINT64 flowContext,
								  OUT FWPS_CLASSIFY_OUT *classifyOut)
#else if(NTDDI_VERSION < NTDDI_WIN7)
NTSTATUS MonitorCoStreamCalloutV4(IN const FWPS_INCOMING_VALUES *inFixedValues,
								  IN const FWPS_INCOMING_METADATA_VALUES *inMetaValues,
								  IN VOID *packet,
								  IN const FWPS_FILTER *filter,
								  IN UINT64 flowContext,
								  OUT FWPS_CLASSIFY_OUT *classifyOut)
#endif
{
	FLOW_DATA *flowData;
	FWPS_STREAM_CALLOUT_IO_PACKET *streamPacket;
	NTSTATUS status = STATUS_SUCCESS;
	BOOLEAN inbound;

	UNREFERENCED_PARAMETER(inFixedValues);
	UNREFERENCED_PARAMETER(inMetaValues);
#if(NTDDI_VERSION >= NTDDI_WIN7)
	UNREFERENCED_PARAMETER(classifyContext);
#endif
	UNREFERENCED_PARAMETER(filter);
	UNREFERENCED_PARAMETER(flowContext);

	if (!monitoringEnabled)
		goto cleanup;

	streamPacket = (FWPS_STREAM_CALLOUT_IO_PACKET *)packet;
	if (streamPacket->streamData != NULL &&
		streamPacket->streamData->dataLength != 0)
	{
		flowData = *(FLOW_DATA **)(UINT64 *)&flowContext;
		inbound = (BOOLEAN)((streamPacket->streamData->flags & FWPS_STREAM_FLAG_RECEIVE) == FWPS_STREAM_FLAG_RECEIVE);
		status = MonitorNfNotifyMessage(streamPacket->streamData,
										inbound,
										flowData->localPort,
										flowData->remotePort);
	}
cleanup:
	classifyOut->actionType = FWP_ACTION_CONTINUE;
	return status;
}

NTSTATUS MonitorCoFlowEstablishedNotifyV4(IN FWPS_CALLOUT_NOTIFY_TYPE notifyType,
										  IN const GUID *filterKey,
										  IN const FWPS_FILTER *filter )
{
	UNREFERENCED_PARAMETER(filterKey);
	UNREFERENCED_PARAMETER(filter);

	switch(notifyType)
	{
	case FWPS_CALLOUT_NOTIFY_ADD_FILTER:
		DoTraceMessage(TRACE_LAYER_NOTIFY,
					   "Filter Added to Flow Established layer.\r\n");
		break;
	case FWPS_CALLOUT_NOTIFY_DELETE_FILTER:
		DoTraceMessage(TRACE_LAYER_NOTIFY,
					   "Filter Deleted from Flow Established layer.\r\n");
		break;
	}
	return STATUS_SUCCESS;
}

NTSTATUS MonitorCoStreamNotifyV4(IN FWPS_CALLOUT_NOTIFY_TYPE notifyType,
								 IN const GUID *filterKey,
								 IN const FWPS_FILTER *filter )
{
	UNREFERENCED_PARAMETER(notifyType);
	UNREFERENCED_PARAMETER(filterKey);
	UNREFERENCED_PARAMETER(filter);

	switch(notifyType)
	{
	case FWPS_CALLOUT_NOTIFY_ADD_FILTER:
		DoTraceMessage(TRACE_LAYER_NOTIFY,
					   "Filter Added to Stream layer.\r\n");
		break;
		
	case FWPS_CALLOUT_NOTIFY_DELETE_FILTER:
		DoTraceMessage(TRACE_LAYER_NOTIFY,
					   "Filter Deleted from Stream layer.\r\n");
		break;
	}
	return STATUS_SUCCESS;
}

VOID MonitorCoStreamFlowDeletion(IN UINT16 layerId,
								 IN UINT32 calloutId,
								 IN UINT64 flowContext )
{
	FLOW_DATA **flowData;
	UINT64 *flow;
	
	UNREFERENCED_PARAMETER(layerId);
	UNREFERENCED_PARAMETER(calloutId);

	flow = &flowContext;
	flowData = ((FLOW_DATA**)flow);

	MonitorCoCleanupFlowContext(*flowData);
}
