#include "precomp.h"

LIST_ENTRY log_list;
KMUTEX log_mutex;

BOOLEAN IsLogBufferFull(LogBuffer *log_buffer,PacketRecord *record)
{
	if (log_buffer == NULL)
	{
		return TRUE;
	}

	if (log_buffer->len + record->dataLen + sizeof(PacketRecord) >= MAX_LOGSIZE)
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

void NewLogBuffer(PacketRecord *record)
{
	LogBuffer *log_buffer;
	//KIRQL old_irql;
	ULONG record_len;
	UCHAR *record_buf;
	UCHAR *log;

	log_buffer = (LogBuffer *)ALLOC_LOG_BUFFER();
	INIT_LOG_BUFFER(log_buffer);
	record_len = sizeof(PacketRecord) + record->dataLen;
	record_buf = (UCHAR *)record;
	log = (UCHAR *)log_buffer + sizeof(LogBuffer);
	RtlCopyMemory(log,record_buf,record_len);
	log_buffer->len += record_len;
	MUTEX_ACQUIRE(log_mutex);
	InsertTailList(&log_list,&log_buffer->next);
	MUTEX_RELEASE(log_mutex);
}

void WriteLogBuffer(PacketRecord *record)
{
	KIRQL irql;
	LogBuffer *log_buffer = NULL;
	LIST_ENTRY *nextLogBuf = &log_list;
	irql = KeGetCurrentIrql();
	ASSERT(irql == PASSIVE_LEVEL);
	MUTEX_ACQUIRE(log_mutex);
	irql = KeGetCurrentIrql();
	ASSERT(irql == PASSIVE_LEVEL);
	while (nextLogBuf->Flink != &log_list)
	{
		nextLogBuf = nextLogBuf->Flink;
	}

	if (nextLogBuf != &log_list)
	{
		log_buffer = CONTAINING_RECORD(nextLogBuf,LogBuffer,next);

		if (IsLogBufferFull(log_buffer,record))
		{
			MUTEX_RELEASE(log_mutex);
			NewLogBuffer(record);
		}
		else
		{
			UCHAR *record_buf;
			ULONG record_len;
			UCHAR *log = ((UCHAR *)log_buffer) + sizeof(LogBuffer) + log_buffer->len;

			record_len = sizeof(PacketRecord) + record->dataLen;
			record_buf = (UCHAR *)record;

			RtlCopyMemory(log,record_buf,record_len);
			log_buffer->len += record_len;
			MUTEX_RELEASE(log_mutex);
		}
	}
	else
	{
		MUTEX_RELEASE(log_mutex);
		NewLogBuffer(record);
	}
}

// run at passive level
VOID DispatchWriteLog(PDEVICE_OBJECT devObj,PVOID Context)
{
	WorkItemCtx *work_item_ctx = (WorkItemCtx *)Context;
	UNREFERENCED_PARAMETER(devObj);
	WriteLogBuffer(work_item_ctx->record);
	IoFreeWorkItem(work_item_ctx->work_item);
	PMGR_FREE_MEM(work_item_ctx->record);
	PMGR_FREE_MEM(work_item_ctx);
}

void LogRecord(PacketRecord *record)
{
	KIRQL cur_irql = KeGetCurrentIrql();
	if (cur_irql != PASSIVE_LEVEL)
	{
		PIO_WORKITEM work_item = IoAllocateWorkItem(ControlDeviceObject);
		WorkItemCtx *work_item_ctx;
		PMGR_ALLOC_MEM(work_item_ctx,sizeof(WorkItemCtx));
		work_item_ctx->record = record;
		work_item_ctx->work_item = work_item;

		IoQueueWorkItem(work_item,DispatchWriteLog,DelayedWorkQueue,work_item_ctx);
	}
	else
	{
		ASSERT(cur_irql == PASSIVE_LEVEL);
		WriteLogBuffer(record);
		PMGR_FREE_MEM(record);
	}
}

BOOLEAN GetFirstLog(UCHAR *userBuffer,ULONG len,ULONG *retLen)
{
	if (len < LOG_BUFSIZE)
		return FALSE;
	else
	{
		//KIRQL irql;
		LogBuffer *log_buffer = NULL;
		LIST_ENTRY *log_entry = log_list.Flink;
		MUTEX_ACQUIRE(log_mutex);

		if (log_entry != &log_list)
		{
			UCHAR *log;
			ULONG log_len;
			log_buffer = CONTAINING_RECORD(log_entry,LogBuffer,next);

			log = ((UCHAR *)log_buffer) + sizeof(LogBuffer);
			log_len = log_buffer->len;

			RtlCopyMemory(userBuffer,log,log_len);
			*retLen = log_len;

			RemoveEntryList(log_entry);

			FREE_LOG_BUFFER(log_buffer);
			MUTEX_RELEASE(log_mutex);
		}
		else
		{
			MUTEX_RELEASE(log_mutex);
			*retLen = 0;
		}

		return TRUE;
	}
}
