#ifndef _LOG_H_
#define _LOG_H_
#include "..\include\userioctrl.h"

extern KEVENT logging_event;

typedef struct _WorkItemCtx
{
	PIO_WORKITEM work_item;
	PacketRecord *record;
} WorkItemCtx;

typedef struct _LogBuffer
{
	LIST_ENTRY next;
	ULONG len;
}LogBuffer,*PLogBuffer;

#define MUTEX_INIT(v)		KeInitializeMutex(&v,0)
#define MUTEX_ACQUIRE(v)	KeWaitForMutexObject(&v,Executive,KernelMode,FALSE,NULL)
#define MUTEX_RELEASE(v)	KeReleaseMutex(&v,FALSE)

#define LOG_TAG 'golR'
#define FREE_LOG_BUFFER(Log) ExFreePoolWithTag(Log,LOG_TAG)
#define INIT_LOG_BUFFER(Log) Log->len = 0

#define MAX_LOGSIZE (LOG_BUFSIZE - sizeof(LogBuffer))
#define ALLOC_LOG_BUFFER() ExAllocatePoolWithTag(PagedPool,LOG_BUFSIZE,LOG_TAG)

BOOLEAN GetFirstLog();
void LogRecord(PacketRecord *record);
void InitLogRecord();
void PushLogWorkerThread(IN PVOID pContext);
#endif


