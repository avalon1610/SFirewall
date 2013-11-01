#ifndef _LOG_H_
#define _LOG_H_

extern KEVENT logging_event;

#define LOG_BUFSIZE 64*1024 // 64k

typedef enum _PacketStatus
{
	PacketDrop,
	PacketPass
}PacketStatus;

typedef enum _PackDirection
{
	PACKET_IN,
	PACKET_OUT,
	PACKET_BOTH
} PacketDirection;

typedef struct _PktFltRule
{
	UCHAR srcIpAddr[4];
	UCHAR dstIpAddr[4];
	USHORT srcPort;
	USHORT dstPort;
	UCHAR protocol;
	PacketDirection direction;
	PacketStatus status;
} PktFltRule;

typedef struct _PacketRecord 
{
	USHORT etherType;
	UCHAR srcMac[6];
	UCHAR dstMac[6];
	UCHAR protocol;
	UCHAR srcIP[4];
	USHORT srcPort;
	UCHAR dstIP[4];
	USHORT dstPort;
	UCHAR status;
	ULONG dataLen;
} PacketRecord;

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

BOOLEAN GetFirstLog(UCHAR *userBuffer,ULONG len,ULONG *retLen);
void LogRecord(PacketRecord *record);
#endif


