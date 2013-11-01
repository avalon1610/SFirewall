#ifndef _PACKET_MGR_H_
#define _PACKET_MGR_H_
#include "log.h"

extern INT packetmgrDebugLevel;
#define PACKET_FILTER_TAG 'pAck'

#define IOCTL_GET_LOG CTL_CODE(FILE_DEVICE_UNKNOWN,0x801,METHOD_BUFFERED,FILE_READ_DATA|FILE_WRITE_DATA)
#define IOCTL_ADD_RULE CTL_CODE(FILE_DEVICE_UNKNOWN,0x802,METHOD_BUFFERED,FILE_READ_DATA|FILE_WRITE_DATA)

#define DL_EXTRA_LOUD	20
#define DL_VERY_LOUD	10
#define DL_LOUD			8
#define DL_INFO			6
#define DL_WARN			4
#define DL_ERROR		2
#define DL_FATAL		0

#define DEBUGP(lev,stmt)					\
{											\
	if ((lev <= packetmgrDebugLevel))		\
	{										\
		DbgPrint("S7FW: ");DbgPrint stmt;	\
	}										\
}											\

#define TCP_PROTOCOL 0x06
#define UDP_PROTOCOL 0x11
#define ICMP_PROTOCOL 0x01

#define IP_TYPE 0x0008
#define ARP_TYPE 0x0608
#define RARP_TYPE 0x3580

#define DHCP_SRC_PORT	103
#define DHCP_DST_PORT	104
#define HTTP_PORT		80

#define PMGR_INIT_LIST_HEAD(_pList)			InitializeListHead(_pList)
#define PMGR_IS_LIST_EMPTY(_pList)			IsListEmpty(_pList)
#define PMGR_INSERT_HEAD_LIST(_pList,_pEnt)	InsertHeadList(_pList,_pEnt)
#define PMGR_INSERT_TAIL_LIST(_pList,_pEnt)	InsertTailList(_pList,_pEnt)
#define PMGR_REMOVE_ENTRY_LIST(_pEnt)		RemoveEntryList(_pEnt)

#define PMGR_ALLOC_MEM(_pVar,_Size) NdisAllocateMemoryWithTag((PVOID *)(&_pVar),(_Size),PACKET_FILTER_TAG)
#define PMGR_FREE_MEM(_pMem) NdisFreeMemory(_pMem,0,0)

typedef struct _EtherHeader
{
	UCHAR dstMac[6];
	UCHAR srcMac[6];
	USHORT etherType;
} EtherHeader;

typedef struct _IPHeader
{
	UCHAR versionLen;
	UCHAR serviceType;
	USHORT ipPackLen;
	USHORT flag;
	USHORT pieceFlag;
	UCHAR ttl;
	UCHAR protocol;
	USHORT headerCheckSum;
	UCHAR srcIpAddr[4];
	UCHAR dstIpAddr[4];
} IPHeader;

typedef struct _UDPHeader
{
	USHORT srcPort;
	USHORT dstPort;
	USHORT udpLen;
	USHORT udpCheckSum;
} UDPHeader;

typedef struct _TCPHeader
{
	USHORT srcPort;
	USHORT dstPort;
	UINT seqNum;
	UINT ackNum;
	UCHAR rsvLen;
	UCHAR rsvFlag;
	USHORT windowSize;
	USHORT checkSum;
	USHORT urgentPointer;
} TCPHeader;

PacketStatus FilterPacket(PUCHAR packet_buf,ULONG len,PacketDirection direction);
UCHAR *PMgrGetIpData(IPHeader *ipHeader);
UCHAR *PMgrGetTcpData(TCPHeader *tcpHeader);
VOID PMgrGetPktData(IN PNDIS_PACKET Packet,OUT PUCHAR pDst,IN ULONG length);
VOID PMgrFreeRecvPkt(IN PADAPT pAdaptContext,IN PNDIS_PACKET pNdisPacket);
PNDIS_PACKET PMgrAllocRecvPkt(IN PADAPT pAdaptContext,IN UINT DataLength,OUT PUCHAR * ppDataBuffer);
#define IP_VERSION(versionLen) (((versionLen)&(0xF0))>>4)
#define IP_HEADERLEN(versionLen) (versionLen)&(0x0F)
#define TCP_HEADERLEN(rsvLen) (((rsvLen)&(0xF0))>>4)
#define MIN(a,b) ((a) <= (b) ? (a) : (b))
#endif