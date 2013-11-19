#include "precomp.h"

INT packetmgrDebugLevel = DL_LOUD;

LIST_ENTRY pkt_flt_list;
KSPIN_LOCK pkt_flt_lock;

VOID InitPktFltList()
{
	InitializeListHead(&pkt_flt_list);
	KeInitializeSpinLock(&pkt_flt_lock);
}

NTSTATUS AddPktFltRule(PktFltRule *pkt_flt_item)
{
	KIRQL oldIrql;
	PktFltEntry *pkt_flt_entry;
	PMGR_ALLOC_MEM(pkt_flt_entry,sizeof(PktFltEntry));
	NdisZeroMemory(pkt_flt_entry,sizeof(PktFltEntry));
	NdisMoveMemory(&pkt_flt_entry->pkt_flt_rule,pkt_flt_item,sizeof(PktFltRule));
	KeAcquireSpinLock(&pkt_flt_lock,&oldIrql);
	InsertHeadList(&pkt_flt_list,&pkt_flt_entry->next);
	KeReleaseSpinLock(&pkt_flt_lock,oldIrql);
	return STATUS_SUCCESS;
}

USHORT ntoh(USHORT us)
{
	UCHAR ch[2];
	USHORT *n;
	ch[0] = *((UCHAR *)(&us) + 1);
	ch[1] = *((UCHAR *)(&us));
	n = (USHORT *)ch;
	return (*n);
}
PNDIS_PACKET PMgrAllocRecvPkt(IN PADAPT pAdaptContext,IN UINT DataLength,OUT PUCHAR * ppDataBuffer)
{
	PNDIS_PACKET	pNdisPacket;
	PNDIS_BUFFER	pNdisBuffer;
	PUCHAR			pDataBuffer;
	NDIS_STATUS		Status;

	pNdisPacket = NULL;
	pNdisBuffer = NULL;
	pDataBuffer = NULL;

	do 
	{
		PMGR_ALLOC_MEM(pDataBuffer,DataLength);
		if (pDataBuffer == NULL)
		{
			DEBUGP(DL_FATAL,("AllocRecvPkt:open %p,failed to alloc data buffer %d bytes\n",pAdaptContext,DataLength));
			break;
		}

		NdisAllocateBuffer(&Status,
						   &pNdisBuffer,
						   pAdaptContext->RecvBufferPoolHandle,
						   pDataBuffer,
						   DataLength);
		if (Status != NDIS_STATUS_SUCCESS)
		{
			DEBUGP(DL_FATAL,("AllocateRecvPkt:open %p,failed to alloc NDIS buffer,%d bytes\n",pAdaptContext,DataLength));
			break;
		}

		NdisAllocatePacket(&Status,&pNdisPacket,pAdaptContext->RecvBufferPoolHandle);
		if (Status != NDIS_STATUS_SUCCESS)
		{
			DEBUGP(DL_FATAL,("AllocateRecvPkt:open %p,failed to alloc NDIS packet,%d bytes\n",pAdaptContext,DataLength));
		}

		NDIS_SET_PACKET_STATUS(pNdisPacket,0);
		RCV_PKT_TO_ORIGINAL_BUFFER(pNdisPacket) = NULL;
		NdisChainBufferAtFront(pNdisPacket,pNdisBuffer);
		*ppDataBuffer = pDataBuffer;

	} while (FALSE);

	if (pNdisPacket == NULL)
	{
		// clean up
		if (pNdisBuffer != NULL)
			NdisFreeBuffer(pNdisBuffer);
		if (pDataBuffer != NULL)
			PMGR_FREE_MEM(pDataBuffer);
	}

	return pNdisPacket;
}

VOID PMgrFreeRecvPkt(IN PADAPT pAdaptContext,IN PNDIS_PACKET pNdisPacket)
{
	PNDIS_BUFFER	pNdisBuffer;
	UINT			TotalLength;
	UINT			BufferLength;
	PUCHAR			pCopyData;

	if (NdisGetPoolFromPacket(pNdisPacket) == pAdaptContext->RecvBufferPoolHandle)
	{
		// this is a local copy
		NdisGetFirstBufferFromPacket(pNdisPacket,
									 &pNdisBuffer,
									 (PVOID *)&pCopyData,
									 &BufferLength,
									 &TotalLength);

		NdisFreePacket(pNdisPacket);
		NdisFreeBuffer(pNdisBuffer);
		PMGR_FREE_MEM(pCopyData);
	}
	else
		NdisReturnPackets(&pNdisPacket,1);
}

VOID PMgrGetPktData(IN PNDIS_PACKET Packet,OUT PUCHAR pDst,IN ULONG length)
{
	PNDIS_BUFFER pNdisBuffer;
	UINT BytesAvailable;
	UINT BytesRemaining = length;
	PUCHAR pSrc;

	pNdisBuffer = NDIS_PACKET_FIRST_NDIS_BUFFER(Packet);

	// Copy the data in the received packet into the buffer provided by the client.
	// If the length of the receive packet is greater than length of the given buffer,
	// we just copy as many bytes as we can. Once the buffer is full, we just discard
	// the rest of the data, and complete the IRP sucessfully even we only did a partial copy.
	while (BytesRemaining && (pNdisBuffer != NULL))
	{
		NdisQueryBuffer(pNdisBuffer,(PVOID *)&pSrc,&BytesAvailable);
		if (BytesAvailable)
		{
			ULONG BytesToCopy = MIN(BytesAvailable,BytesRemaining);
			NdisMoveMemory(pDst,pSrc,BytesToCopy);
			BytesRemaining -= BytesToCopy;
			pDst += BytesToCopy;
		}

		NdisGetNextBuffer(pNdisBuffer,&pNdisBuffer);
	}
}

PacketStatus IsPacketAllowed(UCHAR *srcIpAddr,UCHAR *dstIpAddr,USHORT srcPort,
							 USHORT dstPort,USHORT protocol,PacketDirection direction)
{
	PktFltEntry *entry = NULL;
	LIST_ENTRY *current = pkt_flt_list.Flink;
	PktFltRule *rule;

	while(current != &pkt_flt_list)
	{
		entry = CONTAINING_RECORD(current,PktFltEntry,next);
		rule = &(entry->pkt_flt_rule);
		if (((rule->srcIpAddr[0] == srcIpAddr[0] && 
			rule->srcIpAddr[1] == srcIpAddr[1] && 
			rule->srcIpAddr[2] == srcIpAddr[2] &&
			rule->srcIpAddr[3] == srcIpAddr[3]) || 
			rule->srcIpAddr[0] == '\0') &&
			((rule->dstIpAddr[0] == dstIpAddr[0] && 
			rule->dstIpAddr[1] == dstIpAddr[1] && 
			rule->dstIpAddr[2] == dstIpAddr[2] &&
			rule->dstIpAddr[3] == dstIpAddr[3]) || 
			rule->dstIpAddr[0] == '\0') &&
			(rule->srcPort == srcPort || rule->srcPort == 0) &&
			(rule->dstPort == dstPort || rule->dstPort == 0) &&
			(rule->protocol == protocol || rule->protocol == 0) &&
			(rule->direction == PACKET_BOTH || rule->direction == direction || rule->direction == 0))	
			return rule->status;
		current = current->Flink;
	}

	return PacketPass;
}

PacketStatus FilterPacket(PUCHAR packet_buf,ULONG len,PacketDirection direction)
{
	EtherHeader *etherHeader;
	etherHeader = (EtherHeader *)packet_buf;

	UNREFERENCED_PARAMETER(len);

	DBGPRINT(("dst Mac %02x:%02x:%02x:%02x:%02x:%02x,src Mac %02x:%02x:%02x:%02x:%02x:%02x\n",
		etherHeader->dstMac[0],etherHeader->dstMac[1],etherHeader->dstMac[2],etherHeader->dstMac[3],
		etherHeader->dstMac[4],etherHeader->dstMac[5],
		etherHeader->srcMac[0],etherHeader->srcMac[1],etherHeader->srcMac[2],etherHeader->srcMac[3],
		etherHeader->srcMac[4],etherHeader->srcMac[5]));
	if (etherHeader->etherType == IP_TYPE)
	{
		IPHeader * ipHeader = (IPHeader *)(packet_buf + sizeof(EtherHeader));
		UCHAR *ipData;
		DBGPRINT(("ip version %d, src ip %d.%d.%d.%d,dst ip %d.%d.%d.%d\n",IP_VERSION(ipHeader->versionLen),
			ipHeader->srcIpAddr[0],ipHeader->srcIpAddr[1],ipHeader->srcIpAddr[2],ipHeader->srcIpAddr[3],
			ipHeader->dstIpAddr[0],ipHeader->dstIpAddr[1],ipHeader->dstIpAddr[2],ipHeader->dstIpAddr[3]));

		ipData = PMgrGetIpData(ipHeader);

		if (ipHeader->protocol == TCP_PROTOCOL)
		{
			PacketStatus status;
			TCPHeader *tcpHeader = (TCPHeader*)ipData;
			PacketRecord *record;
			USHORT srcPort = ntoh(tcpHeader->srcPort);
			USHORT dstPort = ntoh(tcpHeader->dstPort);
			DBGPRINT(("[TCP]Src Port %d,Dst Port %d\n",ntoh(tcpHeader->srcPort),ntoh(tcpHeader->dstPort)));
			status = IsPacketAllowed(ipHeader->srcIpAddr,ipHeader->dstIpAddr,ntoh(tcpHeader->srcPort),
				ntoh(tcpHeader->dstPort),TCP_PROTOCOL,direction);
			
			PMGR_ALLOC_MEM(record,sizeof(PacketRecord));
			NdisZeroMemory(record,sizeof(PacketRecord));
			record->dataLen = 0;
			NdisMoveMemory(&record->srcMac[0],&etherHeader->srcMac[0],6);
			NdisMoveMemory(&record->dstMac[0],&etherHeader->dstMac[0],6);
			NdisMoveMemory(&record->etherType,&etherHeader->etherType,sizeof(USHORT));
			NdisMoveMemory(&record->srcIP[0],&ipHeader->srcIpAddr[0],4);
			NdisMoveMemory(&record->dstIP[0],&ipHeader->dstIpAddr[0],4);
			NdisMoveMemory(&record->protocol,&ipHeader->protocol,1);
			NdisMoveMemory(&record->srcPort,&srcPort,sizeof(USHORT));
			NdisMoveMemory(&record->dstPort,&dstPort,sizeof(USHORT));
			NdisMoveMemory(&record->status,&status,sizeof(status));
			
			LogRecord(record);

			return status;
		}
		else if (ipHeader->protocol == UDP_PROTOCOL)
		{
			PacketStatus status;
			UDPHeader *udpHeader = (UDPHeader *)ipData;
			PacketRecord *record;
			USHORT srcPort = ntoh(udpHeader->srcPort);
			USHORT dstPort = ntoh(udpHeader->dstPort);
			DBGPRINT(("[UDP] Src Port %d,Dst Port %d\n",ntoh(udpHeader->srcPort),ntoh(udpHeader->dstPort)));
			status = IsPacketAllowed(ipHeader->srcIpAddr,ipHeader->dstIpAddr,ntoh(udpHeader->srcPort),
				ntoh(udpHeader->dstPort),UDP_PROTOCOL,direction);

			PMGR_ALLOC_MEM(record,sizeof(PacketRecord));
			NdisZeroMemory(record,sizeof(PacketRecord));
			record->dataLen = 0;
			NdisMoveMemory(&record->srcMac[0],&etherHeader->srcMac[0],6);
			NdisMoveMemory(&record->dstMac[0],&etherHeader->dstMac[0],6);
			NdisMoveMemory(&record->etherType,&etherHeader->etherType,sizeof(USHORT));
			NdisMoveMemory(&record->srcIP[0],&ipHeader->srcIpAddr[0],4);
			NdisMoveMemory(&record->dstIP[0],&ipHeader->dstIpAddr[0],4);
			NdisMoveMemory(&record->protocol,&ipHeader->protocol,1);
			NdisMoveMemory(&record->srcPort,&srcPort,sizeof(USHORT));
			NdisMoveMemory(&record->dstPort,&dstPort,sizeof(USHORT));
			NdisMoveMemory(&record->status,&status,sizeof(status));

			LogRecord(record);
			return status;

		}
		else 
		{
			PacketRecord *record;
			PacketStatus status = PacketPass;
			DBGPRINT(("Other Packet Received\n"));
			PMGR_ALLOC_MEM(record,sizeof(PacketRecord));
			NdisZeroMemory(record,sizeof(PacketRecord));
			record->dataLen = 0;
			NdisMoveMemory(&record->srcMac[0],&etherHeader->srcMac[0],6);
			NdisMoveMemory(&record->dstMac[0],&etherHeader->dstMac[0],6);
			NdisMoveMemory(&record->etherType,&etherHeader->etherType,sizeof(USHORT));
			NdisMoveMemory(&record->status,&status,sizeof(status));
			
			LogRecord(record);
			return status;
		}
	}
	else
	{
		PacketRecord *record;
		PacketStatus status = PacketPass;
		PMGR_ALLOC_MEM(record,sizeof(PacketRecord));
		NdisZeroMemory(record,sizeof(PacketRecord));
		record->dataLen = 0;
		NdisMoveMemory(&record->srcMac[0],&etherHeader->srcMac[0],6);
		NdisMoveMemory(&record->dstMac[0],&etherHeader->dstMac[0],6);
		NdisMoveMemory(&record->etherType,&etherHeader->etherType,sizeof(USHORT));
		NdisMoveMemory(&record->status,&status,sizeof(status));

		LogRecord(record);
		return status;
	}

	//return PacketPass;
}

UCHAR *PMgrGetIpData(IPHeader *ipHeader)
{
	UCHAR *ipData;
	UINT byteOffset = 4*(IP_HEADERLEN(ipHeader->versionLen));
	ipData = (UCHAR *)ipHeader + byteOffset;
	return ipData;
}

UCHAR *PMgrGetTcpData(TCPHeader *tcpHeader)
{
	UCHAR *tcpData;
	UINT byteOffset = 4*(TCP_HEADERLEN(tcpHeader->rsvLen));
	tcpData = (UCHAR *)tcpHeader + byteOffset;
	return tcpData;
}