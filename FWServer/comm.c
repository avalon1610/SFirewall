#include "comm.h"
#include <windows.h>
#include <stdio.h>
#include <process.h>
#include "../include/userioctrl.h" //do not change include order.

HANDLE g_hEvent;
PVOID g_ShareMem;
HANDLE g_kEvent;
int bExit = 1;

DWORD __stdcall workthread(PVOID param)
{
	while(bExit)
	{
		PacketRecord *record;
		WaitForSingleObject(g_kEvent,INFINITE);
		if (g_ShareMem)
		{
			printf("Shared Memory:%p",g_ShareMem);
			//get the log
			record = (PacketRecord *)g_ShareMem;
			printf("%d.%d.%d.%d:%d[%02x:%02x:%02x:%02x:%02x:%02x]-->%d.%d.%d.%d:%d[%02x:%02x:%02x:%02x:%02x:%02x]\n",
				record->srcIP[0],record->srcIP[1],record->srcIP[2],record->srcIP[3],record->srcPort,
				record->srcMac[0],record->srcMac[1],record->srcMac[2],record->srcMac[3],record->srcMac[4],record->srcMac[5],
				record->dstIP[0],record->dstIP[1],record->dstIP[2],record->dstIP[3],record->dstPort,
				record->dstMac[0],record->dstMac[1],record->dstMac[2],record->dstMac[3],record->dstMac[4],record->dstMac[5]);
			SetEvent(g_hEvent);
		}
		
	}
	return 0;
}

int setup_comm()
{
	DWORD RetBytes;
	HANDLE m_hEvent;
	DWORD addr = 0;
	HANDLE hFile = CreateFile("\\\\.\\s7fw",GENERIC_READ|GENERIC_WRITE,0,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		fprintf(stderr,"Open Symbol Link failed:%d\n",GetLastError());
		return false;
	}

	//Create event to be sent to kernel
	m_hEvent = CreateEvent(NULL,FALSE,FALSE,NULL);
	SetEvent(m_hEvent);
	if (!DeviceIoControl(hFile,IOCTL_SET_EVENT,&m_hEvent,sizeof(HANDLE),NULL,0,&RetBytes,NULL))
	{
		fprintf(stderr,"Send Event to kernel failed:%d\n",GetLastError());
		CloseHandle(hFile);
		CloseHandle(m_hEvent);
		return FALSE;
	}

	// get shared memory from kernel
	if (!DeviceIoControl(hFile,IOCTL_GET_SHARE_ADDR,NULL,0,&addr,sizeof(addr),&RetBytes,NULL))
	{
		fprintf(stderr,"Get Shared Address failed:%d\n",GetLastError());
		CloseHandle(hFile);
		CloseHandle(m_hEvent);
		return FALSE;
	}

	g_ShareMem = (PVOID)addr;
	g_hEvent = m_hEvent;
	g_kEvent = OpenEvent(EVENT_MODIFY_STATE,FALSE,"s7fw_event");
	if (g_kEvent == NULL)
	{
		fprintf(stderr,"Open Event g_kEvent failed:%d\n",GetLastError());
		return FALSE;
	}

	//Create thread to handle comm
	if (-1 == _beginthreadex(NULL,0,workthread,NULL,0,0))
	{
		fprintf(stderr,"Create work thread errorno:%d\n",errno);
		return FALSE;
	}
	return true;
}