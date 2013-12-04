#include "comm.h"
#include <windows.h>
#include <stdio.h>
#include <process.h>
#include <string.h>
#include "curl/curl.h"
#include "userioctrl.h" //do not change include order.

#pragma comment(lib,"libcurl")

HANDLE g_hEvent;
PVOID g_ShareMem;
HANDLE g_kEvent;
HANDLE g_hFile;
int bExit = 1;
void LogToDB(PacketRecord *record);
int RuleToDB(RULE,int);
char g_ip[16] = {0};

CURL *curl = NULL;


struct MemoryStruct {
	char *memory;
	size_t size;
};

static size_t WriteMemoryCallback(void *contents,size_t size,size_t nmemb,void *userp)
{
	size_t realsize = size * nmemb;
	struct MemoryStruct *mem = (struct MemoryStruct*)userp;
	mem->memory = realloc(mem->memory,mem->size + realsize + 1);
	if (mem->memory == NULL)
	{
		fprintf(stderr,"not enough memory (realloc returned NULL)\n");
		return 0;
	}

	memcpy(&(mem->memory[mem->size]),contents,realsize);
	mem->size += realsize;
	mem->memory[mem->size] = 0;
	return realsize;
}

int send_post(const char *url,const char *field,char *ret,size_t retlen)
{
	CURLcode res;
	int code = 0;
	const char *errmsg;
	int status = true;
	struct MemoryStruct chunk;
	chunk.memory = malloc(1);
	chunk.size = 0;

	if (!curl)
	{
		curl_global_init(CURL_GLOBAL_ALL);
		curl = curl_easy_init();
	}

	curl_easy_setopt(curl,CURLOPT_URL,url);
	curl_easy_setopt(curl,CURLOPT_POSTFIELDS,field);
	curl_easy_setopt(curl,CURLOPT_WRITEFUNCTION,WriteMemoryCallback);
	curl_easy_setopt(curl,CURLOPT_WRITEDATA,(void *)&chunk);
	res = curl_easy_perform(curl);
	if (res == CURLE_OK)
	{
		if (chunk.size < retlen)
			memcpy_s(ret,retlen,chunk.memory,chunk.size);
	}
	else
	{
		errmsg = curl_easy_strerror(res);
		fprintf(stderr,"curl_easy_perform() failed:%s\n",errmsg);
		if (strlen(errmsg) < retlen)
			strcpy_s(ret,retlen,errmsg);
		status =  false;
	}

	if (chunk.memory)
		free(chunk.memory);
	return status;
}

#define POST_FIELD_SIZE 1024
int ReportLog(PacketRecord *record)
{
	char url[128] = {0};
	char *field;
	char ret[64] = {0};
	SYSTEMTIME time;
	char date[64] = {0};
	char srcIP[16] = {0};
	char dstIP[16] = {0};

	if (g_ip[0] == '\0')
		return 0;

	sprintf_s(srcIP,sizeof(srcIP),"%d.%d.%d.%d",record->srcIP[0],record->srcIP[1],record->srcIP[2],record->srcIP[3]);
	sprintf_s(dstIP,sizeof(dstIP),"%d.%d.%d.%d",record->dstIP[0],record->dstIP[1],record->dstIP[2],record->dstIP[3]);
	if (!strcmp(srcIP,g_ip) || !strcmp(dstIP,g_ip))
		return 0;
	field = (char *)malloc(POST_FIELD_SIZE);

	GetLocalTime(&time);
	sprintf_s(date,sizeof(date),"%d-%d-%d %d:%d:%d.%d",time.wYear,time.wMonth,time.wDay,
		time.wHour,time.wMinute,time.wSecond,time.wMilliseconds);
	ZeroMemory(field,POST_FIELD_SIZE);
	sprintf_s(field,POST_FIELD_SIZE,"client_time=%s&event=%s&source_ip=%s&dest_ip=%s",
		date,record->event_name,srcIP,dstIP);
	sprintf_s(url,sizeof(url),"http://%s/project/updata.php",g_ip);
	send_post(url,field,ret,sizeof(ret));
	if (strlen(ret))
		fprintf(stderr,"%s",ret);
	
	free(field);
	return 0;
}

int setup_server(const char *name,const char *ip,const int status,char *ret,size_t retlen)
{
	char url[128] = {0};
	char field[32] = {0};

	strcpy_s(g_ip,sizeof(g_ip),ip);
	sprintf_s(url,sizeof(url),"http://%s/project/register.php",ip);
	sprintf_s(field,sizeof(field),"name=%s&status=%d",(name==NULL)?"\"\"":name,status);
	return send_post(url,field,ret,retlen);
}

DWORD __stdcall workthread(PVOID param)
{
	while(bExit)
	{
		PacketRecord *record;
		WaitForSingleObject(g_kEvent,INFINITE);
		if (g_ShareMem)
		{
			//get the log
			char stat[8] = {0};
			char srcIP[16] = {0};
			char dstIP[16] = {0};
			record = (PacketRecord *)g_ShareMem;
			sprintf_s(srcIP,sizeof(srcIP),"%d.%d.%d.%d",record->srcIP[0],record->srcIP[1],record->srcIP[2],record->srcIP[3]);
			sprintf_s(dstIP,sizeof(dstIP),"%d.%d.%d.%d",record->dstIP[0],record->dstIP[1],record->dstIP[2],record->dstIP[3]);
			if (strcmp(srcIP,g_ip) && strcmp(dstIP,g_ip))
			{	
				if (record->status == PacketDrop)
					strcpy_s(stat,sizeof(stat),"denied");
				else if (record->status == PacketPass)
					strcpy_s(stat,sizeof(stat),"pass");
				else if (record->status == PacketWarn)
					strcpy_s(stat,sizeof(stat),"warning");
				else
					strcpy_s(stat,sizeof(stat),"error");
				if (record->etherType == IP_TYPE)
				{
					if (record->protocol == TCP_PROTOCOL)
						printf("[%s]TCP->%s\n",record->event_name,stat);
					else if (record->protocol == UDP_PROTOCOL)
						printf("[%s]UDP->%s\n",record->event_name,stat);
					else
						printf("[%s]IP->%s\n",record->event_name,stat);

					printf("%d.%d.%d.%d:%d[%02x:%02x:%02x:%02x:%02x:%02x]-->%d.%d.%d.%d:%d[%02x:%02x:%02x:%02x:%02x:%02x]\n",
						record->srcIP[0],record->srcIP[1],record->srcIP[2],record->srcIP[3],record->srcPort,
						record->srcMac[0],record->srcMac[1],record->srcMac[2],record->srcMac[3],record->srcMac[4],record->srcMac[5],
						record->dstIP[0],record->dstIP[1],record->dstIP[2],record->dstIP[3],record->dstPort,
						record->dstMac[0],record->dstMac[1],record->dstMac[2],record->dstMac[3],record->dstMac[4],record->dstMac[5]);
				}
				else if (record->etherType == ARP_TYPE)
				{
					printf("[%s]ARP->%s\n",record->event_name,stat);
					printf("%d - [%02x:%02x:%02x:%02x:%02x:%02x]-->%d - [%02x:%02x:%02x:%02x:%02x:%02x]\n",
						record->srcPort,
						record->srcMac[0],record->srcMac[1],record->srcMac[2],record->srcMac[3],record->srcMac[4],record->srcMac[5],
						record->dstPort,
						record->dstMac[0],record->dstMac[1],record->dstMac[2],record->dstMac[3],record->dstMac[4],record->dstMac[5]);
				}
				else
				{
					printf("[%s]Other->%s\n",record->event_name,stat);
					printf("%d - [%02x:%02x:%02x:%02x:%02x:%02x]-->%d - [%02x:%02x:%02x:%02x:%02x:%02x]\n",
						record->srcPort,
						record->srcMac[0],record->srcMac[1],record->srcMac[2],record->srcMac[3],record->srcMac[4],record->srcMac[5],
						record->dstPort,
						record->dstMac[0],record->dstMac[1],record->dstMac[2],record->dstMac[3],record->dstMac[4],record->dstMac[5]);
				}

				LogToDB(record);
				ReportLog(record);
			}
			SetEvent(g_hEvent);
		}
		
	}
	return 0;
}

int setup_comm(int *error)
{
	DWORD RetBytes;
	HANDLE m_hEvent,m_kEvent;
	DWORD addr = 0;
	g_hFile = CreateFile("\\\\.\\s7fw",GENERIC_READ|GENERIC_WRITE,0,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0);
	if (g_hFile == INVALID_HANDLE_VALUE)
	{
		if (GetLastError() == ERROR_FILE_NOT_FOUND)
			fprintf(stderr,"Installing driver...\n");
		else
		{
			fprintf(stderr,"Open Symbol Link failed:%d\n",GetLastError());
			*error = 1;
		}
		return false;
	}

	//Create event to be sent to kernel
	m_hEvent = CreateEvent(NULL,FALSE,FALSE,NULL);
	m_kEvent = CreateEvent(NULL,FALSE,FALSE,NULL);
	if (!DeviceIoControl(g_hFile,IOCTL_SET_EVENT,&m_hEvent,sizeof(HANDLE),NULL,0,&RetBytes,NULL))
	{
		fprintf(stderr,"Send Event 1 to kernel failed:%d\n",GetLastError());
		goto FAIL_EXIT;
	}

	if (!DeviceIoControl(g_hFile,IOCTL_SET_EVENT_K,&m_kEvent,sizeof(HANDLE),NULL,0,&RetBytes,NULL))
	{
		fprintf(stderr,"Send Event to 2 kernel failed:%d\n",GetLastError());
		goto FAIL_EXIT;
	}

	// get shared memory from kernel
	if (!DeviceIoControl(g_hFile,IOCTL_GET_SHARE_ADDR,NULL,0,&addr,sizeof(addr),&RetBytes,NULL))
	{
		fprintf(stderr,"Get Shared Address failed:%d\n",GetLastError());
		goto FAIL_EXIT;
	}

	g_ShareMem = (PVOID)addr;
	if (!g_ShareMem)
	{
		fprintf(stderr,"get addr:%p,failed.\n",addr);
		goto FAIL_EXIT;
	}
	g_hEvent = m_hEvent;
	g_kEvent = m_kEvent;

	//Create thread to handle comm
	if (-1 == _beginthreadex(NULL,0,workthread,NULL,0,0))
	{
		fprintf(stderr,"Create work thread errorno:%d\n",errno);
		goto FAIL_EXIT;
	}

	return TRUE;

FAIL_EXIT:
	CloseHandle(g_hFile);
	CloseHandle(m_hEvent);
	CloseHandle(m_kEvent);
	*error = 1;
	return FALSE;
}

int DeliveryRule(RULE r,int bAdd,int bToDB)
{
	DWORD retBytes;
	PktFltRule rule;
	DWORD temp_ip;

	if (bToDB && !RuleToDB(r,bAdd))
		return ERROR_SQL;

	ZeroMemory(&rule,sizeof(PktFltRule));
	rule.index = r.index;
	rule.manage = bAdd?ADD_RULE:REMOVE_RULE;
	temp_ip = inet_addr(r.src_ip);
	if (temp_ip != 0xffffffff)
	{
		rule.srcIpAddr[3] = LOBYTE((temp_ip & 0xff000000) >> 24);
		rule.srcIpAddr[2] = LOBYTE((temp_ip & 0x00ff0000) >> 16);
		rule.srcIpAddr[1] = LOBYTE((temp_ip & 0x0000ff00) >> 8);
		rule.srcIpAddr[0] = LOBYTE((temp_ip & 0x000000ff) >> 0);
	}
	temp_ip = inet_addr(r.dst_ip);
	if (temp_ip != 0xffffffff)
	{
		rule.dstIpAddr[3] = LOBYTE((temp_ip & 0xff000000) >> 24);
		rule.dstIpAddr[2] = LOBYTE((temp_ip & 0x00ff0000) >> 16);
		rule.dstIpAddr[1] = LOBYTE((temp_ip & 0x0000ff00) >> 8);
		rule.dstIpAddr[0] = LOBYTE((temp_ip & 0x000000ff) >> 0);
	}
	if (!strcmp(r.type,"TCP"))
		rule.protocol = TCP_PROTOCOL;
	else if (!strcmp(r.type,"UDP"))
		rule.protocol = UDP_PROTOCOL;
	else if (!strcmp(r.type,"ICMP"))
		rule.protocol = ICMP_PROTOCOL;
	else if (!strcmp(r.type,"IP"))
		rule.etherType = IP_TYPE;
	else if (!strcmp(r.type,"ARP"))
		rule.etherType = ARP_TYPE;
	else if (!strcmp(r.type,"RARP"))
		rule.etherType = RARP_TYPE;

	if (!strcmp(r.op,"Pass"))
		rule.status = PacketPass;
	else if (!strcmp(r.op,"Denied"))
		rule.status = PacketDrop;
	else if (!strcmp(r.op,"Warning"))
		rule.status = PacketWarn;

	rule.srcPort = r.src_port;
	rule.dstPort = r.dst_port;
	strcpy_s(rule.data.pi,DATA_RULE_MAX_LEN,r.data.pi);
	rule.data.pos = r.data.pos;
	rule.data.len = r.data.len;
	strcpy_s(rule.name,RULE_NAME_MAX_LEN,r.name);

#ifndef DEVELOP_DEBUG
	if (!DeviceIoControl(g_hFile,IOCTL_MANAGE_RULE,&rule,sizeof(rule),NULL,0,&retBytes,NULL))
	{
		fprintf(stderr,"Send rule to kernel failed:%d\n",GetLastError());
		return ERROR_KERNEL_COMM;
	}
#endif
	
	return SUCCESS;
}
