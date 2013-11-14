#include "sql.h"
#include "sqlite3.h"
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include "../include/userioctrl.h"

#pragma comment(lib,"sqlite3.lib")
static sqlite3 *db = 0;

const char *create_table_log = "CREATE TABLE if not exists [log] (\
								[type] VARCHAR2 NOT NULL,\
								[src_mac] VARCHAR2 NOT NULL,\
								[dst_mac] VARCHAR2 NOT NULL,\
								[src_ip] VARCHAR2,\
								[dst_ip] VARCHAR2,\
								[src_port] INTEGER NOT NULL,\
								[dst_port] INTEGER NOT NULL,\
								[status] VARCHAR2 NOT NULL,\
								[time] TIMESTAMP NOT NULL DEFAULT (datetime('now','localtime')));";

//const char *query_table_sql = "select count(*) from sqlite_master where table=[create_table_log];";

int sql_init(const char *db_name)
{
	int ret = 0;
	char *zErrMsg = 0;
	ret = sqlite3_open(db_name,&db);
	if (ret != SQLITE_OK)
	{
		fprintf(stderr,"Could not open database: %s",sqlite3_errmsg(db));
		return false;
	}
	
	if (!sql_exec(create_table_log))
	{
		fprintf(stderr,"create table error:%s",zErrMsg);
		return false;
	}
	return true;
}

int sql_query_sync(const char *sql,char ***pazResult,int *pnRow,int *pnColumn)
{
	char *pErrMsg = 0;
	int ret = 0;
	if (!db)
		return false;
	ret = sqlite3_get_table(db,sql,pazResult,pnRow,pnColumn,&pErrMsg);
	if (ret != SQLITE_OK)
	{
		fprintf(stderr,"SQL Error:%s",pErrMsg);
		sqlite3_free(pErrMsg);
		return false;
	}
	return true;
}

int sql_query_async(const char *sql,_CALLBACK callback,PVOID param)
{
	char *pErrMsg = 0;
	int ret = 0;
	if (!db)
		return false;
	ret = sqlite3_exec(db,sql,callback,param,&pErrMsg);
	if (ret != SQLITE_OK)
	{
		fprintf(stderr,"SQL Error:%s",pErrMsg);
		sqlite3_free(pErrMsg);
		return false;
	}
	return true;
}

int sql_exec(const char *sql)
{
	char *pErrMsg = 0;
	int ret = 0;
	if (!db)
		return false;
	ret = sqlite3_exec(db,sql,NULL,0,&pErrMsg);
	if (ret != SQLITE_OK)
	{
		fprintf(stderr,"SQL Error:%s",pErrMsg);
		sqlite3_free(pErrMsg);
		return false;
	}

	return true;
}

void RecordToDB(PacketRecord *record)
{
	char sql[256] = {0};
	char type[8] = {0};
	char src_mac[32] = {0};
	char dst_mac[32] = {0};
	char src_ip[16] = {0};
	char dst_ip[16] = {0};
	char status[8] = {0};
	switch (record->status)
	{
	case PacketPass:
		strcpy_s(status,sizeof(status),"Pass");
		break;
	case PacketDrop:
		strcpy_s(status,sizeof(status),"Denied");
		break;
	default:
		strcpy_s(status,sizeof(status),"Unknown");
		break;
	}
	switch (record->etherType)
	{
	case IP_TYPE:
		switch (record->protocol)
		{
		case TCP_PROTOCOL:
			strcpy_s(type,sizeof(type),"TCP");
			break;
		case UDP_PROTOCOL:
			strcpy_s(type,sizeof(type),"UDP");
			break;
		default:
			strcpy_s(type,sizeof(type),"IP");
			break;
		}
		break;
	case ARP_TYPE:
		strcpy_s(type,sizeof(type),"ARP");
		break;
	case RARP_TYPE:
		strcpy_s(type,sizeof(type),"RARP");
		break;
	default:
		strcpy_s(type,sizeof(type),"OTHER");
		break;
	}

	sprintf_s(src_mac,sizeof(src_mac),"%02X:%02X:%02X:%02X:%02X:%02X",
		record->srcMac[0],record->srcMac[1],record->srcMac[2],record->srcMac[3],record->srcMac[4],record->srcMac[5]);
	sprintf_s(dst_mac,sizeof(dst_mac),"%02X:%02X:%02X:%02X:%02X:%02X",
		record->dstMac[0],record->dstMac[1],record->dstMac[2],record->dstMac[3],record->dstMac[4],record->dstMac[5]);
	sprintf_s(src_ip,sizeof(src_ip),"%d.%d.%d.%d",record->srcIP[0],record->srcIP[1],record->srcIP[2],record->srcIP[3]);
	sprintf_s(dst_ip,sizeof(dst_ip),"%d.%d.%d.%d",record->dstIP[0],record->dstIP[1],record->dstIP[2],record->dstIP[3]);
	sprintf_s(sql,sizeof(sql),
		"insert into log (type,src_mac,dst_mac,src_ip,dst_ip,src_port,dst_port,status) values ('%s','%s','%s','%s','%s','%d','%d','%s')",
		type,src_mac,dst_mac,src_ip,dst_ip,record->srcPort,record->dstPort,status);

	sql_exec(sql);
}
