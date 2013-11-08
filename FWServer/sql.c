#include "sql.h"
#include "sqlite3.h"
#include <stdio.h>
#include <stdlib.h>

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
								[time] TIMESTAMP NOT NULL);";

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

