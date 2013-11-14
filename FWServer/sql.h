#ifndef _SQL_H_
#define _SQL_H_
#define false 0
#define true 1

typedef int(*_CALLBACK)(void *, int, char **, char **);
int sql_init(const char *);
int sql_exec(const char *sql);
int sql_query_async(const char *sql,_CALLBACK,void *);
int sql_query_sync(const char *sql,char ***pazResult,int *pnRow,int *pnColumn);
#endif