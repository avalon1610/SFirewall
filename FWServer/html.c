#include "comm.h"
#include "cJSON.h"
#include "mongoose.h"
#include "sql.h"
#include "html.h"
#include "userioctrl.h"

static const char *sql_error_msg = 
"Sql Error ! check server output for more information.";
static const char *kernel_error_msg = 
"FATAL ERROR! Communicate with the kernel has failed.";
static const char *ip_error_msg = 
"<script>alert('Invalid IP');window.history.back(-1);</script>";
static const char *parameter_error_msg = 
"Post Data Error!";

#define DATA_SIZE 204800

void HandleSQLData(char *data,int data_size,int nRow,int nCol,char **pResult)
{
	char temp[64] = {0};
	int i,j,nIndex;
	nIndex = nCol;
	for(i=0; i<=nRow; i++)
	{
		if (i == 0)
			strcat_s(data,data_size,"<thead>");
		if (i == 1)
			strcat_s(data,data_size,"<tbody>");

		strcat_s(data,data_size,"<tr>");
		for (j=0;j<nCol;j++)
		{
			if (i == 0)
			{
				sprintf_s(temp,sizeof(temp),"<th>%s</th>",pResult[j]);
				strcat_s(data,data_size,temp);
				continue;
			}

			if (i > 999)
				return;
			sprintf_s(temp,sizeof(temp),"<td>%s</td>",pResult[nIndex]);
			strcat_s(data,data_size,temp);
			++nIndex;
		}
		strcat_s(data,data_size,"</tr>");
		if (i == 0)
			strcat_s(data,data_size,"</thead>");
	}
	strcat_s(data,data_size,"</tbody>");
}

#define GET_VER_STR(e,t,r) strcpy_s((e).t,sizeof((e).t),!cJSON_GetObjectItem(r,#t)->valuestring?"*":cJSON_GetObjectItem(r,#t)->valuestring)
#define GET_VER_INT(e,t,r) (e).t = cJSON_GetObjectItem(r,#t)->valueint
#define GET_VER_TYPE(t,r) cJSON_GetObjectItem(r,#t)->type
#define GET_VER_INT_FUNC(e,t,r,d)\
	if (GET_VER_TYPE(t,r) == cJSON_Number)\
	GET_VER_INT(e,t,r);\
else if (GET_VER_TYPE(t,r) == cJSON_String)\
{\
	strcpy_s(temp,sizeof(temp),cJSON_GetObjectItem(r,#t)->valuestring);\
	if (strlen(temp) == 0)\
	strcpy_s(temp,sizeof(temp),#d);\
	e.t = atoi(temp);\
}\
else return false;

typedef struct _input_entry
{
	char input_name[DATA_LEN];
	char input_type[DATA_LEN];
	int input_src_port;
	int input_dst_port;
	char input_op[DATA_LEN];
	char input_src_ip[IP_DATA_LEN];
	char input_dst_ip[IP_DATA_LEN];
	char input_manage[DATA_LEN];
	int input_index;
	char input_data_pi[DATA_RULE_MAX_LEN];
	int input_data_pos;
	int input_data_len;
}InputEntry,*PInputEntry;

static int ParseJson(char *data,InputEntry *entry)
{
	int i;
	cJSON *EntryArray;
	int num;
	char temp[8] = {0};
	__try
	{
		cJSON *root = cJSON_Parse(data);
		if (!root)
			return false;
		EntryArray = cJSON_GetObjectItem(root,"entrys");
		num = cJSON_GetArraySize(EntryArray);

		if (num > 32)
			return false;
		for (i = 0;i < num; ++i)
		{
			cJSON *rule = cJSON_GetArrayItem(EntryArray,i);

			GET_VER_STR(entry[i],input_name,rule);
			GET_VER_STR(entry[i],input_type,rule);
			GET_VER_INT_FUNC(entry[i],input_src_port,rule,-1);
			GET_VER_INT_FUNC(entry[i],input_dst_port,rule,-1);
			GET_VER_INT_FUNC(entry[i],input_index,rule,-1);
			GET_VER_STR(entry[i],input_data_pi,rule);
			GET_VER_INT_FUNC(entry[i],input_data_pos,rule,0);
			GET_VER_INT_FUNC(entry[i],input_data_len,rule,0);
			GET_VER_STR(entry[i],input_op,rule);
			GET_VER_STR(entry[i],input_src_ip,rule);
			GET_VER_STR(entry[i],input_dst_ip,rule);
			GET_VER_STR(entry[i],input_manage,rule);
		}
		cJSON_Delete(root);
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		return false;
	}

	return num;
}

int post_handler(struct mg_event *event)
{
	int post_data_len;
	char post_data[POST_DATA_LEN] = {0};
	int num = 0;
	int status = STATUS_OTHER;
	InputEntry *input_list = (InputEntry *)malloc(sizeof(InputEntry)*32);
	ZeroMemory(input_list,sizeof(InputEntry)*32);
	if (!strcmp(event->request_info->uri,"/log"))
	{
		char **pResult;
		int nRow,nCol,i;
		char sql[1024] = {"select rowid,* from log"};
		char temp[64] = {0};
		char condition[6][sizeof(temp)] = {0};
		int first = 1;

		// User has submitted a form, show submitted data and a variable value
		post_data_len = mg_read(event->conn,post_data,sizeof(post_data));
		if (post_data_len != 0)
		{
			num = ParseJson(post_data,input_list);
			if (num != 1)
			{
				status = ERROR_PARAMETER;
				goto CHECK_EXIT;
			}

			// search log 
			if (strcmp(input_list[0].input_type,"ALL"))
			{
				sprintf_s(temp,sizeof(temp),"(type='%s')",input_list[0].input_type);
				strcpy_s(condition[0],sizeof(temp),temp);
			}
			if (strlen(input_list[0].input_src_ip))
			{
				sprintf_s(temp,sizeof(temp),"(src_ip='%s')",input_list[0].input_src_ip);
				strcpy_s(condition[1],sizeof(temp),temp);
			}
			if (strlen(input_list[0].input_dst_ip))
			{
				sprintf_s(temp,sizeof(temp),"(dst_ip='%s')",input_list[0].input_dst_ip);
				strcpy_s(condition[2],sizeof(temp),temp);
			}
			if (input_list[0].input_src_port!=-1)
			{
				sprintf_s(temp,sizeof(temp),"(src_port=%d)",input_list[0].input_src_port);
				strcpy_s(condition[3],sizeof(temp),temp);
			}
			if (input_list[0].input_dst_port!=-1)
			{
				sprintf_s(temp,sizeof(temp),"(dst_port=%d)",input_list[0].input_dst_port);
				strcpy_s(condition[4],sizeof(temp),temp);
			}
			if (strcmp(input_list[0].input_op,"ALL"))
			{
				sprintf_s(temp,sizeof(temp),"(status='%s')",input_list[0].input_op);
				strcpy_s(condition[5],sizeof(temp),temp);
			}

			for(i = 0;i < sizeof(condition)/sizeof(temp); ++i)
			{
				if (condition[i][0] == '\0')
					continue;
				else
				{
					if (first)
					{
						strcat_s(sql,sizeof(sql)," where ");
						strcat_s(sql,sizeof(sql),condition[i]);
						first = 0;
					}
					else
					{
						strcat_s(sql,sizeof(sql)," and ");
						strcat_s(sql,sizeof(sql),condition[i]);
					}
				}
			}
		}

		if (sql_query_sync(sql,&pResult,&nRow,&nCol))
		{
			char *data; 
			char header[128] = {0};
			int data_len;
			if (nCol == 0)
			{
				mg_printf(event->conn,"HTTP/1.0 200 OK\r\n"
					"Content-Length: 9\r\n"
					"Content-Type: text/html\r\n\r\nNo Record");
				goto QUIT;
			}
			data = (char *)malloc(DATA_SIZE);
			ZeroMemory(data,DATA_SIZE);
			HandleSQLData(data,DATA_SIZE,nRow,nCol,pResult);
			data_len = strlen(data);
			sprintf_s(header,sizeof(header),"HTTP/1.0 200 OK\r\n"
				"Content-Length: %d\r\n"
				"Content-Type: text/html\r\n\r\n"
				"<table border=\"1\">",data_len+26);

			mg_printf(event->conn,"%s%s</table>\n",header,data);
			free(data);
QUIT:
			status = STATUS_DONE;

		}
		else
		{
			status = ERROR_SQL;
		}
	}
	else if (!strcmp(event->request_info->uri,"/rule"))
	{
		RULE rule;
		status = SUCCESS;
		// User has submitted a form, show submitted data and a variable value
		post_data_len = mg_read(event->conn,post_data,sizeof(post_data));

		if (post_data_len != 0)
		{
			int i;			
			num = ParseJson(post_data,input_list);
			if (num == 0)
			{
				status = ERROR_PARAMETER;
				goto CHECK_EXIT;
			}

			for (i = 0;i < num; ++i)
			{
				ZeroMemory(&rule,sizeof(RULE));
				strcpy_s(rule.type,sizeof(rule.type),input_list[i].input_type);
				strcpy_s(rule.src_ip,sizeof(rule.src_ip),input_list[i].input_src_ip);
				strcpy_s(rule.dst_ip,sizeof(rule.dst_ip),input_list[i].input_dst_ip);
				strcpy_s(rule.name,sizeof(rule.name),input_list[i].input_name);
				rule.src_port = input_list[i].input_src_port;
				rule.dst_port = input_list[i].input_dst_port;
				rule.index = input_list[i].input_index;
				strcpy_s(rule.op,sizeof(rule.op),input_list[i].input_op);
				if (!_stricmp(input_list[i].input_manage,"ADD"))
					rule.manage = ADD_RULE;
				else if (!_stricmp(input_list[i].input_manage,"REMOVE"))
					rule.manage = REMOVE_RULE;
				else if (!_stricmp(input_list[i].input_manage,"UPDATE"))
					rule.manage = UPDATE_RULE;
				else
				{
					status = ERROR_PARAMETER;
					goto CHECK_EXIT;
				}
				strcpy_s(rule.data.pi,DATA_RULE_MAX_LEN,input_list[i].input_data_pi);
				rule.data.pos = input_list[i].input_data_pos;
				rule.data.len = input_list[i].input_data_len;

				status = DeliveryRule(rule,true);
				if (status != SUCCESS)
					break;
			}
		}
	}	
	else if (!strcmp(event->request_info->uri,"/admin"))
	{
		if  (!strcmp(event->request_info->request_method,"POST"))
		{
			char input_my_name[32] = {0};
			char input_server_ip[16] = {0};
			char input_status[16] = {0};
			char ret[64] = {0};
			post_data_len = mg_read(event->conn,post_data,sizeof(post_data));
			if (post_data_len == 0)
			{
				status = ERROR_PARAMETER;
				goto CHECK_EXIT;
			}
			mg_get_var(post_data,post_data_len,"input_my_name",input_my_name,sizeof(input_my_name));
			mg_get_var(post_data,post_data_len,"input_server_ip",input_server_ip,sizeof(input_server_ip));
			mg_get_var(post_data,post_data_len,"input_status",input_status,sizeof(input_status));
			if (setup_server(input_my_name,input_server_ip,!strcmp(input_status,"online")?ONLINE:OFFLINE,ret,sizeof(ret)) && !strlen(ret))
			{
				strcpy_s(ret,sizeof(ret),"Register Success.");
			}
			mg_printf(event->conn,"HTTP/1.0 200 OK\r\n"
				"Content-Length: %d\r\n"
				"Content-Type: text/html\r\n\r\n%s",
				(int)strlen(ret),ret);
		}
		else
		{
			mg_printf(event->conn,"HTTP/1.0 200 OK\r\n"
				"Content-Length: %d\r\n"
				"Content-Type: text/html\r\n\r\n%s",
				(int)strlen(server_form),server_form);

		}	
		status = STATUS_DONE;
	}

CHECK_EXIT:
	switch (status)
	{
	case SUCCESS:
		{
			char **pResult;
			int nRow,nCol;
			char *data;
			char header[128] = {0};
			int data_len;
			char sql[32] = {"select rowid,* from rule;"};
			if (sql_query_sync(sql,&pResult,&nRow,&nCol))
			{
				if (nCol == 0)
				{
					mg_printf(event->conn,"HTTP/1.0 200 OK\r\n"
						"Content-Length: 9\r\n"
						"Content-Type: text/html\r\n\r\nNo Record");
					break;
				}

				data = (char *)malloc(DATA_SIZE/100);
				ZeroMemory(data,DATA_SIZE/100);
				HandleSQLData(data,DATA_SIZE/100,nRow,nCol,pResult);
				data_len = strlen(data);
				sprintf_s(header,sizeof(header),"HTTP/1.0 200 OK\r\n"
					"Content-Length: %d\r\n"
					"Content-Type: text/html\r\n\r\n"
					"<table border=\"1\">",data_len+26);

				mg_printf(event->conn,"%s%s</table>\n",header,data);
				free(data);
			}
		}
		break;
	case ERROR_SQL:
		mg_printf(event->conn,"HTTP/1.0 200 OK\r\n"
			"Content-Length: %d\r\n"
			"Content-Type: text/html\r\n\r\n%s",
			(int)strlen(sql_error_msg),sql_error_msg);
		break;
	case ERROR_KERNEL_COMM:
		mg_printf(event->conn,"HTTP/1.0 200 OK\r\n"
			"Content-Length: %d\r\n"
			"Content-Type: text/html\r\n\r\n%s",
			(int)strlen(kernel_error_msg),kernel_error_msg);
		break;
	case ERROR_PARAMETER:
		mg_printf(event->conn,"HTTP/1.0 200 OK\r\n"
			"Content-Length: %d\r\n"
			"Content-Type: text/html\r\n\r\n%s",
			(int)strlen(parameter_error_msg),parameter_error_msg);
		break;
	case STATUS_DONE:
		// do nothing
		break;
	default:
		mg_printf(event->conn,"HTTP/1.0 200 OK\r\n"
			"Content-Length: %d\r\n"
			"Content-Type: text/html\r\n\r\n%s",
			(int)strlen(html_form),html_form);
		break;
	}

	free(input_list);
	return 1; // Make event as processed
}