#ifdef _WIN32
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>

#ifdef _WIN32
#include <windows.h>
#include <direct.h>
#include <winsvc.h>
#include <ShlObj.h>
#include <time.h>
#include <assert.h>

#ifndef PATH_MAX
#define PATH_MAX MAX_PATH
#endif

#ifndef S_ISDIR
#define S_ISDIR(x) ((x) & _S_IFDIR)
#endif

#define DIRSEP '\\'
#define snprintf _snprintf
#define vsnprintf _vsnprintf
#define sleep(x) Sleep((x) * 1000)
#define WINCDECL __cdecl
#define abs_path(rel,abs,abs_size) _fullpath((abs),(rel),(abs_size))
#endif

#include "mongoose.h"
#include "comm.h"
#include "../LoadSys/LoadSys.h"
#include "curl/curl.h"
#include "sql.h"

#define MAX_OPTIONS 40
#define MAX_CONF_FILE_LINE_SIZE (8 * 1024)

static int exit_flag;
static char server_name[40];		// Set by init_server_name()
static char config_file[PATH_MAX];	// Set by process_command_line_arguments()
static struct mg_context *ctx;		// Set by start_mongoose()
extern CURL *curl;
extern char g_ip[16];

static CRITICAL_SECTION g_cs;	// Permits exclusive access to other members
static HANDLE g_hsemReaders;	// Readers wait on this if a writer has access
static HANDLE g_hsemWriters;	// Writers wait on this if a reader has access
static int g_nWaitingReaders;	// Number of readers waiting for access
static int g_nWaitingWriters;	// Number of writers waiting for access
static int g_nActive;			// Number of threads currently with access

#if !defined(CONFIG_FILE)
#define CONFIG_FILE "mongoose.conf"
#endif
#define MAX_USER_LEN 20
#define MAX_SESSIONS 1
#define SESSION_TTL 120
static const char *authorize_url = "/authorize";
static const char *login_url = "/login.html";
int post_handler(struct mg_event *event);

// Describes web session
struct session {
	char session_id[33];	// Session ID, must be unique
	char random[20];		// Random data used for extra user validation
	char user[MAX_USER_LEN];// Authenticated user
	time_t expire;			// Expiration timestamp, UTC
};

static struct session sessions[MAX_SESSIONS];	//Current sessions

void init_rwlock()
{
	// Initially no readers want access,no writers want access,
	// and no threads are accessing the resource
	g_nWaitingWriters = g_nWaitingReaders = g_nActive = 0;
	g_hsemWriters = CreateSemaphore(NULL,0,MAXLONG,NULL);
	g_hsemReaders = CreateSemaphore(NULL,0,MAXLONG,NULL);
	InitializeCriticalSection(&g_cs);
}

void rwlock_rdlock()
{
	BOOL fResourceWritePending;
	// Ensure exclusive access to the member variables
	EnterCriticalSection(&g_cs);

	// Are there writers waiting or is a writer writing
	fResourceWritePending = (g_nWaitingWriters || (g_nActive < 0));
	if (fResourceWritePending)
	{
		// This reader must wait, increment the count of waiting readers
		g_nWaitingReaders++;
	}
	else
	{
		// This reader can read, increment the count of active readers
		g_nActive++;
	}

	// Allow other threads to attempt reading/writing
	LeaveCriticalSection(&g_cs);

	if (fResourceWritePending)
	{
		// This thread must wait
		WaitForSingleObject(g_hsemReaders,INFINITE);
	}
}

void rwlock_wrlock()
{
	BOOL fResourceOwned;

	// Ensure exclusive access to the member variables
	EnterCriticalSection(&g_cs);

	// Are there any threads accessing the resource
	fResourceOwned = (g_nActive != 0);

	if (fResourceOwned)
	{
		// This writer must wait,increment the count of waiting writers
		g_nWaitingWriters++;
	}
	else
	{
		// This writer can writer, decrement the count of active writers
		g_nActive = -1;
	}

	// Allow other threads to attempt reading/writing
	LeaveCriticalSection(&g_cs);

	if (fResourceOwned)
	{
		// This thread must wait
		WaitForSingleObject(g_hsemWriters,INFINITE);
	}
}

void rwlock_unlock()
{
	HANDLE hsem;
	LONG lCount;
	// Ensure exclusive access to the member variables
	EnterCriticalSection(&g_cs);

	if (g_nActive > 0)
	{
		// Readers have control so a reader must be done
		g_nActive--;
	}
	else
	{
		// Writers have control so a writer must be done
		g_nActive++;
	}

	hsem = NULL;	// Assume no thread are waiting
	lCount = 1;		// Assume only 1 waiter wakes, always true for writers

	if (g_nActive == 0)
	{
		// It is possible  that readers could never get access
		// if there are always writers wanting to write
		if (g_nWaitingWriters > 0)
		{
			// Writers are waiting and they take priority over readers
			g_nActive = -1;			// A writer will get access
			g_nWaitingWriters--;	// One less writer will be waiting
			hsem = g_hsemWriters;	// Writers wait on this semaphore
			// The semaphore will release only 1 writer thread
		}
		else if (g_nWaitingWriters > 0)
		{
			// Readers are waiting and no writers are waiting
			g_nActive = g_nWaitingReaders;	// All readers will get access
			g_nWaitingReaders = 0;			// No readers will be waiting
			hsem = g_hsemReaders;			// Readers wait on this semaphore
			lCount = g_nActive;				// Semaphore releases all readers
		}
		else
		{
			// There are no threads waiting at all, no semaphore gets released
		}
	}

	// Allow other threads to attempt reading/writing
	LeaveCriticalSection(&g_cs);

	if (hsem != NULL)
	{
		// Some threads are to be released
		ReleaseSemaphore(hsem,lCount,NULL);
	}
}

static struct session *get_session(const struct mg_connection *conn)
{
	int i;
	const char *cookie = mg_get_header(conn,"Cookie");
	char session_id[33];
	time_t now = time(NULL);
	mg_get_cookie(cookie,"session",session_id,sizeof(session_id));
	for (i = 0; i < MAX_SESSIONS; i++)
	{
		if (sessions[i].expire != 0 &&
			sessions[i].expire > now &&
			strcmp(sessions[i].session_id,session_id) == 0)
		{
			break;
		}
	}
	return i == MAX_SESSIONS ? NULL : &sessions[i];
}

static void generate_session_id(char *buf,const char *random,const char *user)
{
	mg_md5(buf,random,user,NULL);
}

// Return 1 if request is authorized,0 otherwise
static int is_authorized(const struct mg_connection *conn,
						 const struct mg_request_info *request_info)
{
	struct session *session;
	char valid_id[33];
	int authorized = 0;

	// Always authorize accesses to login page and to authorize URI
	if (!strcmp(request_info->uri,login_url) ||
		!strcmp(request_info->uri,authorize_url))
		return 1;

	rwlock_rdlock();
	if ((session = get_session(conn)) != NULL)
	{
		generate_session_id(valid_id,session->random,session->user);
		if (strcmp(valid_id,session->session_id) == 0)
		{
			session->expire = time(0) + SESSION_TTL;
			authorized = 1;
		}
	}
	rwlock_unlock();
	return authorized;
}

static void redirect_to_login(struct mg_connection *conn,
							  const struct mg_request_info *request_info)
{
	mg_printf(conn,"HTTP/1.1 302 Found\r\n"
		"Set-Cookie: original_url=%s\r\n"
		"Location: %s\r\n\r\n",
		request_info->uri,login_url);
}

static void redirect_to_url(struct mg_connection *conn,
							const char *jump_url,
							const char *msg)
{
	char code[256] = {0};
	sprintf_s(code,sizeof(code),"<script>alert('%s');location.href='%s';</script>",msg,jump_url);
	mg_printf(conn,"HTTP/1.0 200 OK\r\n"
		"Content-Length: %d\r\n"
		"Content-Type: text/html\r\n\r\n%s",
		(int)strlen(code),code);
}

// Return 1 if username/password is allowed, 0 otherwise.
static int check_password(const char *user,const char *password)
{
	return (strcmp(password,"cc")||strcmp(user,"cc")) ? 0 : 1;
}

// Allocate new session object
static struct session *new_session(void)
{
	int i;
	time_t now = time(NULL);
	rwlock_wrlock();
	for (i = 0; i < MAX_SESSIONS; i++)
	{
		if (sessions[i].expire == 0 || sessions[i].expire < now)
		{
			sessions[i].expire = time(0) + SESSION_TTL;
			break;
		}
	}
	rwlock_unlock();
	return i == MAX_SESSIONS ? NULL : &sessions[i];
}

static void get_qsvar(const struct mg_request_info *request_info,
					  const char *name,char *dst,size_t dst_len)
{
	const char *qs = request_info->query_string;
	mg_get_var(qs,strlen(qs == NULL ? "" : qs),name,dst,dst_len);
}

static void my_strlcpy(char *dst,const char *src,size_t len)
{
	strncpy(dst,src,len);
	dst[len - 1] = '\0';
}

static void authorize(struct mg_connection *conn,
					  const struct mg_request_info *request_info)
{
	char user[MAX_USER_LEN],password[MAX_USER_LEN];
	struct session *session;
	get_qsvar(request_info,"user",user,sizeof(user));
	get_qsvar(request_info,"password",password,sizeof(password));

	if (check_password(user,password) && (session = new_session()) != NULL)
	{
		// Authentication success:
		// 1. create new session
		// 2. set session ID token in the cookie
		// 3. remove original_url from the cookie - not needed anymore
		// 4. redirect client back to the original URL
		my_strlcpy(session->user,user,sizeof(session->user));
		snprintf(session->random,sizeof(session->random),"%d",rand());
		generate_session_id(session->session_id,session->random,session->user);
		mg_printf(conn,"HTTP/1.1 302 Found\r\n"
			"Set-Cookie: session=%s; max-age=3600; http-only\r\n"	// Session ID
			"Set-Cookie: user=%s\r\n"	// Set user,needed by Javascript code
			"Set-Cookie: original_url=/; max-age=0\r\n"		// Delete original_url
			"Location: /\r\n\r\n",
			session->session_id,session->user);
	}
	else
	{
		// Authentication failure, redirect to login
		const char *alert_msg = "Invalid username or password.";
		redirect_to_url(conn,login_url,alert_msg);
	}
}

static void init_server_name(void) 
{
	snprintf(server_name,sizeof(server_name),"Mongoose web server v.%s",mg_version());
}

static void show_usage_and_exit(void)
{
	const char **names;
	int i;
	fprintf(stderr,"Mongoose version %s\n",mg_version());
	fprintf(stderr,"Usage:\n");
	fprintf(stderr,"  mongoose -A <htpasswd_file> <realm> <user> <passwd>\n");
	fprintf(stderr,"  mongoose <config_file>\n");
	fprintf(stderr,"  mongoose [-option value ...]\n");
	fprintf(stderr,"OPTIONS:\n");

	names = mg_get_valid_option_names();
	for (i = 0; names[i] != NULL; i += 3)
	{
		fprintf(stderr,"  -%s %s (default: \"%s\")\n",
				names[i],names[i+1],names[i+2] == NULL ? "" : names[i+2]);
	}
	fprintf(stderr,"See http://code.google.com/p/mongoose/wiki/MongooseManual"
			" for more details.\n");
	fprintf(stderr,"Example:\n  mongoose -s cert.pem -p 80,443s -d no\n");
	exit(EXIT_FAILURE);
}

static void WINCDECL signal_handler(int sig_num)
{
	exit_flag = sig_num;
}

static void die(const char *fmt,...)
{
	va_list ap;
	char msg[200] = {0};
	va_start(ap,fmt);
	vsnprintf(msg,sizeof(msg),fmt,ap);
	va_end(ap);

	fprintf(stderr,"%s\n",msg);

	exit(EXIT_FAILURE);
}

static void verify_document_root(const char *root)
{
	const char *p,*path;
	char buf[PATH_MAX];
	struct stat st;

	path = root;
	if ((p = strchr(root,',')) != NULL && (size_t)(p - root) < sizeof(buf))
	{
		memcpy(buf,root,p - root);
		buf[p - root] = '\0';
		path = buf;
	}

	if (stat(path,&st) != 0 || !S_ISDIR(st.st_mode))
	{
		die("Invalid root directory: [%s]:%s",root,strerror(errno));
	}
}

static char *sdup(const char *str)
{
	char *p;
	if ((p = (char *)malloc(strlen(str)+1)) != NULL)
	{
		strcpy(p,str);
	}
	return p;
}

static void set_option(char **options,const char *name,const char *value)
{
	int i;

	for (i = 0; i < MAX_OPTIONS - 3; i++)
	{
		if (options[i] == NULL)
		{
			options[i] = sdup(name);
			options[i+1] = sdup(value);
			options[i+2] = NULL;
			break;
		}
		else if (!strcmp(options[i],name))
		{
			free(options[i+1]);
			options[i+1] = sdup(value);
			break;
		}
	}

	if (i == MAX_OPTIONS - 3)
	{
		die("%s","Too many options specified");
	}
}

static void process_command_line_arguments(char *argv[],char **options)
{
	char line[MAX_CONF_FILE_LINE_SIZE],opt[sizeof(line)],val[sizeof(line)],*p;
	FILE *fp = NULL;
	size_t i,cmd_line_opts_start = 1,line_no = 0;

	// Should we use a config file ?
	if (argv[1] != NULL && argv[1][0] != '-')
	{
		snprintf(config_file,sizeof(config_file),"%s",argv[1]);
		cmd_line_opts_start = 2;
	}
	else if ((p = strrchr(argv[0],DIRSEP)) == NULL)
	{
		// No command line flags specified. Look where binary lives
		snprintf(config_file,sizeof(config_file),"%s",CONFIG_FILE);
	}
	else
	{
		snprintf(config_file,sizeof(config_file),"%.*s%c%s",
				(int)(p - argv[0]),argv[0],DIRSEP,CONFIG_FILE);
	}

	fp = fopen(config_file,"r");

	// If config file was set in command line and open failed,die
	if (cmd_line_opts_start == 2 && fp == NULL)
	{
		die("Cannot open config file %s:%s",config_file,strerror(errno));
	}

	// Load config file setting first
	if (fp != NULL)
	{
		fprintf(stderr,"Loading config file %s\n",config_file);

		// Loop over the lines in config file
		while (fgets(line,sizeof(line),fp) != NULL)
		{
			line_no++;
			// Ignore empty line and comments
			if (line[0] == '#' || line[0] == '\n')
				continue;
			if (sscanf(line,"%s %s[^\r\n#]",opt,val) != 2)
			{
				die("%s: line %d is invalid",config_file,(int)line_no);
			}
			set_option(options,opt,val);
		}

		(void)fclose(fp);
	}

	// Now handle commandl ine flags. They override config file settings.
	for (i = cmd_line_opts_start; argv[i] != NULL; i+=2)
	{
		if (argv[i][0] != '-' || argv[i+1] == NULL)
		{
			show_usage_and_exit();
		}
		set_option(options,&argv[i][1],argv[i+1]);
	}
}

static int event_handler(struct mg_event *event)
{
	int result = 1;
	struct mg_request_info *request_info = event->request_info;
	struct mg_connection *conn = event->conn;

	if (event->type != MG_REQUEST_BEGIN)
		return 0;
	
	if (!is_authorized(conn,request_info))
		redirect_to_login(conn,request_info);
	else if (strcmp(request_info->uri,authorize_url) == 0)
		authorize(conn,request_info);
	else if (strstr(request_info->uri,".") == NULL)
		post_handler(event);
	else
		result = 0;
	return result;
}

static int is_path_absolute(const char *path)
{
	return path != NULL &&
		((path[0] == '\\' && path[1] == '\\') || // UNC path, e.g. \\server\dir
		(isalpha(path[0]) && path[1] == ':' && path[2] == '\\')); // e.g. X:\dir
}

static char *get_option(char **options,const char *option_name)
{
	int i;
	for (i = 0; options[i] != NULL; i++)
		if (!strcmp(options[i],option_name))
			return options[i+1];
	return NULL;
}

static void verify_existence(char **options,const char *option_name,
							 int must_be_dir)
{
	struct stat st;
	const char *path = get_option(options,option_name);
	if (path != NULL && (stat(path,&st) != 0 || ((S_ISDIR(st.st_mode) ? 1 : 0) != must_be_dir)))
	{
		die("Invalid path for %s: [%s]: (%s). Make sure that path is either "
			"absolute, or it is relative to mongoose executable.",option_name,path,strerror(errno));
	}
}

static void set_absolute_path(char *options[],const char *option_name,
							  const char *path_to_mongoose_exe)
{
	char path[PATH_MAX],abs[PATH_MAX],*option_value;
	const char *p;

	// Check whether option is already set
	option_value = get_option(options,option_name);

	// If option is already set and it is an absolute path,
	// leave it as it is
	if (option_value != NULL && !is_path_absolute(option_value))
	{
		// Not absolute. Use the directory where mongoose executable lives
		// be the relative directory for everything.
		// Extract mongoose executable directory into path.
		if ((p = strrchr(path_to_mongoose_exe,DIRSEP)) == NULL)
		{
			_getcwd(path,sizeof(path));
		}
		else
		{
			snprintf(path,sizeof(path),"%.*s",(int)(p - path_to_mongoose_exe),
					path_to_mongoose_exe);
		}

		strncat(path,"/",sizeof(path) - 1);
		strncat(path,option_value,sizeof(path) - 1);

		// Absolutize the path, and set the option
		abs_path(path,abs,sizeof(abs));
		set_option(options,option_name,abs);
	}
}

static void start_mongoose(int argc,char *argv[])
{
	char *options[MAX_OPTIONS];
	int i;

	// Edit passwords file if -A option is specified
	if (argc > 1 && !strcmp(argv[1],"-A"))
	{
		if (argc != 6)
		{
			show_usage_and_exit();
		}
		exit(mg_modify_passwords_file(argv[2],argv[3],argv[4],argv[5])?EXIT_SUCCESS:EXIT_FAILURE);
	}

	// Show usage if -h or --help options are specified
	if (argc == 2 && (!strcmp(argv[1],"-h") || !strcmp(argv[1],"--help")))
	{
		show_usage_and_exit();
	}

	options[0] = NULL;
	set_option(options,"document_root","./web");

	// Update config based on command line arguments
	process_command_line_arguments(argv,options);

	// Make sure we have absolute paths for files and directories
	set_absolute_path(options, "document_root", argv[0]);
	set_absolute_path(options, "put_delete_auth_file", argv[0]);
	set_absolute_path(options, "cgi_interpreter", argv[0]);
	set_absolute_path(options, "access_log_file", argv[0]);
	set_absolute_path(options, "error_log_file", argv[0]);
	set_absolute_path(options, "global_auth_file", argv[0]);
	set_absolute_path(options, "ssl_certificate", argv[0]);

	// Make extra verification for certain options
	verify_existence(options, "document_root", 1);
	verify_existence(options, "cgi_interpreter", 0);
	verify_existence(options, "ssl_certificate", 0);

	// Setup signal handler: quit on Ctrl-C
	signal(SIGTERM,signal_handler);
	signal(SIGINT,signal_handler);

	// Start Mongoose
	ctx = mg_start((const char **)options,event_handler,NULL);
	for (i = 0; options[i] != NULL; i++)
	{
		free(options[i]);
	}

	if (ctx == NULL)
	{
		die("%s","Failed to start Mongoose.");
	}
}

int setup_rule()
{
	char sql[256] = {0};
	char **azResult;
	int nRow,nColumn,i,nIndex=0;
	RULE rule;
	sprintf_s(sql,sizeof(sql),"select rowid,* from rule;");
	if (sql_query_sync(sql,&azResult,&nRow,&nColumn))
	{	
		for (i = 0;i <= nRow; ++i)
		{	
			if (i == 0)
			{
				nIndex+=11;
				continue;
			}
			
			ZeroMemory(&rule,sizeof(RULE));
			rule.index = atoi(azResult[nIndex++]);
			strcpy_s(rule.name,sizeof(rule.name),azResult[nIndex++]);	
			strcpy_s(rule.type,sizeof(rule.type),azResult[nIndex++]);
			strcpy_s(rule.src_ip,sizeof(rule.src_ip),azResult[nIndex++]);
			strcpy_s(rule.dst_ip,sizeof(rule.dst_ip),azResult[nIndex++]);
			rule.src_port = atoi(azResult[nIndex++]);
			rule.dst_port = atoi(azResult[nIndex++]);
			strcpy_s(rule.data.pi,sizeof(rule.data.pi),azResult[nIndex++]);
			rule.data.pos = atoi(azResult[nIndex++]);
			rule.data.len = atoi(azResult[nIndex++]);
			strcpy_s(rule.op,sizeof(rule.op),azResult[nIndex++]);
			if (SUCCESS == DeliveryRule(rule,true,false))
				printf("Loading Rules from Database...%d\n",i);
			else
			{
				printf("Loading rules error!\n");
				break;
			}
			
		}
		return nRow;
	}
	return 0;
}

BOOL WINAPI ConsoleHandler(DWORD CEvent)
{
	switch (CEvent)
	{
	case CTRL_CLOSE_EVENT:
	case CTRL_C_EVENT:
		{
			mg_stop(ctx);
			if (g_ip[0] != '\0')
				setup_server(NULL,g_ip,OFFLINE,NULL,0);
			if (curl)
			{
				curl_easy_cleanup(curl);
				curl_global_cleanup();
			}

			assert(g_nActive == 0);
			g_nWaitingReaders = g_nWaitingWriters = g_nActive = 0;
			DeleteCriticalSection(&g_cs);
			CloseHandle(g_hsemReaders);
			CloseHandle(g_hsemWriters);
			return FALSE;
		}
	default:
		break;
	}
	return TRUE;
}

#define INF_NAME "netsf"
int main(int argc,char *argv[])
{
	char path[MAX_PATH] = {0};
	char name[32] = {0};
	MSG msg;
	int error = 0;

	//setup database
	if (!sql_init("database.db"))
		return EXIT_FAILURE;

#ifndef DEVELOP_DEBUG
	// Communication with driver
	while (!setup_comm(&error))
	{
		if (error == 1)
			return EXIT_FAILURE;
		// load driver
		_getcwd(path,MAX_PATH);
		strncat(path,"\\",1);
		strncat(path,INF_NAME,strlen(INF_NAME));
		strncat(path,".inf",4);
		load_driver_inf(path);
	}
#endif

	if (SetConsoleCtrlHandler((PHANDLER_ROUTINE)ConsoleHandler,TRUE) == FALSE)
	{
		fprintf(stderr,"Unable to install Console Ctrl Handler");
		return EXIT_FAILURE;
	}
	setup_rule();

	init_rwlock();
	// start web server
	init_server_name();
	start_mongoose(argc,argv);
	printf("%s started on port(s) %s with web root [%s]\n",
		server_name,mg_get_option(ctx,"listening_ports"),
		mg_get_option(ctx,"document_root"));
	
	while (GetMessage(&msg,NULL,0,0))
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}

	return EXIT_SUCCESS;
}