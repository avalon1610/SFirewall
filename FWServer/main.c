#ifdef _WIN32
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>

#include "mongoose.h"
#include "sql.h"
#include "comm.h"
#include "../LoadSys/LoadSys.h"

#ifdef _WIN32
#include <windows.h>
#include <direct.h>
#include <winsvc.h>
#include <ShlObj.h>

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

#define MAX_OPTIONS 40
#define MAX_CONF_FILE_LINE_SIZE (8 * 1024)

static int exit_flag;
static char server_name[40];		// Set by init_server_name()
static char config_file[PATH_MAX];	// Set by process_command_line_arguments()
static struct mg_context *ctx;		// Set by start_mongoose()

#if !defined(CONFIG_FILE)
#define CONFIG_FILE "mongoose.conf"
#endif

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
	if (event->type == MG_EVENT_LOG)
		printf("%s\n",(const char *)event->event_param);
	if (event->type == MG_HTTP_ERROR)
		printf("HTTP ERROR:%d\n",(DWORD)event->event_param);
	return 0;
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
	set_option(options,"document_root",".");

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

void wait()
{
	MSG msg;
	while (GetMessageA(&msg,NULL,0,0))
	{
		TranslateMessage(&msg);
		DispatchMessageA(&msg);
	}
}

#define INF_NAME "netsf"
int main(int argc,char *argv[])
{
	char path[MAX_PATH] = {0};
	char name[32] = {0};
	char msg[128] = {0};
	
	//setup database
	if (!sql_init("database.db"))
		return EXIT_FAILURE;

	// load driver
	_getcwd(path,MAX_PATH);
	strncat(path,"\\",1);
	strncat(path,INF_NAME,strlen(INF_NAME));
	strncat(path,".inf",4);
	load_driver_inf(path);

	// Communication with driver
	setup_comm();

	// start web server
	init_server_name();
	start_mongoose(argc,argv);
	printf("%s started on port(s) %s with web root [%s]\n",
		server_name,mg_get_option(ctx,"listening_ports"),
		mg_get_option(ctx,"document_root"));
	while (exit_flag == 0)
	{
		sleep(1);
	}
	printf("Exiting on signal %d,waiting for all threads to finish...",exit_flag);
	fflush(stdout);
	mg_stop(ctx);
	printf("%s"," done.\n");
	
	return EXIT_SUCCESS;
}