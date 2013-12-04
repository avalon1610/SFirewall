#pragma once
#include <Windows.h>
#include "userioctrl.h"
#define false 0
#define true 1
#define DEVELOP_DEBUG
typedef unsigned int size_t;
enum
{
	SUCCESS = 0,
	ERROR_SQL,
	ERROR_KERNEL_COMM,
	ERROR_PARAMETER,
	STATUS_OTHER,
	STATUS_DONE
};
int setup_comm(int *);
int setup_server(const char *name,const char *ip,const int status,char *ret,size_t retlen);
int DeliveryRule(RULE r,int,int);