#pragma once
#define false 0
#define true 1

enum
{
	SUCCESS = 0,
	SQL_ERROR,
	KERNEL_COMM_ERROR,
	OTHER_ERROR
};
int setup_comm(int *);