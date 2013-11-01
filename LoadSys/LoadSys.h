#pragma once
#ifdef DELETE
#undef DELETE
#endif

enum TYPE
{
	INSTALL = 0,
	START,
	STOP,
	DELETE
};