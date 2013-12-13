#ifndef _USER_IOCTL_H_
#define _USER_IOCTL_H_

#define IOCTL_SET_EVENT CTL_CODE(FILE_DEVICE_UNKNOWN,0x800,METHOD_BUFFERED,FILE_READ_DATA|FILE_WRITE_DATA)
#define IOCTL_SET_EVENT_K CTL_CODE(FILE_DEVICE_UNKNOWN,0x801,METHOD_BUFFERED,FILE_READ_DATA|FILE_WRITE_DATA)
#define IOCTL_GET_SHARE_ADDR CTL_CODE(FILE_DEVICE_UNKNOWN,0x802,METHOD_BUFFERED,FILE_READ_DATA|FILE_WRITE_DATA)
#define IOCTL_MANAGE_RULE CTL_CODE(FILE_DEVICE_UNKNOWN,0x803,METHOD_BUFFERED,FILE_READ_DATA|FILE_WRITE_DATA)

#define TCP_PROTOCOL 0x06
#define UDP_PROTOCOL 0x11
#define ICMP_PROTOCOL 0x01

#define IP_TYPE 0x0008
#define ARP_TYPE 0x0608
#define RARP_TYPE 0x3580

#define LOG_BUFSIZE 64*1024 // 64k

typedef enum _PacketStatus
{
	PacketDrop,
	PacketWarn,
	PacketPass
}PacketStatus;

typedef enum _PackDirection
{
	PACKET_BOTH,
	PACKET_IN,
	PACKET_OUT
} PacketDirection;

typedef enum _RuleManage
{
	ADD_RULE,
	REMOVE_RULE,
	UPDATE_RULE
} RuleManage;

#define DATA_RULE_MAX_LEN 32
#define POST_DATA_LEN 2048
#define IP_DATA_LEN 16
#define PORT_DATA_LEN 8
#define DATA_LEN 16
#define RULE_NAME_MAX_LEN 16

typedef struct _DataRule
{
	char pi[DATA_RULE_MAX_LEN];
	int pos;
	int len;
} DataRule,*PDataRule;

typedef struct _PktFltRule
{
	UCHAR srcIpAddr[4];
	UCHAR dstIpAddr[4];
	USHORT srcPort;
	USHORT dstPort;
	UCHAR protocol;
	USHORT etherType;
	DataRule data;
	PacketDirection direction;
	PacketStatus status;
	USHORT index;
	RuleManage manage;
	UCHAR name[RULE_NAME_MAX_LEN];
} PktFltRule;

typedef struct _PacketRecord 
{
	USHORT etherType;
	UCHAR srcMac[6];
	UCHAR dstMac[6];
	UCHAR protocol;
	UCHAR srcIP[4];
	USHORT srcPort;
	UCHAR dstIP[4];
	USHORT dstPort;
	UCHAR status;
	ULONG dataLen;
	UCHAR event_name[RULE_NAME_MAX_LEN];
} PacketRecord;

typedef struct _RULE
{
	char name[RULE_NAME_MAX_LEN];
	unsigned int index;
	char type[DATA_LEN];
	char src_ip[IP_DATA_LEN];
	char dst_ip[IP_DATA_LEN];
	int src_port;
	int dst_port;
	char op[DATA_LEN];
	DataRule data;
	RuleManage manage;
} RULE,*PRULE;

enum CLIENT_STATUS
{
	ONLINE = 0,
	WARNING_1,
	WARNING_2,
	OFFLINE
};

#endif