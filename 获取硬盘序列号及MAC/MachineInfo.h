#include <net/if.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/io.h> 
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#include <scsi/sg.h>
#include <linux/types.h>
#include <linux/hdreg.h>
#include <fcntl.h>

#define SG_CHECK_CONDITION    0x02
#define SG_DRIVER_SENSE        0x08

#define SG_ATA_16        0x85
#define SG_ATA_16_LEN        16

#define SG_ATA_LBA48        1
#define SG_ATA_PROTO_NON_DATA    ( 3 << 1)
#define SG_ATA_PROTO_PIO_IN    ( 4 << 1)
#define SG_ATA_PROTO_PIO_OUT    ( 5 << 1)
#define SG_ATA_PROTO_DMA    ( 6 << 1)
#define SG_ATA_PROTO_UDMA_IN    (11 << 1) 
#define SG_ATA_PROTO_UDMA_OUT    (12 << 1) 

#define ATA_USING_LBA        (1 << 6)

enum {
    ATA_OP_CHECKPOWERMODE1        = 0xe5,
		ATA_OP_CHECKPOWERMODE2        = 0x98,
		ATA_OP_DOORLOCK            = 0xde,
		ATA_OP_DOORUNLOCK        = 0xdf,
		ATA_OP_FLUSHCACHE        = 0xe7,
		ATA_OP_FLUSHCACHE_EXT        = 0xea,
		ATA_OP_IDENTIFY            = 0xec,
		ATA_OP_PIDENTIFY        = 0xa1,
		ATA_OP_SECURITY_DISABLE        = 0xf6,
		ATA_OP_SECURITY_ERASE_PREPARE    = 0xf3,
		ATA_OP_SECURITY_ERASE_UNIT    = 0xf4,
		ATA_OP_SECURITY_FREEZE_LOCK    = 0xf5,
		ATA_OP_SECURITY_SET_PASS    = 0xf1,
		ATA_OP_SECURITY_UNLOCK        = 0xf2,
		ATA_OP_SETFEATURES        = 0xef,
		ATA_OP_SETIDLE1            = 0xe3,
		ATA_OP_SETIDLE2            = 0x97,
		ATA_OP_SLEEPNOW1        = 0xe5,
		ATA_OP_SLEEPNOW2        = 0x99,
		ATA_OP_SMART            = 0xb0,
		ATA_OP_STANDBYNOW1        = 0xe0,
		ATA_OP_STANDBYNOW2        = 0x94,
};

enum {
    SG_CDB2_TLEN_NODATA    = 0 << 0,
		SG_CDB2_TLEN_FEAT    = 1 << 0,
		SG_CDB2_TLEN_NSECT    = 2 << 0,
		
		SG_CDB2_TLEN_BYTES    = 0 << 2,
		SG_CDB2_TLEN_SECTORS    = 1 << 2,
		
		SG_CDB2_TDIR_TO_DEV    = 0 << 3,
		SG_CDB2_TDIR_FROM_DEV    = 1 << 3,
		
		SG_CDB2_CHECK_COND    = 1 << 5,
};


#define START_SERIAL 10
#define LENGTH_SERIAL 10

int GetMac(char *macAddr);
void print_ascii(__u16 *p, __u8 length, char *SZID);
int GetIdeSer(char *IdeSer);
static void dump_bytes (const char *prefix, unsigned char *p, int len);
int get_sata_serial(char *szDevice, char *szID);
static void dump_bytes (const char *prefix, unsigned char *p, int len);
