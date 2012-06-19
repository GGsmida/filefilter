
#include "MachineInfo.h"


typedef unsigned short WORD;

int GetMac(char *macAddr)
{
	if(macAddr == NULL)
		return 0;

	struct ifreq ifreq; 
	int sock; 
	if((sock=socket(AF_INET,SOCK_STREAM,0))<0) 
	{ 
		perror("socket"); 
		return 0; 
	} 
	strcpy(ifreq.ifr_name,"eth0");
	if(ioctl(sock,SIOCGIFHWADDR,&ifreq)<0) 
	{ 
		strcpy(ifreq.ifr_name, "eth1");
		if(ioctl(sock, SIOCGIFHWADDR, &ifreq)<0)
		{
			perror("ioctl"); 
			return 0; 
		}
	} 

	sprintf(macAddr, "%02x-%02x-%02x-%02x-%02x-%02x",
		(unsigned char)ifreq.ifr_hwaddr.sa_data[0], 
		(unsigned char)ifreq.ifr_hwaddr.sa_data[1], 
		(unsigned char)ifreq.ifr_hwaddr.sa_data[2], 
		(unsigned char)ifreq.ifr_hwaddr.sa_data[3], 
		(unsigned char)ifreq.ifr_hwaddr.sa_data[4], 
		(unsigned char)ifreq.ifr_hwaddr.sa_data[5]); 

	return 1; 

}

static void dump_bytes (const char *prefix, unsigned char *p, int len)
{
    int i;

    if (prefix)
        fprintf(stderr, "%s: ", prefix);
    for (i = 0; i < len; ++i)
        fprintf(stderr, " %02x", p[i]);
    fprintf(stderr, "\n");
}


void print_ascii(__u16 *p, __u8 length, char *SZID) {
    __u8 ii;
    char cl;
    int len=0;

    for (ii = 0; ii< length; ii++) {
        if(((char) 0x00ff&((*p)>>8)) != ' ') break;
        if((cl = (char) 0x00ff&(*p)) != ' ') {
            if(cl != '\0')
			{
				SZID[len]=cl;
				len++;
			}
            p++; ii++;
            break;
        }
        p++;
    }

    for (; ii < length; ii++) {
        __u8 c;

        c = (*p) >> 8;
        if (c)
		{
			SZID[len]=c;
			len++;
		}
        c = (*p);
        if (c) 
		{
			SZID[len]=c;
			len++;
		}
        p++;
    }
	SZID[len]='\n';
}


int get_sata_serial(char *szDevice, char *szID)
{
    int fd = 0;

    static __u8 args[512] = { 0 };
    __u16 *id = (__u16 *)(args);
    
    void *data = (void *)(args);
    unsigned int data_bytes = 512;

    unsigned char cdb[SG_ATA_16_LEN] = { 0 };
    unsigned char sb[32], *desc;
    unsigned char ata_status, ata_error;
    struct sg_io_hdr io_hdr;


    fd = open("/dev/sda", O_RDONLY);
    if (fd < 0)    
	{
        printf("open /dev/sda error\n");
		GetIdeSer(szID);        
        return -1;
	}



    cdb[ 0] = SG_ATA_16;
    cdb[ 1] = SG_ATA_PROTO_PIO_IN;
    cdb[ 2] = SG_CDB2_CHECK_COND;
    cdb[2] |= SG_CDB2_TLEN_NSECT | SG_CDB2_TLEN_SECTORS;
    cdb[2] |= SG_CDB2_TDIR_FROM_DEV;
    cdb[13] = ATA_USING_LBA;
    cdb[14] = ATA_OP_IDENTIFY;


    memset(&(sb[0]), 0, sizeof(sb));


    memset(&io_hdr, 0, sizeof(struct sg_io_hdr));
    io_hdr.interface_id    = 'S';
    io_hdr.cmd_len        = SG_ATA_16_LEN;
    io_hdr.mx_sb_len    = sizeof(sb);
    io_hdr.dxfer_direction    = SG_DXFER_FROM_DEV;
    io_hdr.dxfer_len    = data_bytes;
    io_hdr.dxferp        = data;
    io_hdr.cmdp        = cdb;
    io_hdr.sbp        = sb;
    io_hdr.timeout        = 10000;



    if (ioctl(fd, SG_IO, &io_hdr) == -1) {
        fprintf(stderr, "SG_IO ioctl not supported\n");
        return -1;
    }


    if (io_hdr.host_status || io_hdr.driver_status != SG_DRIVER_SENSE
     || (io_hdr.status && io_hdr.status != SG_CHECK_CONDITION))
    {
         errno = EIO;
        return -2;
    }

    if (sb[0] != 0x72 || sb[7] < 14) {
        errno = EIO;
        return -3;
    }
    desc = sb + 8;
    if (desc[0] != 9 || desc[1] < 12){
        errno = EIO;
        return -4;
    }

    ata_error = desc[3];
    ata_status = desc[13];
    if (ata_status & 0x01)
        errno = EIO;
        return -5;
    }
    print_ascii( &id[START_SERIAL], LENGTH_SERIAL, szID);
    return 0;
}


static void dump_identity (const struct hd_driveid *id, char *IdeSer)
{        
	sprintf(IdeSer, "%.20s", id->serial_no);
}


int GetIdeSer(char *IdeSer)
{
	int fd = 0;
	fd = open("/dev/hda",O_RDONLY);
	if(fd<0)
	{
		perror("open /dev/hda error");
		return 0;
	}
	static struct hd_driveid id;
	if (!ioctl(fd, HDIO_GET_IDENTITY,&id))
	{
		dump_identity(&id, IdeSer);
	}
	else
		printf("HDIO_GET_IDENTITY failed");
	return 0;
}


int main()
{
    int rv = 0;
    char szID[64] = { 0 };
	
    rv= get_sata_serial("/dev/sda", szID);
	
    printf("Serial:%s\r\n",szID);
    char MAC[30]={0};
	GetMac(MAC);
	printf("mac:%s\r\n", MAC);
	
    return 0;
}

    

