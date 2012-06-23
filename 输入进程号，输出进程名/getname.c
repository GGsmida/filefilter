#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>


void getProcessName(int pid, char *pname){
	char path[34]={0};
	sprintf(path,"/proc/%d/status",pid);
    int fd=open(path, O_RDONLY);
    if(fd<0){
        printf("open():\n");
        return;
    }
   
    if(read(fd,pname,200)<0){
        perror("read():\n");
        return;
    }
    
    if(close(fd)<0){
        perror("close():\n");
        return;
    }
}

void main(){
	int pid;
	int i,j,count;
	char chs[200];
	char name[200];
	
	for(i=0; i<200; i++)
		chs[i] = '$';
	
	printf("Please input pid:		");
	scanf("%d",&pid);
	getProcessName(pid, chs);
	printf("The name of pid%d is :	", pid);
	
	for(i=0, j=0, count=0; i<200; i++){
		if(chs[i] == ':'){
			count++;
			if(count == 2){
				j = j-6;
				break;
			}
			j = 0;
			continue;
		}
		name[j] = chs[i];
		j++;
	}
	
	for(i=1; i<j; i++)
		printf("%c", name[i]);
	printf("\n");
}
