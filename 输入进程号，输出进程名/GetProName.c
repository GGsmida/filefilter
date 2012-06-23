#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>


void getProcessName(int pid, char *pname){
    char cmd[100]={0};
    
    sprintf(cmd,"readlink /proc/%d/exe >pname.txt",pid);
    system(cmd);

    int fd=open("pname.txt" ,O_RDWR);
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

    system("rm pname.txt");
}

void main(){
	int pid;
	int i,j;
	char chs[200];
	char name[200];
	
	for(i=0; i<200; i++)
		chs[i] = '$';
	
	printf("Please input pid:		");
	scanf("%d",&pid);
	getProcessName(pid, chs);
	printf("The name of pid%d is :	", pid);
	for(i=0, j=0; i<200; i++){
		if(chs[i] == '/'){
			j = 0;
			continue;
		}
		if(chs[i] == '$')
			break;
		name[j] = chs[i];
		j++;
	}
	for(i=0; i<j-1; i++)
		printf("%c", name[i]);
	printf("\n");
}
