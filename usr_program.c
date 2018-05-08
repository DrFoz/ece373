/*
 *Tyson Fosdick
 *ECE 373 Spring 2018
 *Assignment 3 pci driver userspace program
*/

#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>

int main(){

        int fd = 0, ret = 0, cr = 0, mt = 0;
        char buff[20] = "";

        fd = open("/dev/homework3", O_RDWR);

        if(fd < 0){
                perror("error /dev fail : ");
                exit(1);
        }

        ret = read(fd, buff, 4);

        memcpy(&cr, buff, sizeof(int));

        printf("current number in syscall_val: %d\n", cr);

        printf("Enter new Number: \n");

        ret = read(STDIN_FILENO, buff, 4);

        if(ret < 0){
                perror("error: ");
                exit(-1);
        }

        cr = atoi(buff);

        printf("new number is: %d\n", cr);

        mt = write(fd, &cr, 4);

        if(mt < 0){
                perror("error: ");
                exit(-1);
        }

        ret = read(fd, buff, 4);
        if(ret < 0){
                perror("Error: ");
                exit(-1);
        }


        cr = atoi(buff);
                                                                                                                                    
   printf("reprinting value: %d\n", cr);

        return 0;
}                    

