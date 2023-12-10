#include <stdio.h>
#include <stdlib.h>

short hash(unsigned char * s){

    unsigned short h = 0;
    unsigned char *curr = s; //creating rbp-0x10
    for (int i = 0; *curr != '\0'; i++, curr++)
    {
        if (i % 2 == 0) {
            unsigned short val = *(unsigned short *) curr; //creating rbp-0x16
            val *= 0x1906;
            h ^= val;
        } else {
            unsigned char val = *curr; //creating rbp-0x19
            val = ((val << 3) + val) *2;
            h ^= val;
        }
    }

    return h;

}

int main(int argc, char * argv[]){

    for(int i =1;i<argc;i++)
        printf("hash(\"%s\")=0x%04hx\n",argv[1], hash(argv[i]));
}
