#include <stdio.h>
#include <stdlib.h>

#include "logoffset.h"

int main(int argc, char *argv)
{
    int opt = 1;
    int ret = -1;

////TODO XXX
    while ((opt = getopt(argc, argv, "q")) != -1) {
        switch(opt) {
            case 'q':
                
            default:
        }
    }


    return 0;
}
    
