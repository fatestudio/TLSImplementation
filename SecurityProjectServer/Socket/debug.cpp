#include <stdio.h>

bool debugflag = true;

bool DEBUG(char *str){
	if(debugflag){
		printf("%s", str);
	}
	return debugflag;
}
