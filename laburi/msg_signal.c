    #include <stdio.h>
    #include <stdlib.h>
     
    #define __USE_GNU
    #include <string.h>
     
    #include <signal.h>
     
    int main(void) {
        char *sig_p = strsignal(SIGKILL);
     
        printf("signal %d is %s\n", SIGKILL, sig_p);
     
        psignal(SIGSEGV, "death and decay");
     
        sigset_t set;
 
        sigemptyset(&set);
        sigaddset(&set, SIGINT);
        
        while (1) {
            sleep(5);
            sigprocmask(SIG_BLOCK, &set, NULL);
            sleep(5);
            sigprocmask(SIG_UNBLOCK, &set, NULL);
        }


        return 0;
    }

