#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
 
// pid_t child1, child2;
// int child1_pid;
 
 
void signal_handler(int signum)
{
 
    switch(signum) {
        case SIGINT:
            printf("CTRL+C received in %d Exiting\n", getpid());
            exit(EXIT_SUCCESS);
        case SIGUSR1:
            printf("SIGUSR1 received. Continuing execution\n");
    }
}
 
int main(void)
{
 
    printf("Process %d started\n", getpid());
 
    /* Semnale ca SIGKILL sau SIGSTOP nu pot fi prinse */
    if (signal(SIGKILL, signal_handler) == SIG_ERR)
        printf("\nYou shall not catch SIGKILL\n");
 
    if(signal(SIGINT, signal_handler) == SIG_ERR) {
        printf("Unable to catch SIGINT");
        exit(EXIT_FAILURE);
    }
 
    if(signal(SIGUSR1, signal_handler) == SIG_ERR) {
        printf("Unable to catch SIGUSR1");
        exit(EXIT_FAILURE);
    }
 
 
    printf("Press CTRL+C to stop us\n");
 
    while(1) {
        sleep(1);
    }
 
    return 0;
}