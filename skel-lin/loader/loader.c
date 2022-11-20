/*
 * Loader Implementation
 *
 * 2022, Operating Systems
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

#include "exec_parser.h"

#define null NULL

static so_exec_t *exec;

so_seg_t* findSegment(void *addr){


	for(int i = 0; i < (*exec).segments_no; i++){

		if((char *)exec->segments[i].vaddr > (char *)addr){
			return &(exec->segments[i - 1]);
				
		}
	}

	return null;

}


static void segv_handler(int signum, siginfo_t *info, void *context)
{
	/* TODO - actual loader implementation */
	size_t pgsize = getpagesize();
	so_seg_t *sgm = findSegment(info->si_addr);
	
	
}

int so_init_loader(void)
{
	int rc;
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = segv_handler;
	sa.sa_flags = SA_SIGINFO;
	rc = sigaction(SIGSEGV, &sa, NULL);
	if (rc < 0) {
		perror("sigaction");
		return -1;
	}
	return 0;
}

int so_execute(char *path, char *argv[])
{
	exec = so_parse_exec(path);
	if (!exec)
		return -1;

	so_start_exec(exec, argv);

	return -1;
}
