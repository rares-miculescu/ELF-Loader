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
#include <sys/mman.h>


#include "exec_parser.h"

#define null NULL

static so_exec_t *exec;

so_seg_t* findSegment(void *addr){

	printf("%d\n", (*exec).segments_no);
	for(int i = 0; i < (*exec).segments_no; i++){

		printf("%d ",i);
		if((char *)exec->segments[i].vaddr < (char *)addr
		 && (char *)addr < ((char *)exec->segments[i].vaddr + exec->segments[i].mem_size)){
			printf("intrat\n");
			return &(exec->segments[i]);
				
		}
	}
	printf("\n");

	return null;

}




static void segv_handler(int signum, siginfo_t *info, void *context)
{
	/* TODO - actual loader implementation */
	so_seg_t *sgm = findSegment(info->si_addr);

	if(sgm == null){
		// struct sigacion sa;
		// memset(&sa, 0, sizeof(sa));
		// sigaction(SIGSEGV, &sa, 0);

		exit(SIGSEGV_ERROR);

	}
	

	printf("imi da si return de: %p\n", sgm->vaddr);
	
	size_t pgsize = getpagesize();
	size_t seg_offset = (char *)info->si_addr - (char *)sgm->vaddr;
	size_t pg_offset = seg_offset % pgsize;
	seg_offset -= pg_offset;

	printf("seg_offset = %ld\n", (long)seg_offset);




	mmap(sgm->vaddr + seg_offset, pgsize, PROT_READ | PROT_WRITE, MAP_FIXED, 0, 0);




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
