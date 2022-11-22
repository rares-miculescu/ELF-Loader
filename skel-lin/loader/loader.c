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
#include <fcntl.h>


#include "exec_parser.h"

#define null NULL

long *valid;

static so_exec_t *exec;

int fd;

so_seg_t* findSegment(void *addr){

	// printf("(find)segments_no: %d | ", (*exec).segments_no);
	// printf("(find)imi da fault pe adresa %p | ", addr);
	
	for(int i = 0; i < (*exec).segments_no; i++){

		// printf("segaddr[%d] = %p | ", i, (void *)exec->segments[i].vaddr);

		if((char *)exec->segments[i].vaddr <= (char *)addr
		 && (char *)addr < ((char *)exec->segments[i].vaddr + exec->segments[i].mem_size)){
			return &(exec->segments[i]);
				
		}
	}
	// printf("\n");

	return null;

}

void validate(void *pg_addr, size_t pgsize){

	if(valid == null){

		// printf("(val)imi adauga prima adresa: %p | ", (void *)pg_addr);
		
		valid = malloc(sizeof(long));
		(*valid) = (long)pg_addr;
		return;
	}
	
	long *prc = valid;
	for(int i = 0; i < sizeof(valid) / sizeof(long *); i += sizeof(long)){

		// printf("(val)adresa deja mapata %lx | ", (*prc));

		if(*(prc + i) == (long)pg_addr){

			// printf("(val)am gasit segmentul deja: %p | ", (void *)pg_addr);
			
			exit(139);
		}
	}

	// printf("(val)nu e primul element si imi adauga adresa: %p | ", (void *)pg_addr);

	long *aux = realloc(valid, sizeof(valid) + sizeof(long));
	*(aux + (sizeof(valid))) = (long)pg_addr;
	valid = aux;


}

void cpy_mem(void *pg_addr, int seg_offset, so_seg_t *sgm, size_t page_size){

	char *buffer = malloc(page_size);
	
	lseek(fd, sgm->offset + seg_offset, SEEK_SET);
	
	memset(buffer, 0, page_size);
	
	// printf("(cpm)filesize %u si pagesize %ld si memsize %u | ", sgm->file_size, (long)page_size, sgm->mem_size);

	size_t size = seg_offset + page_size;
	// printf("(cpm)pgaddr = %p | ", pg_addr);
	if(seg_offset > sgm->file_size){
		// printf("(cpm)e dupa filesize | ");
		memcpy((void *)pg_addr, buffer, page_size);
		free(buffer);
		return;
	}
	if(size > sgm->file_size){
		// printf("(cpm)e putin in filesize | ");
		read(fd, buffer, sgm->file_size - seg_offset);
		memcpy((void *)pg_addr, buffer, page_size);
		free(buffer);
		return;
	}
	// printf("(cpm)e in filesize | ");
	read(fd, buffer, page_size);
	memcpy((void *)pg_addr, buffer, page_size);
	free(buffer);

}


static void segv_handler(int signum, siginfo_t *info, void *context)
{
	/* TODO - actual loader implementation */
	so_seg_t *sgm = findSegment(info->si_addr);

	if(sgm == null){
		// struct sigacion sa;
		// memset(&sa, 0, sizeof(sa));
		// sigaction(SIGSEGV, &sa, 0);

		exit(139);

	}

	// printf("(main)imi da si return de: %p | ", (void *)sgm->vaddr);
	
	size_t pgsize = getpagesize();
	size_t seg_offset = (char *)info->si_addr - (char *)sgm->vaddr;
	size_t pg_offset = seg_offset % pgsize;
	seg_offset -= pg_offset;

	// printf("(main)seg_offset = %ld | ", (long)seg_offset);

	validate((void *)sgm->vaddr + seg_offset, pgsize);

	void *pgaddr = mmap((void *)(sgm->vaddr) + seg_offset, 
	pgsize, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_SHARED | MAP_ANONYMOUS, 0, 0);

	// printf("(main)a facut mmap la %p | ", pgaddr);

	// printf("nuj\n");

	cpy_mem(pgaddr, seg_offset, sgm, pgsize);

	// printf("nuj");

	mprotect(pgaddr, pgsize, sgm->perm);

	// printf("                                              ");

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
	fd = open(path, O_RDONLY);

	exec = so_parse_exec(path);
	if (!exec)
		return -1;

	so_start_exec(exec, argv);

	return -1;
}
