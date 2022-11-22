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

int *valid;

static so_exec_t *exec;

int fd;

so_seg_t* findSegment(void *addr){

	// printf("segments_no: %d\n", (*exec).segments_no);
	// printf("imi da fault pe adresa %p\n", addr);
	for(int i = 0; i < (*exec).segments_no; i++){

		// printf("segaddr[%d] = %p\n", i, (void *)exec->segments[i].vaddr);

		if((char *)exec->segments[i].vaddr <= (char *)addr
		 && (char *)addr < ((char *)exec->segments[i].vaddr + exec->segments[i].mem_size)){
			return &(exec->segments[i]);
				
		}
	}
	printf("\n");

	return null;

}

void validate(void *pg_addr, size_t pgsize){

	if(valid == null){

		// printf("imi adauga prima adresa: %p\n", (void *)pg_addr);
		
		valid = malloc(sizeof(int));
		(*valid) = (int)pg_addr;
		return;
	}
	
	int *prc = valid;
	for(int i = 0; i < sizeof(valid) / sizeof(int *); i += sizeof(int)){

		// printf("adresa deja mapata %d\n", (*prc));

		if(*(prc + i) == (int)pg_addr){

			// printf("am gasit segmentul deja: %p\n", (void *)pg_addr);
			
			exit(139);
		}
	}

	// printf("nu e primul element si imi adauga adresa: %p\n", (void *)pg_addr);

	int *aux = realloc(valid, sizeof(valid) + sizeof(int));
	*(aux + (sizeof(valid))) = (int)pg_addr;
	// free(valid);
	valid = aux;


}

void cpy_mem(void *pg_addr, int seg_offset, so_seg_t *sgm, size_t page_size){

	char *buffer = malloc(page_size);
	
	lseek(fd, sgm->offset + seg_offset, SEEK_SET);
	
	memset(buffer, 0, page_size);
	
	// printf("filesize %u si pagesize %ld si memsize %u\n", sgm->file_size, (long)page_size, sgm->mem_size);

	size_t size = seg_offset + page_size;
	if(seg_offset > sgm->file_size){
		// printf("e dupa filesize\n");
		memcpy((void *)pg_addr, buffer, page_size);
		// free(buffer);
		return;
	}
	if(size > sgm->file_size){
		// printf("e putin in filesize\n");
		read(fd, buffer, sgm->file_size - seg_offset);
		memcpy((void *)pg_addr, buffer, page_size);
		// free(buffer);
		return;
	}
	// printf("e in filesize");
	read(fd, buffer, page_size);
	memcpy((void *)pg_addr, buffer, page_size);
	// free(buffer);

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

	// printf("imi da si return de: %p\n", (void *)sgm->vaddr);
	
	size_t pgsize = getpagesize();
	size_t seg_offset = (char *)info->si_addr - (char *)sgm->vaddr;
	size_t pg_offset = seg_offset % pgsize;
	seg_offset -= pg_offset;

	// printf("seg_offset = %ld\n", (long)seg_offset);

	validate((void *)sgm->vaddr + seg_offset, pgsize);

	void *pgaddr = mmap((void *)(sgm->vaddr) + seg_offset, 
	pgsize, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_SHARED | MAP_ANONYMOUS, 0, 0);

	// printf("a facut mmap la %p\n", pgaddr);

	cpy_mem(pgaddr, seg_offset, sgm, pgsize);

	mprotect(pgaddr, pgsize, sgm->perm);

	// printf("\n\n");

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
