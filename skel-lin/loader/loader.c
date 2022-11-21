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

uintptr_t *valid;

static so_exec_t *exec;

int fd;

so_seg_t* findSegment(void *addr){

	// printf("segments_no: %d\n", (*exec).segments_no);
	for(int i = 0; i < (*exec).segments_no; i++){

		if((char *)exec->segments[i].vaddr < (char *)addr
		 && (char *)addr < ((char *)exec->segments[i].vaddr + exec->segments[i].mem_size)){
			return &(exec->segments[i]);
				
		}
	}
	printf("\n");

	return null;

}

void validate(uintptr_t pg_addr){

	size_t addr_size = sizeof(pg_addr);
	printf("addr_size: %ld\n", (long)addr_size);

	if(valid == null){
		printf("imi adauga prima adresa: %p\n", (void *)pg_addr);
		valid = malloc(sizeof(pg_addr));
		(*valid) = pg_addr;
		return;
	}
	
	uintptr_t *prc = valid;
	for(; (void *)(*prc) != null; prc += addr_size){
		if((*prc) == pg_addr){
			printf("am gasit segmentul deja: %p\n", (void *)pg_addr);
			exit(139);
		}
	}

	printf("nu e primul element si imi adauga adresa: %p\n", (void *)pg_addr);
	uintptr_t *aux = realloc(valid, sizeof(valid) + addr_size);
	*(aux + (sizeof(valid))) = pg_addr;
	// free(valid);
	valid = aux;


}

void cpy_mem(void *pg_addr, int seg_offset, so_seg_t *sgm, size_t page_size){

	char *buffer = malloc(page_size);
	
	lseek(fd, sgm->offset + seg_offset, SEEK_SET);
	
	memset(buffer, 0, page_size);
	
	size_t size = seg_offset + page_size;
	if(seg_offset > sgm->file_size){
		memcpy((void *)pg_addr, buffer, page_size);
		// free(buffer);
		return;
	}
	if(size > sgm->file_size){
		read(fd, buffer, sgm->file_size - seg_offset);
		memcpy((void *)pg_addr, buffer, page_size);
		// free(buffer);
		return;
	}
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

	printf("imi da si return de: %p\n", (void *)sgm->vaddr);
	
	size_t pgsize = getpagesize();
	size_t seg_offset = (char *)info->si_addr - (char *)sgm->vaddr;
	size_t pg_offset = seg_offset % pgsize;
	seg_offset -= pg_offset;

	printf("seg_offset = %ld\n", (long)seg_offset);

	validate(sgm->vaddr + seg_offset);

	void *pgaddr = mmap((void *)(sgm->vaddr + seg_offset), 
	pgsize, PROT_READ | PROT_WRITE, MAP_FIXED, 0, 0);

	printf("a facut mmap la %p", pgaddr);

	cpy_mem(pgaddr, seg_offset, sgm, pgsize);

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
