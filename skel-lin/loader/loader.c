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

//array where we store what pages were added
long *valid;

//struct of ELF executable
static so_exec_t *exec;

//file descriptor
int fd;


//function that finds the segment that contains the given address
so_seg_t* findSegment(void *addr)
{

	for(int i = 0; i < (*exec).segments_no; i++){

		if((char *)exec->segments[i].vaddr <= (char *)addr
		 && (char *)addr < ((char *)exec->segments[i].vaddr + exec->segments[i].mem_size)){
			return &(exec->segments[i]);
				
		}
	}

	return null;

}

//function that uses the array valid to verifiy if the address was already mapped or not
//if it was mapped exits with seg fault, else it adds the address to the array
void validate(void *pg_addr, size_t pgsize){

	if(valid == null){
		
		valid = malloc(sizeof(long));
		(*valid) = (long)pg_addr;
		return;
	}
	
	long *prc = valid;
	for(int i = 0; i < sizeof(valid) / sizeof(long *); i += sizeof(long))
	{

		if(*(prc + i) == (long)pg_addr)
			exit(139);
		
	}

	long *aux = realloc(valid, sizeof(valid) + sizeof(long));
	*(aux + (sizeof(valid))) = (long)pg_addr;
	valid = aux;

}

//copies the memory on the virtual memory
//we have 3 cases here, where the entire page is in the filesize, when a part of 
//the page is in the filesize and when none of the page is in the filesize
void cpy_mem(void *pg_addr, int seg_offset, so_seg_t *sgm, size_t page_size){

	char *buffer = malloc(page_size);
	
	lseek(fd, sgm->offset + seg_offset, SEEK_SET);
	
	memset(buffer, 0, page_size);

	size_t size = seg_offset + page_size;

	if(seg_offset > sgm->file_size){

		memcpy((void *)pg_addr, buffer, page_size);
		free(buffer);
		return;
	}
	if(size > sgm->file_size){

		read(fd, buffer, sgm->file_size - seg_offset);
		memcpy((void *)pg_addr, buffer, page_size);
		free(buffer);
		return;
	}

	read(fd, buffer, page_size);
	memcpy((void *)pg_addr, buffer, page_size);
	free(buffer);

}

//the handler finds the segment where the fault was made, calculates the 
//address of the page, chacks if it was already added, maps the page and
//copies the page from the file to the memory
static void segv_handler(int signum, siginfo_t *info, void *context)
{
	so_seg_t *sgm = findSegment(info->si_addr);

	if(sgm == null){

		exit(139);

	}
	
	size_t pgsize = getpagesize();
	size_t seg_offset = (char *)info->si_addr - (char *)sgm->vaddr;
	size_t pg_offset = seg_offset % pgsize;
	seg_offset -= pg_offset;

	validate((void *)sgm->vaddr + seg_offset, pgsize);

	void *pgaddr = mmap((void *)(sgm->vaddr) + seg_offset, 
	pgsize, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_SHARED | MAP_ANONYMOUS, 0, 0);

	cpy_mem(pgaddr, seg_offset, sgm, pgsize);

	mprotect(pgaddr, pgsize, sgm->perm);

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
