# The "Skipping" based transient execution mechanism on indirect branches

Recent speculative execution attacks based on controlling branch prediction
demonstrated how maliciously initialized speculative execution can violate
architectural state and lead to sensitive data leakage through covert channels.
Spectre v1 attack relied on executing the wrong direction of a conditional branch.
Spectre v2 attack relied on one software entity (attacker) injecting target into BTB
that is later used by the CPU when executing another software entity (victim),
allowing attacker to force speculative execution of arbitrary code.

We are reporting a new source of violation of program's architectural state --- potentially malicious speculative execution due to skipping of indirect jump/call
instructions. Attacks based on this phenomenon do 
require no conditional branches or branch target injections. 
We confirmed this mechanism on AMD Ryzen Threadripper 1950X. 
This kind of transient execution may appear either naturally in binaries
or can be intentionally introduced in code by a malicious 
software developer as a form of hidden malware. This malicious code 
does not contain any suspicious instructions in any place reachable
by the program according to the architectural state. However,
due to skipping of indirect call/jump instructions, the
architectural state is violated and which may result in malicious behavior.


## New transient execution based on indirect branch "skipping"

We discovered a new branch instruction related transient execution pattern which is triggered
when execution encounters an indirect branch, i.e an indirect jump or an indirect call.  **During branch mispredictions, while 
BPU is resolving the target of indirect branch, instructions (around 100+) located below the branch instruction 
can be executed speculatively.**  The outcome of this type of transient execution can 
be critical violation of architectural state.


## Potential exploit: Proof of Concept for transient execution attack using the "Skipping" mechanism

In the attached source code, we give 2 For Proof-of-Concept (PoC) examples to demonstrate the "Skipping" mechanism transient attacks using either indirect call (in `PoC-icall.c`) or indirect jump (in `PoC-switch.c`).  
The attack rate / performance may depend on execution environment (CPU, OS, frequency and other workloads). Please note, provided code is not optimized. It's highly likely that it's possible to significantly improve the attack success rate.
Please contact us if you have any questions. 

Both PoCs presented bellow have secret variable `position_secret` 
with value 42 and non-secret variable `position_nonsecret` with value 237.
If attack is successful the memory address `user_dat[42*256]` is accessed (from speculative execution) and becomes cached in CPU data cache.

### `PoC-switch.c` explanation:
In this example, *case 0* and *case 2* in the `switch` statement can access `user_dat` with either *secret* value (in case 0), or *nonsecret* value (in case 2). 

Since case selector `sw` is fixed to point to case 2.  The execution of switch statement should always take place at nowhere but case 2 and accesses `user_data` with non secret value as `user_dat[position_nonsecret*256]`.

However, during resolving the indirect jump inside of the switch statement, "skipping" mechanism advances the transient execution to the instructions located right after the indirect jump, i.e. case 0:

```
  400c32:	ff e0                	jmpq   *%rax // indirect branch that is skipped
  400c34:	90                   	nop
  400c35:	90                   	nop

  /* case 0 this code is erroneously executed */
  400c36:	8b 05 c4 94 2b 00    	mov    0x2b94c4(%rip),%eax        # 6ba100 <position_secret>
  400c3c:	89 45 f8             	mov    %eax,-0x8(%rbp)
  400c3f:	8b 45 f8             	mov    -0x8(%rbp),%eax
  400c42:	c1 e0 08             	shl    $0x8,%eax
  400c45:	48 98                	cltq   
  400c47:	8b 04 85 40 a1 6c 00 	mov    0x6ca140(,%rax,4),%eax
  400c4e:	89 05 4c 37 31 00    	mov    %eax,0x31374c(%rip)        # 7143a0 <var>
  400c54:	eb 4a                	jmp    400ca0 <main+0x120>

  /* case 1 */
  400c56:	90                   	nop
  400c57:	90                   	nop
  400c58:	90                   	nop
  400c59:	eb 45                	jmp    400ca0 <main+0x120>
  
  /* case 2 this code is the one that must always be executed */
  400c5b:	90                   	nop
  400c5c:	90                   	nop
  400c5d:	90                   	nop
  400c5e:	90                   	nop
  400c5f:	8b 05 bb 14 2c 00    	mov    0x2c14bb(%rip),%eax        # 6c2120 <position_nonsecret>
  400c65:	89 45 f8             	mov    %eax,-0x8(%rbp)
  400c68:	8b 45 f8             	mov    -0x8(%rbp),%eax
  400c6b:	c1 e0 08             	shl    $0x8,%eax
  400c6e:	48 98                	cltq
  400c70:	8b 04 85 40 a1 6c 00 	mov    0x6ca140(,%rax,4),%eax
  400c77:	89 05 23 37 31 00    	mov    %eax,0x313723(%rip)        # 7143a0 <var>
  400c7d:	eb 21                	jmp    400ca0 <main+0x120>   
```

As a result, `user_dat[position_secret*256]` is cached, and the secret could be observable via cache covert channel via timing analysis. Please note, `#define CACHE_HIT_THRESHOLD 200` is hardcoded for our machine, other machines may require other cache hit threshold.

### `PoC-icall.c` explanation:
In this PoC we have two functions 'f2' and 'f3'. Function 'f2' initiates a memory access at address `user_dat[r14 * 256]` where `r14` is the value stored in register `%r14` and then returns.
Function 'f3' loads non-secret value into `r14` and returns. Please note both functions are
striped and contain no prologue or epilogue, see object dump.

In the main loop of this experiment, register `r14` is loaded with secret value at first.  Before using it as an index for array access in function `_f2`, an indirect call to `_f3` is performed which must erase the secret value and replaces it with a non-secret one.  

However, when resolving the indirect call, "skipping" mechanism advances the transient execution to the
following instructions, i.e. `_f2`.  Thus, the secret value is preserved and then used for data accessing during speculative execution. As a result, `user_dat[position_secret*256]` is cached. Then the secret value becomes observable through cache covert channel via timing analysis.


### Run PoC 
Build:  
    `make`

Usage:  
    `./poc \[# of bits to leak\] \(e.g. 1, 10, 100, etc.\)`

