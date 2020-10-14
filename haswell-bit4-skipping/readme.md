# New Haswell branch prediction vulnerabilities: "skipping" mechanism and bit-4 branch collision

We are reporting 2 branch prediction related hardware vulnerabilities in Intel Haswell CPUs, including:

1. **The "skipping" based transient execution mechanism on indirect branches**:  a new source for violation of program's architectural state --- potentially malicious speculative execution due to skipping of indirect jump/call instructions.

2. **The bit-4 branch collision**: a new branch instruction collision pattern in Intel Haswell CPUs that, when setting bit 4 in a specific way, two close branches could collide during branch prediction, triggering unexpected / malicious speculative execution.

Both the aboves are confirmed on an Intel Core i7-4800MQ and could lead to initiating speculative execution that violates architectural state, resulting in sensitive data leakage or other potential harmful exploits.  For instance, both of the above phenomena allow transient execution to appear either naturally in binaries or intentionally in code by a malicious software developer as a form of hidden Trojan.

## 1 The "Skipping" based transient execution mechanism on indirect branches

### 1.1 Brief of Spectre speculative execution attacks 

Recent speculative execution attacks based on controlling branch prediction demonstrated how maliciously initialized speculative execution can violate architectural state and lead to sensitive data leakage through covert channels. Spectre v1 attack relied on executing the wrong direction of a conditional branch. Spectre v2 attack relied on one software entity (attacker) injecting target into BTB that is later used by the CPU when executing another software entity (victim), allowing attacker to force speculative execution of arbitrary code.

### 1.2 New transient execution based on indirect branch "skipping"

We discovered a new branch instruction related transient execution pattern which is triggered when execution encounters an indirect branch, i.e an indirect jump or an indirect call.  **While BPU is resolving the target of indirect branch during branch prediction, instructions (around 100+) located below the branch instruction can be executed speculatively.** This attack seems working on Haswell but not working on Skylake and Kaby Lake.

### 1.3 Potential exploit: Proof of Concept for transient execution attack using the "Skipping" mechanism

In the attached source code, we give 2 For Proof-of-Concept (PoC) examples to demonstrate the "Skipping" mechanism transient attacks using either indirect call (in `PoC-icall.c`) or indirect jump (in `PoC-switch.c`). The attack rate / performance may depend on execution environment (CPU, OS, frequency and other workloads). Please note, provided code is not optimized. It's highly likely that it's possible to significantly improve the attack success rate. Please contact us if you have any questions. 

Both PoCs presented below have secret variable `position_secret` with value 42 and non-secret variable `position_nonsecret` with value 237. If attack is successful the memory address `user_dat[42*256]` is accessed (from speculative execution) and becomes cached in CPU data cache.

#### 1.3.1 `PoC-switch.c` explanation:
In this example, *case 0* and *case 2* in the `switch` statement can access `user_dat` with either *secret* value (in case 0), or *nonsecret* value (in case 2). 

Since case selector `sw` is fixed to point to case 2.  The execution of switch statement should always take place at nowhere but case 2 and accesses `user_data` with non secret value as `user_dat[position_nonsecret*256]`.

However, during resolving the indirect jump inside of the switch statement, "skipping" mechanism advances the transient execution to the instructions located right after the indirect jump, i.e. case 0:

```
  // please note the dump could be different due to different compilers, compiler versions, etc
  400c32:   ff e0                   jmpq   *%rax // indirect branch that is skipped
  400c34:   90                      nop
  400c35:   90                      nop

  /* case 0 this code is erroneously executed */
  400c36:   8b 05 c4 94 2b 00       mov    0x2b94c4(%rip),%eax        # 6ba100 <position_secret>
  400c3c:   89 45 f8                mov    %eax,-0x8(%rbp)
  400c3f:   8b 45 f8                mov    -0x8(%rbp),%eax
  400c42:   c1 e0 08                shl    $0x8,%eax
  400c45:   48 98                   cltq   
  400c47:   8b 04 85 40 a1 6c 00    mov    0x6ca140(,%rax,4),%eax
  400c4e:   89 05 4c 37 31 00       mov    %eax,0x31374c(%rip)        # 7143a0 <var>
  400c54:   eb 4a                   jmp    400ca0 <main+0x120>

  /* case 1 */
  400c56:   90                      nop
  400c57:   90                      nop
  400c58:   90                      nop
  400c59:   eb 45                   jmp    400ca0 <main+0x120>
  
  /* case 2 this code is the one that must always be executed */
  400c5b:   90                      nop
  400c5c:   90                      nop
  400c5d:   90                      nop
  400c5e:   90                      nop
  400c5f:   8b 05 bb 14 2c 00       mov    0x2c14bb(%rip),%eax        # 6c2120 <position_nonsecret>
  400c65:   89 45 f8                mov    %eax,-0x8(%rbp)
  400c68:   8b 45 f8                mov    -0x8(%rbp),%eax
  400c6b:   c1 e0 08                shl    $0x8,%eax
  400c6e:   48 98                   cltq
  400c70:   8b 04 85 40 a1 6c 00    mov    0x6ca140(,%rax,4),%eax
  400c77:   89 05 23 37 31 00       mov    %eax,0x313723(%rip)        # 7143a0 <var>
  400c7d:   eb 21                   jmp    400ca0 <main+0x120>   
```

As a result, `user_dat[position_secret*256]` is cached, and the secret could be observable via cache covert channel via timing analysis. Please note, `#define CACHE_HIT_THRESHOLD 200` is hardcoded for our machine, other machines may require other cache hit threshold.

#### 1.3.2 `PoC-icall.c` explanation:
In this PoC we have two functions 'f2' and 'f3'. Function 'f2' initiates a memory access at address `user_dat[r14 * 256]` where `r14` is the value stored in register `%r14` and then returns. Function 'f3' loads non-secret value into `r14` and returns. Please note both functions are striped and contain no prologue or epilogue, see object dump.

In the main loop of this experiment, register `r14` is loaded with secret value at first.  Before using it as an index for array access in function `_f2`, an indirect call to `_f3` is performed which must erase the secret value and replaces it with a non-secret one.  

However, when resolving the indirect call, "skipping" mechanism advances the transient execution to the following instructions, i.e. `_f2`.  Thus, the secret value is preserved and then used for data accessing during speculative execution. As a result, `user_dat[position_secret*256]` is cached. Then the secret value becomes observable through cache covert channel via timing analysis.


#### 1.3.3 Run PoC 
Build:  
    `make`

Usage:  
    ```
    ./PoC-icall \[# of bits to leak\] \(e.g. 1, 10, 100, etc.\)
    ./PoC-switch \[# of bits to leak\] \(e.g. 1, 10, 100, etc.\)
    ```

## 2 The bit-4 branch collision

### 2.2 New collision pattern in Haswell: bit-4 branch collision

This collision patten is similar to the one specific to Skylake and Kaby Lake we reported earlier. However instead of bit #5, bit #4 plays critical role. We think it may be due to doubling the size of DSB window in SL and KL.

#### Description

Normally, to trigger a collision in BTB, two branches must have the exactly the same *index*, *tag* and *offset*. However, based on our observations there exists another collision pattern in Haswell, i.e. **If the branch that writes into BTB has bit 4 of address is set and the branch that reads BTB has bit 4 is not set, the offset bits may be ignored.**  The new pattern could cause collisions between branches within the same address space.

For instance, if we first execute a branch for which the last byte is located at `0x400a7f` and then another branch at address `0x400a6b`, branch predictor unit may use the target from the first branch to predict destination of the second.


### 2.3 Violation of architectural state

Same as previously reported.


### 2.4 Potential exploit: Proof of Concept for transient execution attack using bit-4 branch collision

Attached source code shows a Proof-of-Concept of bit-4 branch collision transient execution attack is similar to previously demonstrated.  

#### 2.4.1 PoC explanation:
For proof-of-concept we use a simple attack scenario: 

There are two functions, `f1` and `f2` are located next to each other. Function `f1` operates with sensitive data, which is loaded into registers in function prologue. This function does not contain any leaking code, (including side-channel leakage) and can be inspected. The function contains an indirect jump instruction.  A `lfence` is placed right after the indirect jump instruction to prevent any transient executions based on "skipping" of indirect branches. 

Function `f2` operates with non-sensitive data and thus may contain code that leaks its variables through side/covert channels. From architectural state point of view no leakage of sensitive data is possible. However, due to bit-4 branch collision, speculative execution with instruction from `f2` and context of `f1` will happen, resulting in sensitive data leakage.  

We use assembly code labeled by `_f1` and `_f2` to implement potential code for the functions. When `f1` is executed, it loads secret value `42` into register `r14`. Then it jumps to a return and completes its execution. Due to BTB poisoning instead it first speculatively jumps to the body of `_f2` which leaks the secret value by performing a memory access into a non-sensitive data structure with address dependent from the value stored in `r14`. Please note, each time we execute function `_f2` we first load non-sensitive value `256` into `r14`.

Below we present comparison of architectural state and microarchitectural states during execution of the PoC.

| step | line # | Arch state | uArch state | note |
|------|--------------|----------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------|
| 1 | 183,<br> 184 | `r14 = 256`<br> `call _f2` |  | `r14` is loaded with non-secret value.<br> Function `_f2` is started. |
| 2 | 135 | jump to `load_dat` location | BTB update:<br> `0x...74 -> load_data` | `_f2` invokes `load_data`<br> gadget to access `user_dat`. |
| 3 | 159 | `some_var = user_dat[256 * 256]` |  | Revealing value of r14 (non-secret) by accessing the array:<br> `user_dat[256*256]`. |
| 4 | 161 | ret |  | `_f2` returns. |
| 5 | 187-<br> 189 |  |  | Execute other code,<br> flush user data, etc. |
| 6 | 194 | `call _f1` |  | Executes `_f1`. |
| 7 | 102-<br> 104 | `r12 = ret_address`<br> `r14 = secret` |  | `_f1` acquires 2 arguments:<br> 1. an address pointing to return<br> 2. secret value 42 (hold by `r14`). |
| 8 | 117 | jump to a `ret` | BTB lookup with address `0x...63` produces a hit.<br> Address `load_data` will be used as the target addr from the prediction. <br> This happens due to bit-4 collision between: <br> `0x...74` and `0x...63` |  
| 9 | 159 |  | Memory access to `user_dat[42 * 256]` | Secret data leaked via cache <br> covert channel. Then the value <br>is read in `timing_analysis()` function. |
| 10 | 117 | jump to a `ret` | Correct branch target resolved.<br> Execution rewinds. <br> |  |
| 11 | 89 | ret |  | `_f1` returns. |

#### 2.4.2 Run PoC 
Build:  
    `make`

Usage:  
    `./PoC-bit4 [# of bits to leak] (e.g. 1, 10, 100, etc.)`
