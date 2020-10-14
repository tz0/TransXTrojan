# The DSB bit-5 branch collision

We are reporting a new branch instruction collision pattern that is 
present in multiple Intel CPUs. Confirmed on **Kaby Lake** and
**Skylake**. This collision can lead to
initiating speculative execution that violates 
architectural state and may lead to sensitive data leakage.
These collisions may appear either naturally in binaries
or can be intentionally introduced in code by a malicious 
software developer as a form of Trojan exploiting speculative
execution.

## Known BTB collision pattern

Prior works [1,2] partially reverse engineered mechanisms present in
Intel's CPUs for predicting branch instruction targets. 
Two different branch instructions can collide in branch target buffer (BTB).
This enables side channel attacks [1] and speculative execution based attacks [2].
Collisions are possible due to the addressing scheme used by BTB. In particular:

1. When performing a BTB lookup/update bits [47:30] are ignored resulting in collisions of branches where only higher bits are different. That may lead to poisoning kernel branches from userland.
2. Bits [29:14] are XOR-ed together to get a 8-bit tag which is matched during BTB lookups.

Existing microcode based protections cover generally two scenarios:

1. Collisions between User and Kernel by tagging BTB entries with privilege level (IBRS)
2. Collisions between two User processes (or two kernels) by flushing BTB on context/VM switches.

However, collisions within the same address space (for instance between .text and a 
library code segment) still can happen [3]. Such collisions are difficult to achieve because:

1. For collisions between two code segment (.text and libc) ASLR will be a problem since it randomizes both addresses each time application is executed. In this situation matching bits [29:12] is very challenging.
2. Collisions within same segment utilizing folding of bits [29:14] are possible, but they
require code segment being not less than 4MB. ASLR further complicates collision creation.

## New DSB collision pattern

We discovered a new branch collision pattern which is triggered by setting bit 5 in a
specific way. In addition when it is activated bits [0:4] of branch instruction address
are ignored. That allows collisions between branches located close to each other.

Based on our experiments, to perform a BTB lookups CPU will use:

1. bits [29:14] as *tag bits* which are XORed together and 8-bit *tag* is compared.
2. bits [14:5] as index to access BTB.
3. bits [4:0] are used as offset

Normally to trigger a collision in BTB two branches must have the exactly the same *index*, *tag* and *offset*. However, based on our observations there exist another collision pattern. **If the branch that writes into BTB has bit 5 of address is set and the branch that reads BTB has bit 5 of not set, the offset bits may be ignored.** For instance if we first execute a branch for which the last byte is located at `0x7100080104a` and then another branch at address `0x71000801028`, branch predictor may use the target from the first branch to predict destination of the second.

## Violation of architectural state

In short, bit-5 collision requires the last byte of a WB (writer branch) 
to be located at the lower half of a cache line, while the last byte of a RB
(reader branch) is located in the higher half of the same cache line.  
The new type of collision allows reliably creating branch collisions within the
same address space when ASLR is enabled because RB and WM branches can be 
placed inside one cache line (64 Bytes). This enables creating
portable Trojans which do not rely on any hard-coded addresses.
For further details please see the paper draft.

Our experiments show that it's also possible to combine known
collision patten, i.e. exploiting ignored or XOR-ed bits with the new pattern.
Please see Fig. 8 in the paper.

## Potential exploit: Proof of Concept for transient execution attack using bit-5 branch collision

Attached source code shows a Proof-of-Concept of bit-5 collision transient execution
attack.  The attack rate / performance depends on execution environment (CPU, OS, other workloads), 
and it could be further improved with genetic algorithm approach (see paper).  Please contact us or 
refer to our paper for the detail of improvement. 

### PoC explanation:
For proof-of-concept we use a simple attack scenario:
There are two functions, `f1` and `f2` located next to each other. Function `f1` operates with sensitive
data, which is loaded into registers in function prologue. The function does not contain any leaking code,
(including side-channel leakage) and can be inspected. The function contains an indirect jump instruction.
Function `f2` operates with non-sensitive data and thus may contain code that leaks its variables through
side/covert channels. From architectural state point of view no leakage of sensitive data is possible.
However, due to branch collision speculative execution with instruction from `f2` and context of `f1` will happen resulting in sensitive data leakage.  

We use assembly code labeled by `_f1` and `_f2` to implement potential code for the functions.
When `f1` is executed it loads secret value `42` into register `r14`. Then it jumps to a return
and completes its execution. Due to BTB poisoning instead it first speculatively jumps to the body of `_f2`
which leaks the secret value by performing a memory access into a non-sensitive data structure with address dependent form
the value stored in `r14`. Please note, each time we execute function `_f2` we first load non-sensitive value `256`
into `r14`.

Below we present comparison of architectural state and microarchitectural states during execution of the PoC.

| step | line # | Arch state | uArch state | note |
|------|--------------|----------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------|
| 1 | 180,<br> 181 | `r14 = 256`<br> `call _f2` |  | `r14` is loaded with non-secret value.<br> Function `_f2` is started. |
| 2 | 127 | jump to `load_dat` location | BTB update:<br> `0xxx3d -> load_data` | `_f2` invokes `load_data`<br> gadget to access `user_dat`. |
| 3 | 154 | `some_var = user_dat[256 * 256]` |  | Revealing value of r14 (non-secret) by accessing the array:<br> `user_dat[256*256]`. |
| 4 | 156 | ret |  | `_f2` returns. |
| 5 | 184-<br> 187 |  |  | Execute other code.<br> Re-execute `_f2`, etc. |
| 6 | 192 | `call _f1` |  | Executes `_f1`. |
| 7 | 106-<br> 108 | `r12 = ret_address`<br> `r14 = secret` |  | `_f1` acquires 2 arguments:<br> 1. an address pointing to return<br> 2. secret value 42 (hold by `r14`). |
| 8 | 110 | jump to a `ret` | BTB lookup with address `0xxx1b` produces a hit.<br> Address `load_data` will be used as prediction. <br> This happens due to 5-bit collision between <br> `0xxx3d` and `0xxx1b` |  
| 9 | 154 |  | Memory access to `user_dat[42 * 256]` | Secret data leaked via cache <br> covert channel. Then the value <br>is read in `timing_analysis()` function. |
| 10 | 110 | jump to a `ret` | Correct branch target resolved.<br> Execution rewinds. <br> |  |
| 11 | 93 | ret |  | `_f1` returns. |


### Run PoC 
Build:  
    `make`

Usage:  
    The variant with nondispersed spec gadget:
        `./poc-nondispersed [# of bits to leak] (e.g. 1, 10, 100, etc.)`
    The variant with dispersed spec gadget:
        `./poc [# of bits to leak] (e.g. 1, 10, 100, etc.)` 


##References  

[1] Evtyushkin, Dmitry, Dmitry Ponomarev, and Nael Abu-Ghazaleh. "Jump over ASLR: Attacking branch predictors to bypass ASLR." The 49th Annual IEEE/ACM International Symposium on Microarchitecture. IEEE Press, 2016.  
[2] Kocher, Paul, et al. "Spectre attacks: Exploiting speculative execution." arXiv preprint arXiv:1801.01203 (2018).  
[3] Canella, Claudio, et al. "A systematic evaluation of transient execution attacks and defenses." arXiv preprint arXiv:1811.05441 (2018).  
