# c_switch_open
## Kernel sys call triggered attack with switch() statement.

Example usage: sudo ./c_switch_open 510 0xc5 0x0 -v 

true case: (Ubuntu image, with Linux 4.20.2 with Skylake and Kaby lake CPU)
    sudo ./c_switch_open 510 0xc5 0x0 -v 
with highlighted true case:
    sudo ./c_switch_open 510 0xc5 0x0 -v | grep "1 [0-9][0-9]]"


If attack succeed, observations of both performance counter and accessing time should be varied from the regular cases (no attack). 

For example: (use performance counter 0xC5 0x20 )
regular cases: 
    [0 215] = [no MISP, slow data accessing time]

attack succeed: 
    [1 215] = [branch MISP happened, fast data accessing time due to data being cached.]


Note:
    - This distant attack example is demonstrated in exactly matched collision pattern, writer address, reader address and spec gadget address that needs to be correct aligned. 
    - Since the writer branch is inside of a system call in kernel space (in an Ubuntu image, with Linux 4.20.2), this address might get shifted in other versions of image or with different configuration settings during Kernel compilations, or KASLR type of protections if you have them on.  Please refer to the paper section 3.2 whenever fixing branch alignment is required.
    - In addition, it's possible to switch collision pattern to general DSB collision