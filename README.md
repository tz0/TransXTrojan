# About TransXTrojan (working title)
The repository contains some experiments and PoCs used by our work: "Exploring Branch Predictors for Constructing Transient Execution Trojans" All details can be found in our ASPLOS '20 [paper](https://doi.org/10.1145/3373376.3378526) here.

Here is a sample format for citing our work:
```
@inproceedings{Zhang2020TransXTrojan,
author = {Zhang, Tao and Koltermann, Kenneth and Evtyushkin, Dmitry},
title = {Exploring Branch Predictors for Constructing Transient Execution Trojans},
year = {2020},
booktitle = {Proceedings of the Twenty-Fifth International Conference on Architectural Support for Programming Languages and Operating Systems},
pages = {667–682},
location = {Lausanne, Switzerland},
series = {ASPLOS '20}
}
```

# Contents
Current repo consists of: (20201014)
- bit5: DSB bit 5 attack PoC for **Skylake & Kabylake**
- distant: Distant attack PoC for **Skylake & Kabylake** with particular ver of Kernel, see readme in side the dir.
- ryzen-skipping: skipping attack PoC for **ryzen**
- haswell-bit4-skipping: attack PoCs for **Haswell** including both DSB bit4 attack and skipping attack

Staging (TBD):
- bin-analysis: tool sets for natural branch collision analysis 
- gpapproach: GA tool sets for optimizing DSB attack hit rate
- rev-eng: tool sets for reverse-engineering branch predictor units


### A few quick tips
Triggering transient execution for attacks often requires matching patterns.  Depends on the side/covert-channel in your exploits, some attack effects could be 'delicate' that, sometimes, the 'cleaner' environment (e.g., fixed CPU freq., iso-ed cores, etc.) the better attack rates.  

Please find readme in every subdirectory and grasp the idea before 'attacking' (your own machines).  Although all the PoCs and the standalone demos are tested, they are better to be used as examples to facilitate your understanding. A working attack may require your own modification in code, alignment, or even kernel. 

Also, feel free to reach me out if you need help with the repo or find any problems here and have fun~