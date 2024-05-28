# Hardware-based Control Flow Enforcement
## Description
A PoC of intel CET protection on a vulnerable program.  
*Running on 5.15.146.1-microsoft-standard-WSL2*

## Setup 
1. Install dependency
```bash
pip install -r requirements.txt
```
2. Pwn!
```bash
./exp.py vuln     # without CET
./exp.py vuln-cet # with CET
```