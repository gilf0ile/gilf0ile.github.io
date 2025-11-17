---
title: x86 Assembly File Handling Programs
tags: [assembly, x86, linux, syscalls, file operations]
style: border
color: info
description: A collection of x86 assembly programs demonstrating various file handling operations including create, open, read, write, delete, and more using Linux syscalls.
---

## Overview

This post showcases a series of **x86 assembly language programs** that demonstrate fundamental file handling operations in Linux. These programs interact directly with the kernel through system calls, providing a low-level understanding of file I/O operations.

**Repository**: [file-handling](https://github.com/gilf0ile/pwn/tree/master/x86-Assembly/file-handling)

All programs are written in NASM (Netwide Assembler) syntax and utilize Linux system calls for file operations.

## Programs Included

The collection includes the following file handling operations:

1. **create.asm** - Create a new file
2. **open.asm** - Open an existing file
3. **read.asm** - Read data from a file
4. **write.asm** - Write data to a file
5. **close.asm** - Close a file descriptor
6. **delete.asm** - Delete/unlink a file
7. **sleek.asm** - Seek to a position in a file
8. **time.asm** - File timestamp operations

## Linux System Calls for File Operations

Before diving into the programs, let's understand the key system calls used:

| Syscall | Number (x86) | Purpose |
|---------|--------------|---------|
| `sys_open` | 5 | Open a file |
| `sys_read` | 3 | Read from file descriptor |
| `sys_write` | 4 | Write to file descriptor |
| `sys_close` | 6 | Close file descriptor |
| `sys_creat` | 8 | Create a file |
| `sys_unlink` | 10 | Delete a file |
| `sys_lseek` | 19 | Reposition file offset |
| `sys_exit` | 1 | Exit program |

## Program Deep Dive

### 1. Creating a File (create.asm)

Creating a file in x86 assembly involves using the `sys_creat` system call:

```nasm

	; PROGRAM TO CREATE A FILE	

section .rodata
	filename: db "readme.txt", 0
	
section .text
	global main
	main:
		push ebp
		mov ebp, esp

		mov eax, 8
		mov ebx, filename
		mov ecx, 0777
		int 0x80

	leave
	ret
```

**Key Points:**
- File permissions are specified in octal (0777 = rwxrwxrwx - full permissions for all)
- Returns file descriptor on success, -1 on error
- The program creates a file named "readme.txt" with full read/write/execute permissions
- Uses `main` function instead of `_start` for easier linking with C runtime

### 2. Opening a File (open.asm)

This program demonstrates creating a file, writing content, and then opening it for reading:

```nasm

	; PROGRAM TO OPEN A FILE

section .rodata
	filename: db "readme.txt", 0
	contents: db "Hello World!", 0
	
section .text
	global main
	main:
		push ebp
		mov ebp, esp

		mov eax, 8
		mov ebx, filename
		mov ecx, 0777
		int 0x80
		
		mov ebx, eax
		mov ecx, contents
		mov edx, 12
		mov eax, 4
		int 0x80

		mov eax, 5
		mov ebx, filename
		mov ecx, 0
		int 0x80

	leave
	ret
```

**Program Flow:**
1. Creates "readme.txt" with `sys_creat` (syscall 8)
2. Writes "Hello World!" (12 bytes) to the file using the returned file descriptor
3. Opens the file with `sys_open` in read-only mode (flag 0)

**Common Flags:**
- `O_RDONLY` (0) - Read only
- `O_WRONLY` (1) - Write only
- `O_RDWR` (2) - Read and write
- `O_CREAT` (64) - Create if doesn't exist
- `O_APPEND` (1024) - Append mode

### 3. Reading from a File (read.asm)

Complete file operation: create, write, open, read, and display using `printf`:

```nasm

	; PROGRAM TO READ FROM A FILE

extern printf

section .rodata
	filename: db "readme.txt", 0
	contents: db "Hello World!", 0
	format: db "%s", 0	

section .bss
	store resb 255,	

section .text
	global main
	main:
		push ebp
		mov ebp, esp

		mov eax, 8
		mov ebx, filename
		mov ecx, 0777
		int 0x80
		
		mov ebx, eax
		mov ecx, contents
		mov edx, 12
		mov eax, 4
		int 0x80

		mov eax, 5
		mov ebx, filename
		mov ecx, 0
		int 0x80

		mov ebx, eax
		mov ecx, store
		mov edx, 12
		mov eax, 3
		int 0x80
	
		sub esp, 0x10
		mov eax, store
		push eax
		push format
		call printf
		add esp, 0x10

	leave
	ret
```

**Program Flow:**
1. Creates "readme.txt" file
2. Writes "Hello World!" to the file
3. Opens the file for reading
4. Reads 12 bytes from the file into `store` buffer (in .bss section)
5. Uses external C `printf` function to display the contents
6. Requires linking with C library: `gcc -m32 read.asm -o read`

**Key Features:**
- Uses `.bss` section for uninitialized buffer (255 bytes reserved)
- Demonstrates interoperability with C standard library
- Shows proper stack management for function calls

### 4. Writing to a File (write.asm)

Creating a file and writing content - simplified version focusing on the write operation:

```nasm

	; PROGRAM TO WRITE INTO A FILE WITH SOME CONTENT

section .rodata
	filename: db "readme.txt", 0
	contents: db "Hello World!", 0
	
section .text
	global main
	main:
		push ebp
		mov ebp, esp

		mov eax, 8
		mov ebx, filename
		mov ecx, 0777
		int 0x80
		
		mov ebx, eax
		mov ecx, contents
		mov edx, 12
		mov eax, 4
		int 0x80

	leave
	ret
```

**Program Flow:**
1. Creates "readme.txt" using `sys_creat` (syscall 8)
2. The returned file descriptor is stored in EBX
3. Writes the contents "Hello World!" (12 bytes) using `sys_write` (syscall 4)
4. File descriptor is automatically available for writing immediately after creation

### 5. Closing a File (close.asm)

Complete example demonstrating the full lifecycle including proper file descriptor closing:

```nasm

	; PROGRAM TO CLOSE THE ALREADY OPENED FILE WHICH WE OPENED DURING THE PREVIOUS PROGRAM

extern printf

section .rodata
	filename: db "readme.txt", 0
	contents: db "Hello World!", 0
	format: db "%s", 0	

section .bss
	store resb 255,	

section .text
	global main
	main:
		push ebp
		mov ebp, esp

		mov eax, 8
		mov ebx, filename
		mov ecx, 0777
		int 0x80
		
		mov ebx, eax
		mov ecx, contents
		mov edx, 12
		mov eax, 4
		int 0x80

		mov eax, 5
		mov ebx, filename
		mov ecx, 0
		int 0x80

		mov ebx, eax
		mov ecx, store
		mov edx, 12
		mov eax, 3
		int 0x80
	
		sub esp, 0x10
		mov eax, store
		push eax
		push format
		call printf
		add esp, 0x10

		mov ebx, eax		; AS FILE DESCRIPTOR IS ALREADY SAVED IN EBX
		mov eax, 6
		int 0x80

	leave
	ret
```

**Program Flow:**
1. Creates and writes to "readme.txt"
2. Opens the file for reading
3. Reads the contents into a buffer
4. Prints the contents using C `printf`
5. **Closes the file descriptor** using `sys_close` (syscall 6)
6. The file descriptor saved in EBX is used for closing

**Important Note:**
- Always close file descriptors to prevent resource leaks
- The kernel has a limit on open file descriptors per process
- Closing returns 0 on success, -1 on error

### 6. Deleting a File (delete.asm)

Remove a file from the filesystem using `sys_unlink`:

```nasm

	; PROGRAM TO DELETE A FILE

section .rodata
	filename: db "readme.txt", 0

section .text
	global main
	main:
		push ebp
		mov ebp, esp

		mov ebx, filename
		mov eax, 10
		int 0x80

	leave 
	ret
```

**Program Details:**
- Uses `sys_unlink` (syscall 10) to delete the file
- File must not be open when deleted (or will be deleted after last file descriptor closes)
- Returns 0 on success, -1 if file doesn't exist or permission denied
- Very simple implementation - just filename and syscall

### 7. File Seeking (sleek.asm)

Advanced file operation: seek to end of file and append new content:

```nasm

	; PROGRAM TO UPDATE THE EXESTING FILE WITH SOME NEW CONTENT

section .rodata
	filename: db "readme.txt", 0
	updated: db "--updated--", 0

section .text
	global main
	main:
		push ebp
		mov ebp, esp

		mov eax, 5
		mov ebx, filename
		mov ecx, 1
		int 0x80
		
		mov ebx, eax
		mov ecx, 0
		mov edx, 2
		mov eax, 19
		int 0x80

		mov ebx, eax
		mov ecx, updated
		mov edx, 11
		mov eax, 4
		int 0x80

	leave
	ret
```

**Program Flow:**
1. Opens "readme.txt" in write-only mode (flag 1)
2. Uses `sys_lseek` (syscall 19) to seek to the end of file
   - Offset: 0 (no additional offset from the reference point)
   - Whence: 2 (SEEK_END - end of file)
3. Writes "--updated--" (11 bytes) at the end of the file
4. This effectively appends content to the existing file

**Note:** The program assumes "readme.txt" already exists with some content. The lseek positions the file pointer at the end, allowing append operation.

**Seek Whence Values:**
- `SEEK_SET` (0) - Beginning of file
- `SEEK_CUR` (1) - Current position
- `SEEK_END` (2) - End of file (used in this program)

### 8. File Time Operations (time.asm)

Get current system time - Unix timestamp (seconds since January 1, 1970 UTC):

```nasm

	; PROGRAM TO PRINT THE NUMBER OF SECONDS FROM 1ST JANUARY 1970 UTC

extern printf

section .rodata
	format: db "%s", 0
	formatd: db "%d", 0
	msg: db "seconds: ", 0

section .text
	global main
	main:
		push ebp
		mov ebp, esp
		sub esp, 0x8

		push msg
		push format
		call printf
		add esp, 0x8		

		xor eax, eax
		mov eax, 13
		int 0x80

		sub esp, 0x8
		push eax
		push formatd
		call printf
		
	leave 
	ret
```

**Program Details:**
- Uses `sys_time` (syscall 13) to get current Unix timestamp
- Returns the number of seconds since the Unix epoch (Jan 1, 1970 00:00:00 UTC)
- Prints a message "seconds: " followed by the timestamp value
- Uses C `printf` with two format strings:
  - `%s` for the message string
  - `%d` for the decimal integer (timestamp)
- Requires linking with C library: `gcc -m32 time.asm -o time`

**Note:** This isn't specifically a file timestamp operation, but demonstrates getting system time which is often used for file operations, logging, or timestamping events.

## Building and Running

### Assembly and Linking

There are two linking methods depending on whether the program uses C library functions:

**For pure assembly programs** (create.asm, delete.asm, write.asm):
```bash
# Assemble
nasm -f elf32 program.asm -o program.o

# Link with ld
ld -m elf_i386 program.o -o program

# Run
./program
```

**For programs using C library** (read.asm, close.asm, time.asm, open.asm):
```bash
# Assemble
nasm -f elf32 program.asm -o program.o

# Link with gcc (includes C runtime and libc)
gcc -m32 program.o -o program
# OR compile directly
gcc -m32 program.asm -o program

# Run
./program
```

**Note:** Programs that use `extern printf` require the C library and must be linked with `gcc`.

### Using a Makefile

Create a `Makefile` for easier compilation:

```makefile
AS = nasm
LD = ld
CC = gcc
ASFLAGS = -f elf32
LDFLAGS = -m elf_i386
CCFLAGS = -m32

# Programs that need C library
C_PROGRAMS = read open close time
# Pure assembly programs
ASM_PROGRAMS = create write delete sleek

SOURCES = $(wildcard *.asm)
OBJECTS = $(SOURCES:.asm=.o)
ALL_PROGRAMS = $(C_PROGRAMS) $(ASM_PROGRAMS)

all: $(ALL_PROGRAMS)

# Link C library programs with gcc
$(C_PROGRAMS): %: %.o
	$(CC) $(CCFLAGS) $< -o $@

# Link pure assembly programs with ld
$(ASM_PROGRAMS): %: %.o
	$(LD) $(LDFLAGS) $< -o $@

%.o: %.asm
	$(AS) $(ASFLAGS) $< -o $@

clean:
	rm -f $(OBJECTS) $(ALL_PROGRAMS)

.PHONY: all clean
```

Then simply run:
```bash
make              # Build all programs
make clean        # Clean up
./create          # Run individual program
```

## Error Handling

System calls return negative values on error. Here's a robust error checking pattern:

```nasm
    ; After a syscall
    test eax, eax       ; Check if result is negative
    js handle_error     ; Jump if sign flag is set (negative)
    
    ; Success path
    ; ...
    jmp continue
    
handle_error:
    ; eax contains -errno
    neg eax             ; Convert to positive errno
    ; Handle specific error codes
    cmp eax, 2          ; ENOENT (No such file)
    je file_not_found
    cmp eax, 13         ; EACCES (Permission denied)
    je permission_denied
    ; etc...
    
continue:
    ; Rest of program
```

## Common Error Codes

| Error Code | Name | Description |
|------------|------|-------------|
| 2 | ENOENT | No such file or directory |
| 9 | EBADF | Bad file descriptor |
| 13 | EACCES | Permission denied |
| 17 | EEXIST | File exists |
| 21 | EISDIR | Is a directory |
| 28 | ENOSPC | No space left on device |

## Registers and System Call Convention

In 32-bit x86 Linux:
- **EAX**: System call number, also returns result
- **EBX**: First argument
- **ECX**: Second argument
- **EDX**: Third argument
- **ESI**: Fourth argument
- **EDI**: Fifth argument
- **EBP**: Sixth argument

The system call is invoked with `int 0x80`.

## Key Takeaways

1. **Direct Kernel Interface**: Assembly provides direct access to kernel system calls without library overhead
2. **Manual Resource Management**: File descriptors must be explicitly managed and closed
3. **Error Handling**: Always check return values for error conditions
4. **Permissions Matter**: File creation requires proper permission bits (mode)
5. **Buffer Management**: Memory for read/write operations must be explicitly allocated
6. **Efficiency**: Assembly code is extremely efficient but requires careful attention to detail

## Practical Applications

These low-level file operations are foundational for:
- **Binary Exploitation**: Understanding how programs interact with files at the syscall level
- **Malware Analysis**: Recognizing file operation patterns in disassembled code
- **Performance Optimization**: Writing highly optimized file I/O routines
- **System Programming**: Building system utilities and tools
- **Operating System Development**: Understanding kernel interfaces

## Debugging Tips

### Using `strace`

Monitor system calls in real-time:
```bash
strace ./program
```

This shows all system calls, their arguments, and return values.

### Using GDB

Debug assembly programs:
```bash
gdb ./program
(gdb) break main     # These programs use main, not _start
(gdb) run
(gdb) stepi          # Step one instruction
(gdb) info registers # View all registers
(gdb) x/s $ebx       # Examine string at ebx
(gdb) x/12c $ecx     # Examine 12 characters at ecx
```

## Resources

- [Linux System Call Table](https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md)
- [NASM Documentation](https://www.nasm.us/xdoc/2.15.05/html/nasmdoc0.html)
- [x86 Assembly Guide](https://www.cs.virginia.edu/~evans/cs216/guides/x86.html)
- [Linux System Call Reference](https://man7.org/linux/man-pages/man2/syscalls.2.html)

## Conclusion

Understanding file handling in x86 assembly provides invaluable insight into how programs interact with the operating system at the lowest level. These programs demonstrate the fundamental building blocks that higher-level languages abstract away. 

Whether you're interested in reverse engineering, exploit development, or simply want to understand how computers work at a fundamental level, mastering assembly language file operations is an essential skill.

Feel free to explore the [complete source code](https://github.com/gilf0ile/pwn/tree/master/x86-Assembly/file-handling) and experiment with these programs. Try modifying them, combining operations, or adding new functionality to deepen your understanding!

---

**Date**: September 19, 2021  
**Tags**: #assembly #x86 #linux #syscalls #file-operations #low-level-programming
