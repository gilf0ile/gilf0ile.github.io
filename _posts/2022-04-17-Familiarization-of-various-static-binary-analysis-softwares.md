---
title: Getting to know about various static binary analysis softwares.
tags: [re, pwn, binary analysis]
style: border
color: success
description: This blog post gives you a glance of various static binary analysis softwares like radare2, retdec, and IDA Pro using basic scripts.
---
- Static binary analysis examines the input file the same way attackers look at them by creating a detailed model of the file data and control path. The static analysis provides us the freedom to understand the various properties of the binary, its program flow, control flow, and the behaviors of the code without being executed. Static analysis can be carried out on source code, intermediate representations (IR), binary code, or assembly code. Static analysis is often used by security researchers to find vulnerabilities, malware, and many other security purposes. 
- The static analysis software I'm going to use here are radare2, retdec, and IDA Pro. We can run our own scripts using python bindings by importing the static analysis software modules for automation purposes to aid us during reverse engineering or exploitation.
- In this blog post, I want to show a glance at how to import the retdec, r2libr, and Idapython modules and use them to perform some basic operations. I'll update this blog post with scripts that will be useful and relevant for reverse engineering and binary analysis.

## Radare2

[source](https://github.com/radareorg)
- The radare2 project is a set of small command-line utilities to perform static binary analysis for reverse engineering, exploitation, and various security purposes. The primary tool of this whole framework is `radare2`, which features us to understand the binary file completely. Using this radare2 tool, we can view the disassembly, CFG, registers, stack, heap, etc...
- This can be scripted using various programming languages. The languages are python, Ruby, JavaScript, Lua, and Perl.
- `r2libr` is one of the radare2 python bindings.

#### Script to print the no. of basic blocks present in all the functions of a binary

```python
import libr
import ctypes
import argparse

class r2:

    def __init__(self, binary):
        binary = binary.encode("utf-8")
        self._r2c = libr.r_core.r_core_new()
        fh = libr.r_core.r_core_file_open(self._r2c, ctypes.create_string_buffer(binary), 0b101, 0)
        libr.r_core.r_core_bin_load(self._r2c, ctypes.create_string_buffer(binary), (1<<64) - 1)
    
    def cmd(self, cmd):
        r = libr.r_core.r_core_cmd_str(self._r2c, ctypes.create_string_buffer(cmd.encode("utf-8")))
        return ctypes.string_at(r).decode('utf-8')
    
    def __del__(self):
        libr.r_core.r_core_free(self._r2c)
    
if __name__ == "__main__":
    io = argparse.ArgumentParser("Program which prints the number of basic blocks in all the functions using r2libr")
    io.add_argument("binary", help="Input binary")
    args = io.parse_args()

    run = r2(args.binary)

    print('-------------------------------------------------------------------------------------------------')
    print('ANALYZING THE BINARY')
    print('-------------------------------------------------------------------------------------------------')
    run.cmd('aaa')                      # ANALYZING 

    print('-------------------------------------------------------------------------------------------------')
    print('PRINTING THE NUMBER OF BASIC BLOCKS (nbbs) IN EACH FUNCTION')
    print('-------------------------------------------------------------------------------------------------')
    print(run.cmd('afll'))              # PRINITNG THE NO. OF BASIC BLOCKS IN TABULAR FORM
```

#### Output

![alt text](/Images/r2libr-op-1.png "help")
![alt text](/Images/r2libr-op-2.png "Printing no. of basic blocks")

- Here, the `nbbs` is the number of basic blocks present in the function.

## RetDec

[source](https://github.com/s3rvac/retdec-python)
- RetDec is a python library and tool which provide decompilation service.

#### Script to print the decompilation of a particular function or the decompilation of the entire binary.

```python
import subprocess
import sys
import argparse

## CODE TO PARSE ARGUMENTS FROM PYTHON TO COMMAND LINE
parser = argparse.ArgumentParser(description="PRINT DECOMPILATION OF [func_name] FUNCTION USING RETDEC-PYTHON LIBRARY")
parser.add_argument("binary", help="Input binary")
parser.add_argument("func_name", help="Name of the function to be decompiled; Use 'all' if the complete file decompilation is needed.")
args = parser.parse_args()

## USING THE INSTALLED 'RETDEC-DECOMPILER' BINARY, DECOMPILATION IS DONE
if (sys.argv[2] == "all"):
    subprocess.run(["/home/expl0it/tools/retdec-install/bin/retdec-decompiler", sys.argv[1]])
else:
    subprocess.run(["/home/expl0it/tools/retdec-install/bin/retdec-decompiler", "--select-functions", sys.argv[2], sys.argv[1]])

## PRINTING THE CONTENT OF THE GENERATED C FILE WITH DECOMPILATION CODE
decomp_file = sys.argv[1] + '.c'
s = ''
f = open(decomp_file, 'r')
for everyline in f:
    s = s + everyline

print(s)
```
#### Output

![alt text](/Images/retdec-op-1.png "help")
![alt text](/Images/retdec-op-2.png "decompilation of main function")

## IDA Pro [using IDAPython]

[source](https://www.hex-rays.com/products/ida/support/idapython_docs/)
- IDAPython is an IDA plugin by which we can run scripts written in python inside the IDA framework. IDAPython provides complete access to IDA API and any other python module.

#### Script to print the boundaries of a function.

```python
import idc
import idautils

def function_list():
    print("----- The functions available in the binary -----")
    for func in idautils.Functions():
        print("Function address: %s; Function name: %s" % (hex(func), idc.get_func_name(func)))

def func_boundaries(inp_data):
    start_addr = idc.get_name_ea_simple(inp_data)
    func = idaapi.get_func(start_addr)
    end_addr = func.end_ea
    print("function %s start address: 0x%x" % (inp_data, start_addr))
    print("function %s end address: 0x%x" % (inp_data, end_addr))

if __name__ == "__main__":
    function_list()
    inp_data = 'main'       # I want the function boundaries of 'main' 
    func_boundaries(inp_data)
```

#### Output
![alt text](/Images/idapython.png "IDAPython Output for printing function boundaries")
