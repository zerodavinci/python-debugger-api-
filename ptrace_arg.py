#!/usr/bin/python
from ctypes import *

PTRACE_TRACEME = 0  
PTRACE_PEEKTEXT = 1  
PTRACE_PEEKDATA = 2  
PTRACE_PEEKUSER = 3  
PTRACE_POKETEXT = 4  
PTRACE_POKEDATA = 5  
PTRACE_POKEUSER = 6  
PTRACE_CONT = 7  
PTRACE_GETREGS = 12  
PTRACE_SETREGS = 13  

PTRACE_ATTACH = 16  
PTRACE_DETACH = 17 


RTLD_LAZY = 0x00001         # Lazy function call binding.  
RTLD_NOW = 0x00002          # Immediate function call binding.  
RTLD_BINDING_MASK = 0x3     # Mask of binding time value.  
RTLD_NOLOAD =  0x00004      # Do not load the object.  
RTLD_DEEPBIND =  0x00008    # Use deep binding.  
RTLD_GLOBAL = 0x00100
RTLD_NODELETE = 0x01000

class user_regs_struct(Structure):
        _fields_ = [
            ("r15", c_ulong),
            ("r14", c_ulong),
            ("r13", c_ulong),
            ("r12", c_ulong),
            ("rbp", c_ulong),
            ("rbx", c_ulong),
            ("r11", c_ulong),
            ("r10", c_ulong),
            ("r9", c_ulong),
            ("r8", c_ulong),
            ("rax", c_ulong),
            ("rcx", c_ulong),
            ("rdx", c_ulong),
            ("rsi", c_ulong),
            ("rdi", c_ulong),
            ("orig_rax", c_ulong),
            ("rip", c_ulong),
            ("cs", c_ulong),
            ("eflags", c_ulong),
            ("rsp", c_ulong),
            ("ss", c_ulong),
            ("fs_base", c_ulong),
            ("gs_base", c_ulong),
            ("ds", c_ulong),
            ("es", c_ulong),
            ("fs", c_ulong),
            ("gs", c_ulong)
            ]
