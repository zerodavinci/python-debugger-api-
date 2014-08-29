#!/usr/bin/python
# -*- coding: utf-8 -*-
#注入成功後
import mydebug
from ctypes import *
from ptrace_arg import *
import os
import sys

pattern = "90 90 90 4d 87 ff 49 bf"
""" hook dynamic library """
h = mydebug.debug()
pid = int(sys.argv[1])


hookfunc = h.find_hook_point(pid,"libc","puts")
ourfunc = h.find_hook_point(pid,"hitcon","hello")

h.attach(pid)

# 找到注入so後先改寫push 的值
push_addr = h.searchmem(pattern.strip(),"r-xp","hitcon")
for x in push_addr:
	print "[*] change return address at " + hex(x) + "\n"
	return_addr = (c_ulong * 1)()
	return_addr[0] = hookfunc
	h.writemem(x + 8, return_addr, sizeof(return_addr))

print "[*] our inject so is at " + hex(ourfunc)

opcode = [hex(hookfunc)[i:i+2] for i in range(2, len(str(hookfunc)), 2)]
opcode = opcode[:-1] # 去掉空白
opcode = opcode[::-1] # little endian
word = ""
for token in opcode:
	word = word + token + " "
print "[*] search opcode " + word

got_table = h.searchmem(word.strip(),"rw-p","out")
got_table = got_table + h.searchmem(word.strip(),"r--p","out")

our_addr_array = c_ulong * 1
our_addr = our_addr_array()
our_addr[0] = ourfunc

for got_addr in got_table:
	print "[*] rewrite got_table " + hex(got_addr)
	h.writemem(got_addr, our_addr, sizeof(our_addr))
h.detach()
