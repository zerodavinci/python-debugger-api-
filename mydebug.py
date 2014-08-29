#!/usr/bin/env python
# -*- coding: utf-8 -*-
from ptrace_arg import *
from ctypes import *

class debug():

	def __init__(self):
		self.libc = CDLL("libc.so.6") 
		self.libdl= CDLL("libdl.so.2") # dlopen dlsym
		self.ptrace = self.libc.ptrace
		self.getpid = self.libc.getpid
		self.wait = self.libc.wait

		self.status = 0
		self.bp_data = c_ulong() 
		self.regs = user_regs_struct()

		self.is_attached = False
		self.trace_pid = 0

		self.dlopen = self.libdl.dlopen  
		self.dlsym = self.libdl.dlsym
		""" restype 很重要比較要搞懂每個function return type """
		self.ptrace.restype = c_ulong
		self.dlopen.restype = c_ulong
		self.dlsym.restype = c_ulong  # very important 設定return type

	def attach(self,pid):
		state = self.ptrace(PTRACE_ATTACH, pid, None, None)
		if state != 0:
			print "attach error"
			exit(-1)
		self.is_attached = True
		self.trace_pid = pid

	def detach(self):
		self.ptrace(PTRACE_DETACH, self.trace_pid, None, None)

	def wait(self):
		if self.is_attached:
			self.wait(None) # wait(NULL)

	def cont(self):
		self.ptrace(PTRACE_CONT, self.trace_pid, None, None)

	""" 讀寫memory有問題就馬上退出 """
	def peekdata(self,addr):
		data = c_ulong()
		if self.is_attached:
			data = c_ulong(self.ptrace(PTRACE_PEEKDATA, self.trace_pid, c_void_p(addr), None))
			if data.value == -1:
				print "read process memory error"
				self.detach()
				exit(-1)
			return data

	""" 丟進來的都是ctypes 型態 """
	def poketext(self,addr,data):
		if self.is_attached:
			status = self.ptrace(PTRACE_POKETEXT, self.trace_pid, c_void_p(addr), c_void_p(data))
		if status != 0:
			print "write process memory error"
			self.detach()
			exit(-1)
	
	""" 下斷點功能我覺得沒啥用 """
	def bpset(self,addr):
		backup_data = self.peekdata(addr)
		self.bp_data.value = backup_data.value  
		backup_data.value = (backup_data.value & 0xFFFFFFFFFFFFFF00) | 0xCC
		self.poketext(addr, backup_data.value)


	def bpclear(self,addr):
		""" 要記得修改rip的值 - 1 回到未下斷點前 """
		self.getregs(self.regs) 
		self.poketext(addr, self.bp_data.value)
		self.regs.rip = self.regs.rip - 1
		self.setregs(self.regs)

	def getregs(self,regs):
		self.ptrace(PTRACE_GETREGS,self.trace_pid,None,byref(regs))


	def setregs(self,regs):
		self.ptrace(PTRACE_SETREGS,self.trace_pid,None,byref(regs))

		
	""" read from /dev/pid/mem 
	    要先attach才能有辦法讀,end_address 不能讀,會error 
	"""
	def searchmem(self,opcode,attr = "r-xp",segment = ""):
		# opcode format 11,22,33,ff,44 用空白隔開直接從objdump copy貼上
		opcode_list = opcode.split(" ")
		print opcode_list
		memory = open("/proc/"+str(self.trace_pid)+"/mem","r", 0) # 0(zero) means no buffering
		maps = open("/proc/"+str(self.trace_pid)+"/maps","r")
		start_address = 0
		end_address = 0
		flag = 0 # check 是否都比對成功
		code = ""
		found_address = []
		for line in maps:
			tokens = line.strip().split(" ")
			if attr in tokens[1] and segment in tokens[-1]: # we only interested in executive seg r-xp

					start_address = tokens[0].split("-")[0]
					end_address =  tokens[0].split("-")[1]
					print "search between " + start_address + " and " + end_address

					start_address = int(start_address,16) # no prefix 0x
					end_address = int(end_address,16)
					if start_address > 0x7fffffffffffffff:
						break
					memory.seek(start_address) # may be overflow because -0x8000000000000000 to 0x7fffffffffffffff (c long type)
					while start_address != end_address:
						base_address = start_address
						code = memory.read(1) # 會一直前進,不須重新seek
						start_address = start_address + 1 
						for pattern in opcode_list: 
							if pattern != format(ord(code),'02x'): # hex string without prefix 0x
								flag = 0
								break
							if memory.tell() != end_address:
							 	flag = flag + 1 # 比對到一個
							 	code = memory.read(1) # 相同才會繼續讀
								start_address = start_address + 1 

						if flag == len(opcode_list):
							print "[*] found at " + hex(base_address)
							found_address.append(base_address)
							flag = 0
		memory.close()
		maps.close()
		return found_address



	""" 丟近來的data都是ctype array 的型態
		data = (c_ulong * 10)
		只寫入一個word 也要 c_ulong * 1
	"""
	# writemem(addr,data,sizeof(data))
	def writemem(self, addr, data, size):
		count = size / sizeof(c_ulong)
		if (size % sizeof(c_ulong)) != 0:
			count = count + 1

		for i in range(0,len(data)):
			self.poketext(addr,data[i])
			addr = addr + sizeof(c_ulong)

	def readmem(self,addr,size):
		count = size / sizeof(c_ulong)
		if (size % sizeof(c_ulong)) != 0:
			count = count + 1
		array = c_ulong * count
		data = array() # 這樣就可以index data

		for i in range(0,len(data)):
			data[i] = self.peekdata(addr)
			addr = addr + sizeof(c_ulong)

		return data
	
	""" find target library path and start_address """
	def find_hook_start(self,pid,libname,attr):
		maps = open("/proc/"+str(pid)+"/maps","r")
		start_address = ""
		end_address = ""
		libpath = ""
		for line in maps:
			if libname in line.strip():
				tokens = line.strip().split(" ")
				if attr in tokens[1]: # r-xp p -> private
					start_address = tokens[0].split("-")[0]
					end_address = tokens[0].split("-")[1]
					libpath = tokens[-1]
					break
		maps.close()
		""" 不知為啥空字串也能用dlopen開"""
		if (start_address == "") or (libpath == ""):
		  start_address = "error"
		  libpath = "error"
		return start_address,libpath

	def find_hook_point(self,pid,libname,funcname):
		remote_start,libpath = self.find_hook_start(pid,libname,"r-xp")

		print "[*] get remote start addr " + remote_start
		print "[*] get remote libpath " + libpath
		my_pid = self.getpid()
		print "my pid is " + str(my_pid)
		
		my_handle = self.dlopen(libpath,RTLD_NOW)
		if my_handle == 0:
			print "dlopen error\n"
			return -1
		
		funcaddr = self.dlsym(c_void_p(my_handle), c_char_p(funcname))
		if funcaddr == 0:
			print "dlsym error\n"
			return -1
		""" load so before search """

		my_start, mylibpath = self.find_hook_start(my_pid,libname,"r-xp")
		print "my_start " + my_start
		print "mylibpath " + mylibpath

		offset =  int(funcaddr) - int(my_start,16)
		print "[*] get offset " + hex(offset)

		hook_point = int(remote_start,16) + offset 
		print "[*] target function " + funcname
		print "[*] hook point " + hex(hook_point)

		return hook_point


	""" 對target call 任意funcname 
	How x64 pass args : rdi rsi rdx rcx r8 r9 ...
	libpath 和 funcname 是為了呼叫目標的dlopen來載入我們的lib
	"""
	def inject(self,injectso):
		libpath = "libc-2.1"
		funcname = "__libc_dlopen_mode"
		backup_regs = user_regs_struct()

		self.getregs(self.regs) 
		self.getregs(backup_regs) # backup register

		backup_stack = self.readmem(self.regs.rsp,2048) # backup stack

		call_lib_addr = self.find_hook_point(self.trace_pid, libpath, funcname)

		strings = injectso
		count =(len(strings) + 1) / sizeof(c_ulong)
		if (count % sizeof(c_ulong)) != 0:
			count = count + 1

		array = c_char * (len(strings) ) # null 
		arg1_temp = array()
		arg1_temp.value = strings
		arg1_temp = cast(arg1_temp, POINTER(c_ulong))

		arg1 = (c_ulong * count)()
		for i in range(0,count):
			arg1[i] = arg1_temp[i]
		
		# 故意引發trap 
		ret_addr_array = c_ulong * 1
		ret_addr = ret_addr_array()
		ret_addr[0] = 0x0 # invalid return address

		self.writemem(self.regs.rsp, ret_addr, sizeof(ret_addr)) # fake return address
		self.writemem(self.regs.rsp + 1024, arg1, sizeof(arg1))  
			
		self.regs.rax = 0 # like gdb call function
		self.regs.rbp = self.regs.rsp
		self.regs.rdi = self.regs.rsp + 1024 # where inject so
		self.regs.rsi = RTLD_NOW|RTLD_GLOBAL|RTLD_NODELETE
		
		self.regs.rip = call_lib_addr 

		# should be restore
		self.setregs(self.regs)
		print "we'll execute at " + hex(self.regs.rip)
		
		self.cont()
		self.wait()
		print "control again.....because of 0x0 return address"

		self.setregs(backup_regs)
		self.writemem(backup_regs.rsp,backup_stack,sizeof(backup_stack))

		self.detach()

	def dumpregs(self):
		self.getregs(self.regs) 
		print "rax\t" + hex(self.regs.rax)
		print "rbx\t" + hex(self.regs.rbx)
		print "rcx\t" + hex(self.regs.rcx)
		print "rdx\t" + hex(self.regs.rdx)
		print "rsi\t" + hex(self.regs.rsi)
		print "rdi\t" + hex(self.regs.rdi)
		print "rbp\t" + hex(self.regs.rbp)
		print "rsp\t" + hex(self.regs.rsp)
		print "r8\t"  + hex(self.regs.r8)
		print "r9\t"  + hex(self.regs.r9)
		print "r10\t" + hex(self.regs.r10)
		print "r11\t" + hex(self.regs.r11)
		print "r12\t" + hex(self.regs.r12)
		print "r13\t" + hex(self.regs.r13)
		print "r14\t" + hex(self.regs.r14)
		print "r15\t" + hex(self.regs.r15)
		print "rip\t" + hex(self.regs.rip)
		print "eflags\t" + hex(self.regs.eflags)
		print "cs\t" +  hex(self.regs.cs)
		print "ss\t" +  hex(self.regs.ss)
		print "ds\t" +  hex(self.regs.ds)
		print "es\t" +  hex(self.regs.es)
		print "fs\t" +  hex(self.regs.fs)
		print "gs\t" +  hex(self.regs.gs)
