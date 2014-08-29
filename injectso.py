#!/usr/bin/python
from ctypes import *
from ptrace_arg import *
import mydebug
import sys

pid = int(sys.argv[1])
so = sys.argv[2]

h = mydebug.debug()
h.attach(pid)
h.wait()
h.inject(so)
h.detach()
