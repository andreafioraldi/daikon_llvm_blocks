#!/usr/bin/env python3

import subprocess
import sys
import os

be_quite = os.getenv("LLVMDAIKON_QUIET") is not None

script_dir = os.path.dirname(os.path.realpath(os.path.abspath(__file__)))

is_cxx = "++" in sys.argv[0]

def cc_exec(args):
    if os.getenv("LLVMDAIKON_CC"):
        cc_name = os.environ["LLVMDAIKON_CC"]
    else:
        cc_name = "clang"
    if is_cxx:
        if os.getenv("LLVMDAIKON_CXX"):
            cc_name = os.environ["LLVMDAIKON_CXX"]
        else:
            cc_name = "clang++"
    argv = [cc_name] + args
    if "-O2" in argv:
        argv = [flag if flag != "-O2" else "-O0" for flag in argv]
    #print(" ".join(argv))
    return subprocess.run(argv)


def common_opts():
    return [
      "-g",
      "-O0",
      "-fno-discard-value-names",
      "-fno-inline",
      "-fno-unroll-loops",
    ]

def cc_mode():
    args = common_opts()
    args += sys.argv[1:]

    args += [
      "-Xclang", "-load", "-Xclang", os.path.join(script_dir, "dump_pass.so"),
    ]

    if os.getenv("AFL_USE_ASAN"):
        args += ["-fsanitize=address"]
    if os.getenv("AFL_USE_MSAN"):
        args += ["-fsanitize=memory"]
    if os.getenv("AFL_USE_UBSAN"):
        args += [
                  "-fsanitize=undefined",
                  "-fsanitize-undefined-trap-on-error",
                  "-fno-sanitize-recover=all",
                ]

    return cc_exec(args)

def ld_mode():
    args = common_opts()
    
    args += sys.argv[1:]
    args += [os.path.join(script_dir, "dump_rt.a")]

    args += [
      "-Xclang", "-load", "-Xclang", os.path.join(script_dir, "dump_pass.so"),
    ]
    
    if os.getenv("AFL_USE_ASAN"):
        args += ["-fsanitize=address"]
    if os.getenv("AFL_USE_MSAN"):
        args += ["-fsanitize=memory"]
    if os.getenv("AFL_USE_UBSAN"):
        args += [
                  "-fsanitize=undefined",
                  "-fsanitize-undefined-trap-on-error",
                  "-fno-sanitize-recover=all",
                ]

    
    args += ["-lstdc++", "-ldl"]
    #args += ["-std=c++14"]
    
    return cc_exec(args)

def is_ld_mode():
    return not ("--version" in sys.argv or "--target-help" in sys.argv or
                "-c" in sys.argv or "-E" in sys.argv or "-S" in sys.argv or
                "-shared" in sys.argv)

#if not be_quite:
#    print("\x1b[0;36m" + os.path.basename(sys.argv[0]) + " 1.0a\x1b[0m by <andreafioraldi@gmail.com>")

if len(sys.argv) <= 1:
  cc_exec(sys.argv[1:])
elif is_ld_mode():
    ld_mode()
else:
    cc_mode()
