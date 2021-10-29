#!/usr/bin/env python

import subprocess
import os
import argparse
import sys
import shutil


dir_path = os.path.dirname(os.path.realpath(__file__))


opt = argparse.ArgumentParser(description = "Analyse a program to extract source code level invariants")
opt.add_argument('--output', action = 'store', help="Output directory for all the files (LLVMDAIKON_OUTPUT_PATH)")
opt.add_argument('--project', action = 'store', help="Path to the project that must be compiled and analysed")
opt.add_argument('--corpus', action = 'store', help = "Path to the produced corpus that will be used for learning")
opt.add_argument('--configure', nargs='*', help="Command line to configure the project to analyse (Recommended to use with quotes)")
opt.add_argument('--compile', nargs='*', help="Command line to compile the project to analyse (Recommented to use with quotes)")
opt.add_argument('--harness', nargs='*', help="Command line to generate an harness")
opt.add_argument('--dumper', nargs='*', help = "Command line to run the dumper program (with its args)")
args = opt.parse_args()

cmd_exists = lambda x: any((os.access(os.path.join(path, x), os.X_OK) and os.path.isfile(os.path.join(path, x))) for path in os.environ["PATH"].split(os.pathsep))

def check_deps(clang, clang_pp, java):  
  return (cmd_exists(clang) and cmd_exists(clang_pp) and cmd_exists(java))
  

def compile(project_path, configure_cmd, compile_cmd, harness_cmd, llvmdaikon_output_path):

  output_log = open(os.path.join(llvmdaikon_output_path, 'log.out'), 'w')
  error_log = open(os.path.join(llvmdaikon_output_path, 'log.err'), 'w')
  #p = subprocess.Popen(cmdline, stdout = output_log , stderr = error_log, cwd = project_path)
  print("Configure {0} with {1}".format(project_path, configure_cmd))
  conf = subprocess.Popen(configure_cmd, stdout = output_log, stderr = error_log, cwd = project_path)
  conf.wait()
  print("Compiling {0} with {1}".format(project_path, compile_cmd))
  comp = subprocess.Popen(compile_cmd, stdout = output_log, stderr = error_log, cwd = project_path)
  comp.wait()
  if harness_cmd != '':
    print("Generating harness {0} with {1}".format(project_path, harness_cmd))
    print(''.join(el + " " for el in harness_cmd))
    harness = subprocess.Popen(harness_cmd, stdout = output_log, stderr = error_log, cwd = project_path)
    harness.wait()

  output_log.close()
  error_log.close()
  #sys.exit()


def reconstruct_dump_and_dwarf(llvmdaikon_output_path):
  output_log = open(os.path.join(llvmdaikon_output_path, 'log.out'), 'w')
  error_log = open(os.path.join(llvmdaikon_output_path, 'log.err'), 'w')
  reconstruct_script = os.path.join(dir_path, 'reconstruct-dump')
  reconstruct_dwarf = os.path.join(dir_path, 'reconstruct-dwarf')
  print("Reconstructing dump")
  p = subprocess.Popen(reconstruct_script, stdout = output_log, stderr = error_log)
  p.wait()
  print("Reconstructing dwarf")
  p = subprocess.Popen(reconstruct_dwarf, stdout = output_log, stderr = error_log)
  p.wait()
  output_log.close()
  error_log.close()


def learn_invariants(llvmdaikon_output_path, corpus, dumper_cmd):
  output_log = open(os.path.join(llvmdaikon_output_path, 'log.out'), 'w')
  error_log = open(os.path.join(llvmdaikon_output_path, 'log.err'), 'w')
  learn_invariants = [os.path.join(dir_path, 'learn-invariants'), corpus] + dumper_cmd.split(' ')
  print(learn_invariants)
  print("Learning Invariants")
  p = subprocess.Popen(learn_invariants, stdout = output_log, stderr = error_log)
  #p = subprocess.Popen(learn_invariants)
  p.wait()
  output_log.close()
  error_log.close()



def generate_json_annotations(llvmdaikon_output_path):
  output_log = open(os.path.join(llvmdaikon_output_path, 'log.out'), 'w')
  error_log = open(os.path.join(llvmdaikon_output_path, 'log.err'), 'w')
  generate_constraints = os.path.join(dir_path, 'generate-constraints')
  mapper = os.path.join(dir_path, 'map_llvm_to_src')
  print("Generating constraints")
  p = subprocess.Popen(generate_constraints, stdout = output_log, stderr = error_log)
  p.wait()
  print("Reconstructing dwarf")
  p = subprocess.Popen(mapper, stdout = output_log, stderr = error_log)
  p.wait()
  output_log.close()
  error_log.close()


def replace_env_command(cmd, cc, cxx, cflags, cxxflags):

  res = []

  string_cmd = cmd[0]
  string_cmd = string_cmd.replace('CFLAGS', cflags).replace('CC', cc)
  string_cmd = string_cmd.replace('CXXFLAGS', cxxflags).replace('CXX', cxx)
  #res.append(string_cmd)
  return string_cmd
      
      
 
  
def main():
  cc = os.path.join(dir_path, 'dump-cc')
  cxx = os.path.join(dir_path, 'dump-c++')
  cflags = '-g -O0 -fno-discard-value-names -fno-inline -fno-unroll-loops'
  cxxflags = '-g -O0 -fno-discard-value-names -fno-inline -fno-unroll-loops'
  llvmdaikon_output_path = args.output
  llvmdaikon_cc = '/usr/bin/clang-10'
  llvmdaikon_cxx = '/usr/bin/clang++-10'
  if not check_deps(llvmdaikon_cc, llvmdaikon_cxx, 'java'):
    print("You need to install clang-10/++ and java")
    return
  project_path = args.project
  configure_cmd = args.configure[0]
  compile_cmd = args.compile[0]
  corpus = args.corpus
  dumper_cmd = args.dumper[0]
  harness_cmd = args.harness

  harness_cmd = replace_env_command(harness_cmd, cc, cxx, cflags, cxxflags)
  assert(os.path.isdir(llvmdaikon_output_path))
  assert(os.path.isdir(project_path))
  assert(compile_cmd != '')
  #print(harness_cmd)
  #sys.exit()
  os.environ['CC'] = cc
  os.environ['CXX'] = cxx
  os.environ['CFLAGS'] = cflags
  os.environ['CXXFLAGS'] = cxxflags
  os.environ['LLVMDAIKON_OUTPUT_PATH'] = llvmdaikon_output_path
  os.environ['LLVMDAIKON_CC'] = llvmdaikon_cc
  os.environ['LLVMDAIKON_CXX'] = llvmdaikon_cxx

  compile(project_path, configure_cmd.split(' '), compile_cmd.split(' '), harness_cmd.split(' '), llvmdaikon_output_path)
  reconstruct_dump_and_dwarf(llvmdaikon_output_path)
  learn_invariants(llvmdaikon_output_path, corpus, dumper_cmd)
  generate_json_annotations(llvmdaikon_output_path)


if __name__ == '__main__':
  main()
