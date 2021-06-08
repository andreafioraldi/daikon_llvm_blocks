# daikon_llvm_blocks

An LLVM frontend for Daikon to generate basic-block level invariants.

### Pre

+ set LLVMDAIKON_OUTPUT_PATH

### Input

+ It requires a working command line to compile a project

### Output

+ file containing the source-level mapping in json format

## Steps

+ set LLVMDAIKON_OUTPUT_PATH
+ compile with dump-cc/c++
+ run reconstruct_dump
+ run reconstruct_dwarf
+ run learn_invariants with dumper binary
+ run generate_constraints
+ run map_llvm_to_src.py
+ run insert_annotations path/to/project/src [TO BE FIXED]
