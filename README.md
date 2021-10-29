# Daikon LLVM frontend for block invariants

An LLVM frontend for Daikon to generate basic-block level invariants.

### Pre

+ set LLVMDAIKON_OUTPUT_PATH
+ run a fuzzing campaign

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
+ run map_llvm_to_src
+ run insert_annotations path/to/project/src [TO BE FIXED]

## Automation

The script ```analyser.py``` provides an easy way to automate the previous steps. Command line example:

```
./analyser.py --output /tmp/res --project SRC_FOLDER --corpus ./FUZZER_OUTPUT/default/queue/ --configure "./configure --disable-shared" --compile make --dumper "SRC_FOLDER/BINARY @@"
```

It only assumes to running the fuzzing campaign before the actual analysis
