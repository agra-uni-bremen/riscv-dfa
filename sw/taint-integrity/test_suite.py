#!/usr/bin/python3
import subprocess
import os

#attacks = [-4, -3, 1, 2, 3, 4, 5, 6, -2, -1, 7, 8, 9, 10, 11, 12, 13, 14]
#technique = ["Direct","Direct","Direct","Direct","Direct","Direct","Direct","Direct",
#            "Indirect", "Indirect", "Indirect", "Indirect", "Indirect", "Indirect", "Indirect", "Indirect"]
#location = ["Stack", "Stack", "Stack", "Stack", "Stack", "Stack", "Heap/BSS/Data", "Heap/BSS/Data",
#            "Stack","Stack","Stack","Stack","Stack","Stack", "Heap/BSS/Data", "Heap/BSS/Data", "Heap/BSS/Data", "Heap/BSS/Data", ]
#target = ["Function Pointer (param)", "Longjmp Buffer (param)", "Return address", "Base Pointer", "Function Pointer (local)",
#          "Longjmp Buffer", "Function Pointer", "Longjmp Buffer", "Function Pointer (param)", "Longjmp Buffer (param)",
#          "Return Address", "Base pointer", "Function Pointer (local)", "Longjmp Buffer", "Return Address", "Base pointer",
#          "Function Pointer (local)", "Longjmp Buffer"]

attacks = [(-4, 'Direct', 'Stack', 'Function Pointer (param)'),
           (-3, 'Direct', 'Stack', 'Longjmp Buffer (param)'),
           (1, 'Direct', 'Stack', 'Return address'),
           (2, 'Direct', 'Stack', 'Base Pointer'),
           (3, 'Direct', 'Stack', 'Function Pointer (local)'),
           (4, 'Direct', 'Stack', 'Longjmp Buffer'),
           (5, 'Direct', 'Heap/BSS/Data', 'Function Pointer'),
           (6, 'Direct', 'Heap/BSS/Data', 'Longjmp Buffer'),
           (-2, 'Indirect', 'Stack', 'Function Pointer (param)'),
           (-1, 'Indirect', 'Stack', 'Longjmp Buffer (param)'),
           (7, 'Indirect', 'Stack', 'Return Address'),
           (8, 'Indirect', 'Stack', 'Base pointer'),
           (9, 'Indirect', 'Stack', 'Function Pointer (local)'),
           (10, 'Indirect', 'Stack', 'Longjmp Buffer'),
           (11, 'Indirect', 'Heap/BSS/Data', 'Return Address'),
           (12, 'Indirect', 'Heap/BSS/Data', 'Base pointer'),
           (13, 'Indirect', 'Heap/BSS/Data', 'Function Pointer (local)'),
           (14, 'Indirect', 'Heap/BSS/Data', 'Longjmp Buffer')]

for counter, attack in enumerate(attacks, 1):
    print(str(counter) + ": " + attack[1] + " " + attack[2] + " on " + attack[3], end="\n\t")
    try:
        #os.system("riscv-vp atts --parameter " + str(attack))
        output = subprocess.check_output("riscv-vp atts --parameter " + str(attack[0]) + " 2> /dev/null", shell=True)
        if "ATTACK successful" in str(output):
            print ("Oh no, attack " + str(attack[0]) + " was successful")
            exit (-1)
        else:
            print ("Attack " + str(attack[0]) + " not applicable")
    except subprocess.CalledProcessError as e:
        if "Invalid tainting operation" in str(e.output):
            print ("Attack " + str(attack[0]) + " prevented")
            pass
        else:
            print ("Attack " + str(attack[0]) + " error")
            print (e.output)

