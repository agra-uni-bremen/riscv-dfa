#!/usr/bin/python3
import subprocess
import os

attacks = ['Success',
           'Fail',
           'Fail',
           'Fail',
           'Fail']

for counter, attack in enumerate(attacks, 0):
    print(str(counter) + ":")
    try:
        print ("riscv-dfa main --parameter " + str(counter) + " 2>&1")
        output = subprocess.check_output("riscv-dfa main --parameter " + str(counter) + " 2>&1", shell=True)
        if "Invalid tainting operation" in str(output):
            if attack == 'Success':
                print ("Test failed")
                os.exit(-1)
            print ("Attack " + str(counter) + " prevented")
        elif attack == 'Fail':
            print ("Attack " + str(counter) + " successful!")
            print (output)
    except subprocess.CalledProcessError as e:
        if "Invalid tainting operation" in str(e.output):
            if attack == 'Success':
                print ("Test failed")
                os.exit(-1)
            print ("Attack " + str(counter) + " prevented")
            pass
        else:
            print ("Attack " + str(counter) + " error")
            print (e.output)

