#!/usr/bin/python3
import subprocess
import os

attacks = [-4, -2, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]

for attack in attacks:
    try:
        #os.system("riscv-vp atts --parameter " + str(attack))
        output = subprocess.check_output("riscv-vp atts --parameter " + str(attack) + " 2> /dev/null", shell=True)
        if "ATTACK successful" in str(output):
            print ("Oh no, attack " + str(attack) + " was successful")
            exit -1
        else:
            print ("Attack " + str(attack) + " not applicable")
    except subprocess.CalledProcessError as e:
        if "Invalid tainting operation" in str(e.output):
            print ("Attack " + str(attack) + " prevented")
            pass
        else:
            print ("Attack " + str(attack) + " error")
            print (e.output)

