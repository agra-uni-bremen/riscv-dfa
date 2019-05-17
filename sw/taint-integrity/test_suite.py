#!/usr/bin/python3
import subprocess

attacks = [-4, -2, 1, 2, 3, 5, 7, 8, 9, 11, 12, 13]

for attack in attacks:
    try:
        output = subprocess.check_output("riscv-vp atts --parameter " + str(attack) + " 2> /dev/null", shell=True)
        if "ATTACK successful" in str(output):
            print ("Oh no, attack " + str(attack) + " was successful")
            exit -1
        else:
            print ("Attack " + str(attack) + " not applicable")
    except Exception:
        print ("Attack " + str(attack) + " prevented")
        pass

