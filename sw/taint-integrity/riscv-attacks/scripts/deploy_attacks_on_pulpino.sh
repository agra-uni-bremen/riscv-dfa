#!/bin/bash

# This script deploys the attacks of John Wilander and Mariam Kamkar on PULPino.

ATTACK=wilander_kamkar

PULPino_dir=../deploy/pulpino/

if [ ! -d "$PULPino_dir" ]; then
    echo "Error: the submodule pulpino is not present"
    exit
fi

PULPino_app_dir=../deploy/pulpino/sw/apps

if grep -q "add_subdirectory($ATTACK)" $PULPino_app_dir/CMakeLists.txt; then

    echo "Info: $ATTACK directory was present"

else

    # Create the directory in pulpino apps
    mkdir $PULPino_app_dir/$ATTACK

    # Add the CMakeLists.txt in $ATTACK
    echo "add_application($ATTACK $ATTACK.c)" > $PULPino_app_dir/$ATTACK/CMakeLists.txt

    # Add the target in the global CMakeLists.txt
    sed -i "s/add_subdirectory(helloworld)/add_subdirectory(helloworld)\nadd_subdirectory($ATTACK)/" $PULPino_app_dir/CMakeLists.txt

    echo "Info: $ATTACK directory created"
fi

# Add the source code of the attack (or update it if it was present)
cp ../attacks/$ATTACK/$ATTACK.c $PULPino_app_dir/$ATTACK

echo "Info: $ATTACK deployed successfully"

