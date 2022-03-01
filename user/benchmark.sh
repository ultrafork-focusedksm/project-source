#!/bin/bash

if [[ $EUID -ne 0 ]]; then
    echo "Run as root"
    exit 1
fi

TRIALS="${1}"


for i in $(seq 1 ${1}) ; do
    echo "Iteration ${i}"

    for j in $(seq 1 ${2}) ; do
        touch "ufrk_${i}_${j}"
        ./sus_mod_tester -u -n "${i}"
        if [[ $? -ne 0 ]]; then
            echo "FAIL"
            exit 1
        fi
        dmesg -l alert | tail -n "${i}" | grep "return to caller, took" | cut -d ',' -f 2 | cut -d ' ' -f 3 \
            | tr -d 'ns' | awk '{x = x + $1} END {print x}' >> "ufrk_${i}_${j}"
        sync
        sleep 1
    done
done
