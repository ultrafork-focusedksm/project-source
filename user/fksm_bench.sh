#!/bin/bash

if [[ $EUID -ne 0 ]]; then
    echo "Run as root"
    exit 1
fi

TRIALS="${1}"

rm -rf ./tests/all/*
rm -rf ./tests/dt/*
rm -rf ./tests/scan/*
rm -rf ./tests/m_s/*
rm -rf ./tests/m_f/*


for i in $(seq 1 ${1}) ; do
    echo "Pages per pid: ${i}"

    for j in $(seq 1 ${2}) ; do
        touch "./tests/all/fksm_${i}_${j}"
        touch "./tests/dt/fksm_${i}_${j}"
        touch "./tests/scan/fksm_${i}_${j}"
        touch "./tests/m_s/fksm_${i}_${j}"
        touch "./tests/m_f/fksm_${i}_${j}"
        ./sus_mod_tester -f ${i}
        if [[ $? -ne 0 ]]; then
            echo "FAIL"
            exit 1
        fi
        dmesg | tail -n "${i}" | grep "FKSM_TESTS: " >> "./tests/all/fksm_${i}_${j}"
        dmesg | tail -n "${i}" | grep "FKSM_TESTS: " | cut -d ' ' -f 4 >> "./tests/dt/fksm_${i}_${j}"
        dmesg | tail -n "${i}" | grep "FKSM_TESTS: " | cut -d ' ' -f 6 >> "./tests/scan/fksm_${i}_${j}"
        dmesg | tail -n "${i}" | grep "FKSM_TESTS: " | cut -d ' ' -f 8 >> "./tests/m_s/fksm_${i}_${j}"
        dmesg | tail -n "${i}" | grep "FKSM_TESTS: " | cut -d ' ' -f 10 >> "./tests/m_f/fksm_${i}_${j}"
        sync
        sleep 1
    done
done
