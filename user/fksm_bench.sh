#!/bin/bash

if [[ $EUID -ne 0 ]]; then
    echo "Run as root"
    exit 1
fi

TRIALS="${1}"

for j in $(seq 1 ${2}) ; do
    touch "./tests/all/fksm_${1}_${j}"
    touch "./tests/dt/fksm_${1}_${j}"
    touch "./tests/scan/fksm_${1}_${j}"
    touch "./tests/m_s/fksm_${1}_${j}"
    ./sus_mod_tester -f ${1}
    if [[ $? -ne 0 ]]; then
        echo "FAIL"
        exit 1
    fi
    dmesg | tail -n 2 | grep "FKSM_TESTS:" >> "./tests/all/fksm_${1}_${j}"
    dmesg | tail -n 2 | grep "FKSM_TESTS:" | cut -d ',' -f 2 | cut -d ' ' -f 2 >> "./tests/dt/fksm_${1}_${j}"
    dmesg | tail -n 2 | grep "FKSM_TESTS:" | cut -d ',' -f 3 | cut -d ' ' -f 2  >> "./tests/scan/fksm_${1}_${j}"
    dmesg | tail -n 2 | grep "FKSM_TESTS:" | cut -d ',' -f 4 | cut -d ' ' -f 2  >> "./tests/m_s/fksm_${1}_${j}"

    dmesg | tail -n 2 | grep "FKSM_TIMES:" >> "./tests/all/fksm_${1}_${j}"
    dmesg | tail -n 2 | grep "FKSM_TIMES:" | cut -d ',' -f 2,3 --output-delimiter=' ' | cut -d ' ' -f 2,4 | awk '{avg=$1/$2}; END {print avg}' >> "./tests/hash/fksm_${1}_${j}"
    dmesg | tail -n 2 | grep "FKSM_TIMES:" | cut -d ',' -f 4,5 --output-delimiter=' ' | cut -d ' ' -f 2,4 | awk '{avg=$1/$2}; END {print avg}' >> "./tests/lookup/fksm_${1}_${j}"
    sync
    sleep 1
done