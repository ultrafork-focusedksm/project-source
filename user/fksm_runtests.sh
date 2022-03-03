#!/bin/bash

if [[ $EUID -ne 0 ]]; then
    echo "Run as root"
    exit 1
fi

rm -rf tests/
rm -rf res/

mkdir tests
mkdir tests/all
mkdir tests/dt
mkdir tests/scan
mkdir tests/m_s
mkdir res

echo "PAGES: 2"
bash fksm_bench.sh 2 10
echo "PAGES: 50"
bash fksm_bench.sh 50 10
echo "PAGES: 100"
bash fksm_bench.sh 100 10
echo "PAGES: 1000"
bash fksm_bench.sh 1000 10
echo "PAGES: 5000"
bash fksm_bench.sh 2500 10

bash fksm_avgsum.sh 2 
bash fksm_avgsum.sh 50 
bash fksm_avgsum.sh 100 
bash fksm_avgsum.sh 1000 
bash fksm_avgsum.sh 2500 