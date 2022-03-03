#!/bin/bash

touch ultrafork_input
for i in $(seq 1 "${1}") ; do
    cat ./tests/dt/fksm_${i}_* | awk '{sum += $1; n++} END{ if (n > 0) printf "%d\n", sum / 10; }' >> fksm_dt
    cat ./tests/scan/fksm_${i}_* | awk '{sum += $1; n++} END{ if (n > 0) printf "%d\n", sum / 10; }' >> fksm_scan
    cat ./tests/m_s/fksm_${i}_* | awk '{sum += $1; n++} END{ if (n > 0) printf "%d\n", sum / 10; }' >> fksm_m_s
done
