#!/bin/bash

touch ./res/fksm_dt_${1}
touch ./res/fksm_scan_${1}
touch ./res/fksm_m_s_${1}
touch ./res/fksm_hash_${1}
touch ./res/fksm_lookup_${1}

cat ./tests/dt/fksm_${1}_* | awk '{sum += $1; n++} END{ if (n > 0) printf "%d\n", sum / 10; }' >> ./res/fksm_dt_${1}
cat ./tests/scan/fksm_${1}_* | awk '{sum += $1; n++} END{ if (n > 0) printf "%d\n", sum / 10; }' >> ./res/fksm_scan_${1}
cat ./tests/m_s/fksm_${1}_* | awk '{sum += $1; n++} END{ if (n > 0) printf "%d\n", sum / 10; }' >> ./res/fksm_m_s_${1}
cat ./tests/hash/fksm_${1}_* | awk '{sum += $1; n++} END{ if (n > 0) printf "%d\n", sum / 10; }' >> ./res/fksm_hash_${1}
cat ./tests/lookup/fksm_${1}_* | awk '{sum += $1; n++} END{ if (n > 0) printf "%d\n", sum / 10; }' >> ./res/fksm_lookup_${1}


