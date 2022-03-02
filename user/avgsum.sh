#!/bin/bash

touch ultrafork_input
for i in $(seq 1 "${1}") ; do
    cat ufrk_${i}_* | awk '{sum += $1; n++} END{ if (n > 0) printf "%d\n", sum / 10; }' >> ultrafork_input
done
