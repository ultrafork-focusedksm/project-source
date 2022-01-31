echo "USER: CLEAR SHM"
bash clear_shm.sh

# echo "\tUSER: MAKE CLEAN"
# make clean

echo "USER: MAKE"
make

cd ../kernel/

echo "KERN: RMMOD"
rmmod sus

# echo "\tKERN: MAKE CLEAN"
# make clean

echo "KERN: MAKE"
make

echo "KERN: INSMOD"
insmod sus.ko
