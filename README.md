# Things to install for new setup

sudo apt install libb2-1 libb2-dev base-devel

copy kernel config from mqp_sus_memory/linux into the kernel source directory
run make menuconfig and make sure legacy ksm is enabled and address sanitizer is on

run:
sudo make -j $(nproc)
sudo make modules_install
sudo make install

then reboot
