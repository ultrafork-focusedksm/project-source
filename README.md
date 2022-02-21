# Things to install for new setup

sudo apt install build-essential libb2-1 libb2-dev libncurses-dev flex bison libssl-dev libelf-dev

copy kernel config from mqp_sus_memory/linux into the kernel source directory
run make menuconfig and make sure legacy ksm is enabled and address sanitizer is on

i had to change CONFIG_FRAME_WARN to 2048 instead of 1024 because it kept giving me errors

run:
sudo make -j $(nproc)
sudo make modules_install
sudo make install

then reboot
