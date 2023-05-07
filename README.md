# Custom Linux IDS - CSCE 3560 Project

To compile: gcc group12.c -o group12 -pthread

To run: sudo ./group12

Members: Chance Currie, William Mahoney, Joe Selvera, David Abbot

Date: Sunday May 7th, 2023

Description: 
This IDS will continuously monitor and detect three specific DoS attacks: TCP SYN Flood, Ping Flooding, and Fork Bombing. When the programs detects
any of these attacks occuring, the program will automatically block/stop the attack from occuring.

For TCP SYN Attack, the program will continuously monitor for any Slowloris attacks. If an attack is detected due to the number of connections 
being made from one IP being greater than a specified threshold,it will block the IP through the use of ufw. Since Slowloris can still keep the 
connections that made it through open before being  blocked, we then remove any existing connections that are still alive that are being made by the blocked IP.

For the Ping Flood, this program will continuously monitor incoming ping packets into the system. When a burst of ping packets are being directed at the system
in  a small time span, the prgram will grab the IP address of the attacker, and through ufw, temporarily block the IP address of the attacker. When the specified amount of time has passed, the program will automatically unblock the IP address.

For the Fork Bomb, this program will continuously monitor the system processes. It does this by calling the ps commands and capturing the output. It will parse 
this output and for each unique process name it will add a count to it. If the count reaches past 10 processes of the same unique name it is assumed that the 
system may be facing a potential fork bomb attack as processes usually only contain 1 or 2 of the same unique name. The program will call the kill system call 
to kill all processes with over 10 of the same unique name. The program will then get the username and uid of the offender and log the attack with a timestamp,
the process name, the username and the uid.
