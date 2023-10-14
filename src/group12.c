/*
To compile: gcc group12.c -o group12
To run: sudo ./group12
Members: 
  Chance Currie
  William Mahoney
  Joe Selvera
  David Abbot
Date: Sunday May 7th, 2023
Description: 
This IDS will continuously monitor and detect three specific DoS attacks: TCP SYN Flood, Ping Flooding, and Fork Bombing. When the programs detects
any of these attacks occuring, the program will automatically block/stop the attack from occuring.

For TCP SYN Attack, the program will continuously monitor for any Slowloris attacks. If an attack is detected due to the number of connections 
being made from one IP being greater than a specified threshold,it will block the IP through the use of ufw. Since Slowloris can still keep the 
connections that made it through open before being  blocked, we then remove any existing connections that are still alive that are being made by the blocked IP.

For the Ping Flood, this program will continuously monitor incoming ping packets into the system. When a burst of ping packets are being directed at the system
in  a small time span, the prgram will grab the IP address of the attacker, and through ufw, temporarily block the IP address of the attacker. When the specified
amount of time has passed, the program will automatically unblock the IP address.

For the Fork Bomb, this program will continuously monitor the system processes. It does this by calling the ps commands and capturing the output. It will parse 
this output and for each unique process name it will add a count to it. If the count reaches past 10 processes of the same unique name it is assumed that the 
system may be facing a potential fork bomb attack as processes usually only contain 1 or 2 of the same unique name. The program will call the kill system call 
to kill all processes with over 10 of the same unique name. The program will then get the username and uid of the offender and log the attack with a timestamp,
the process name, the username and the uid.
*/

#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<errno.h>
#include<string.h>
#include<sys/types.h>
#include<time.h>
#include<signal.h>
#include<stdbool.h>
#include<pthread.h>
#include<sys/wait.h>
#include<pwd.h>
//Libraries needed

struct timespec pBegin, tBegin; //Keeping track of the time
struct timespec pEnd, tEnd; //Keeping track of time
double prevElapsedTime = 0; //Keeping track of the previous time
int pingCounter = 0; //Keep track of current pings if they exceed a certain time span
int totalIPAddressesBlocked = 0; //Keep track of the total amount of IP addresses we have blocked
char foreignIP[INET_ADDRSTRLEN]; //Grab and store the IP address from the attacker
char** ipArray; //Dynamic 2D array to store currently blocked IP addresses.
char** tempIPArray; //Used to store the IPs we block when we delete an IP address.
double* timeArray; //Dynamic array to store the time we blocked the IP address
double* tempTimeArray; //Used to store time stamps for when we delete an IP address
int serverfd = 0, clientfd = 0; //Need for sockets. Needs to be global so we can shutdown the program
bool quitParentProcess = false; //When we shutdown the program, breaks the parent process out of the while loop
bool quitThread = false; //When we shutdown the program, breaks the thread out of the while loop
bool pingFlood = false; //How we notify the thread that we have an attack and need to block the IP address
bool parentWait; //Want to block the parent process when we are attacked and unblock the parent process once we block the attacker
//Global Variables needed

void parentCompareTime(); //Allows the parent process to compare time of packets arriving to determine if we are under attack
void* threadFunction(void*); //Keep the thread in this function to handle all other functions
void* threadPingWatch(void*); //Watch for incoming ICMP ping packets

void createIPRule();
void ufwFile(); //Need to add rule to firewall file so firewall can block communications from the IP
void ufwReload(); //Reload the firewall for rules to take effect

void addToIPTable(char* foreignIP); //Need to store the blocked IP address to dynamic array
void addToTimeTable(); //Need to store the time stamp of the blocked IP address to dynamic array

void deleteFromIPTable(int position); //Need to delete stored IP from dynamic array
void deleteFromTimeTable(int position); //Need to delete stored timestamp from deleted IP

void deleteCreatedIPRule(int position); //Delete the rule we created for the firewall
void deleteRule(int position); //Need to delete the rule from the before.rules file for the firewall

void beforeStart(); //Want to do some pre-processing before we start the program
void cleanUp(); //Want to properly free the dynamic arrays if we end the program early with values still stored
void signalHandler(int signum); //To grab the signal "ctrl c" so our program knows to properly clean up, and get thread/process out of their while loops
void logFile(int operation, int position); //Want to log an event (adding of IP or deletion of IP)
//Functions above needed for the ping flood

#define MAX_CONNECTIONS 30  // The max connections to the server that one IP can have. Can be changed as needed.

volatile sig_atomic_t stop_flag = 0; // Flag to stop program

void* detect_block_slowloris(void*);
void* tcpPrintLoop(void*);
//Needed for the TCP SYN Flood detection

#define MAX_PROCESSES 1000
bool quitForkBomb = false;
void* forkBomb(void*);
//Needed for the Fork Bomb detection

int main(int argc, char* argv[])
{
  signal(SIGINT, signalHandler); //Set our signal handler
  beforeStart(); //Perform our pre-processing
  sleep(1);

  pthread_t sleepThread; //Make the definitions for our threads
  pthread_t pingThread; //Make the definitions for our threads
  pthread_create(&pingThread, NULL, threadPingWatch, NULL); //Have our thread go to its function.
  pthread_create(&sleepThread, NULL, threadFunction, NULL); //Have our thread go to its function.
  //Needed for the ping flood detection of the IDS

  
  pthread_t tcpThread;
  pthread_t tcpThreadPrint;
  pthread_create(&tcpThread, NULL, detect_block_slowloris, NULL);
  pthread_create(&tcpThreadPrint, NULL, tcpPrintLoop, NULL);
  //Information needed for TCP SYN Flood detection

  pthread_t forkThread;
  pthread_create(&forkThread, NULL, forkBomb, NULL);

  pthread_join(sleepThread, NULL); //Want to wait for thread to finish before we end
  pthread_join(pingThread, NULL); //Want to wait for thread to finish before we end
  pthread_join(tcpThread, NULL);
  pthread_join(tcpThreadPrint, NULL);
  pthread_join(forkThread, NULL);
  printf("\nEnding program\n");
  return 0;
}

void parentCompareTime()
{
  double elapsedTime = (pEnd.tv_sec - pBegin.tv_sec) + (pEnd.tv_nsec - pBegin.tv_nsec) / 1000000000.0; //Compute the time the packet arrived at
  if(elapsedTime > 5.00)
  {
    pingCounter = 0; //If packets are spaced apart appropriately, we are not under attack
  }
  if(elapsedTime - prevElapsedTime < 0.000500 && elapsedTime <= 0.000900 && prevElapsedTime <= 0.000900) //KEEP THIS LINE
  {
    pingCounter++; //Since this is very small time between packets, we increment the counter
  }

  if(pingCounter == 0) //Only want to print messages when we know we aren't being flooded, to keep terminal buffer clean
  {
    printf("Ping packet recieved from IP address: %s\n", foreignIP );
  }

  if(totalIPAddressesBlocked != 0)
  {
  
    for(int i = 0; i < totalIPAddressesBlocked; i++)
    {
      if(strcmp(foreignIP, ipArray[i]) == 0) //Matching blocked IP
      {
        pingCounter = 0;
      }
    }
  }

  if(pingCounter == 500) //We know if we get 500 ping messages suddenly, we are getting flooded. So we only want to do the operations once. Once the operations are done, the system will stop responding.
  {
    printf("**PING FLOOD DETECTED**\n");
    pingFlood = true; //We alert the thread
    parentWait = true; //Block the parent
    while(1)
    {
      if(parentWait == false)
      {
        break; //Unblock the parent once we finish blocking the IP address
      }
    }
  }
  prevElapsedTime = elapsedTime; //Set the previous captured time
  return;
}

void* threadPingWatch(void* arg)
{
  int clientSize; //The size of the client addr.
  int portNumber; //For the portnumber used.

  struct sockaddr_in serverAddr; //Declaring the server structure
  struct sockaddr_in clientAddr; //Declaring the client structure

  char buff[100]; //Buffer for recvfrom

  if((serverfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) //Set up to capture ICMP Ping Packets
  {
    printf("Socket error\n");//Will print the error if the program is unable to create the socket.
    exit(EXIT_FAILURE);
  }//To set up a server, the first step is to set up the sockets

  memset(&serverAddr, '0', sizeof(serverAddr));
  memset(&clientAddr, '0', sizeof(clientAddr));
  //Fill struct with 0s

  serverAddr.sin_family = AF_INET; //Sets the family to internet Socket
  portNumber = 0; //Use port 0 since its a wildcard
  serverAddr.sin_port = htons(0); //Setting the port.
  serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);//Using INADDR_ANY so we dont bind to a specific IP

  int on = 1;
  setsockopt(serverfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
  //Code to reuse port if it were to fail

  if(bind(serverfd, (struct sockaddr*) &serverAddr, sizeof(serverAddr)) < 0)
  {
    printf("bind error\n"); //Will print the error if the server is unable to bind to the socket.
    exit(EXIT_FAILURE);
  } //The second step in creating a server is to bind the socket to a port.

  clientSize = sizeof(clientAddr); //Set clientsize
  printf("\n[server]: ready to accept data...\n");
  while(1) //The thread will only end when we do ctrl c
  {
    if(quitThread == true)
    {
      break; //Allows the thread to break from loop and clean up
    }
    //printf("\n[server]: ready to accept data...\n");
    while(1)//This while loop will only fully execute when we get a ICMP Ping Packet
    {
    timespec_get(&pBegin, TIME_UTC); //Want to capture time before a packet arrives
    if(clientfd = recvfrom(serverfd, buff, 100, 0, (struct sockaddr*) &clientAddr, &clientSize) < 0)
    {
      printf("Unable to recieve data\n");
      exit(EXIT_FAILURE);
    } //If unable to capture the packets, we exit

    if(quitParentProcess == true)
    {
      break; //Want to break out of the while loop to clean up
    }
    inet_ntop(AF_INET, &clientAddr.sin_addr, foreignIP, sizeof(foreignIP)); //Capture the IP address from the client, needed for if we get attacked.
    timespec_get(&pEnd, TIME_UTC); //Want to capture the time after the packet arrives
    parentCompareTime(); //Parent process will compare time to determine if we are under attack.
  }
    
  }
  pthread_exit(NULL); //Have thread exit
}

void* threadFunction(void* arg)
{
  double timeCheck; //For checking the time.
  while(1) //The thread will only end when we do ctrl c
  {
    if(quitThread == true)
    {
      break; //Allows the thread to break from loop and clean up
    }
    if(pingFlood == true)//We want to block an IP address since we are getting flooded.
    {
      printf("Blocking IP Address: %s\n", foreignIP);
      //createIPRule(foreignIP); //Want to create the rule using the attackers IP address
      createIPRule();
      ufwFile(); //Update the before.rules file
      ufwReload(); //Reload the firewall so the newly added rules take effect
      totalIPAddressesBlocked++; //Increment the counter for our currently blocked IP addresses
      addToIPTable(foreignIP); //Add the blocked IP address to the dynamic array
      addToTimeTable(); //Add the time we blocked the IP address to the dynamic array
      logFile(1, 0); //Add we blocked an IP address to the log file
      parentWait = false; //Let the parent process proceed
      pingFlood = false; //We have blocked the IP Address.
    }

    if(totalIPAddressesBlocked > 0) //Only execute when we know we have blocked IP addresses.
    {
      timespec_get(&tEnd, TIME_UTC); //Get time
      timeCheck = tEnd.tv_sec; //Get the time in seconds
      for(int i = 0; i < totalIPAddressesBlocked; i++) //Loop through all IP addresses stored
      {
        if(((timeCheck - timeArray[i])) >= 20) //Counted in seconds, if 20 seconds pass, we unblock the IP address
        {
          //printf("The value stored at %d has passed 20 seconds, unbanning IP\n", i);
          printf("The IP address: %s has been blocked for 20 seconds, unblocking this IP address\n", ipArray[i]);
          deleteCreatedIPRule(i); //Want to delete the rule for the IP address
          deleteRule(i); //Want to delete the rule added to the before.rules file for the IP address
          ufwReload(); //Reload the firewall so changes take place
          printf("Deleting IP and time stamp stored\n\n");
          logFile(0, i); //Want to log we deleted an IP address
          deleteFromIPTable(i); //Delete the IP from the dynamic array
          deleteFromTimeTable(i); //Delete the time stamp of the IP address from the dynamic array
          totalIPAddressesBlocked--; //Decrement the total amount of IP addresses we have currently blocked.
          break; //Break out of the loop since the counter for the IP addresses has changed.
        }
      }
      sleep(1);
    }
    //Wanting to check if time has passed to delete the blocked IP Address
  }

  //When we terminate the program, the thread will clean up.
  printf("\nThread cleaning up\n");
  if(totalIPAddressesBlocked > 0)
  {
    printf("Printing IP Addresses currently blocked from ping flooding: \n");
    for(int i = 0; i < totalIPAddressesBlocked; i++)
    {
      printf("%s\n", ipArray[i]);
    }
  }
  cleanUp(); //Clean up our memory
  pthread_exit(NULL); //Have thread exit
}

void beforeStart()
{
  system("clear");
  char disableUFW[] = "ufw disable";
  char enableUFW[] = "ufw enable";
  bool blockPresent = false;
  FILE* beforeRules;
  FILE* tempFile;
  char c; //For writing data to files
  char *fileLine = NULL; //Store the line of the file
  size_t length = 0;
  ssize_t lineLength;//readLine; //Store the length of the file
  int filePos = 0; //Keep position of the file

  printf("Performing pre-processing...\n");
  system(disableUFW);
  printf("Checking before.rules file...\n");
  //Upon boot, we do pre-processing.

  beforeRules = fopen("/etc/ufw/before.rules", "r"); //Want to open the before.rules file for reading
  tempFile = fopen("tempFile.txt", "w"); //Want to make a temporary file for writing

  while((lineLength = getline(&fileLine, &length, beforeRules)) != -1)//Want to get the position of the text, and stop at the end of the file if its not present
  {
    filePos = lineLength + filePos;
    if(strcmp(fileLine, "# Block spammers\n") == 0)
    {
      blockPresent = true;
      break;
    }
  }
  //Want to check if the comment is present

  if(blockPresent == false) //We want to add # Block spammers since its not present
  {
    fseek(beforeRules, 0, SEEK_SET); //Set file pointer back to the start of the file.
    filePos = 0;
    while((lineLength = getline(&fileLine, &length, beforeRules)) != -1)
    {
      filePos = lineLength + filePos;
      if(strcmp(fileLine, "# End required lines\n") == 0)
      {
        break;
      }
    }
    filePos++;
    fseek(beforeRules, 0, SEEK_SET); //Go back to start of the file
    c = fgetc(beforeRules);
    while(!feof(beforeRules))
    {
      fputc(c, tempFile);
      c = fgetc(beforeRules);
      if(ftell(beforeRules) == filePos)
      {
        fprintf(tempFile, "\n%s\n", "# Block spammers"); //Write the new command into the second file
      }
    } //Write to the temporary file
    fclose(beforeRules); //Close the file
    fclose(tempFile); //Close the file
    beforeRules = fopen("/etc/ufw/before.rules", "w"); //Want to open the before.rules file for writing
    tempFile = fopen("tempFile.txt", "r"); //Open the temporary file for reading

    c = fgetc(tempFile);
    while(!feof(tempFile))
    {
      fputc(c, beforeRules);
      c = fgetc(tempFile);
    }
    //Copy the data over to the before.rules file

    fclose(beforeRules);
    fclose(tempFile);
    remove("tempFile.txt");
    printf("Added required lines\n");      
  } //This goes through and adds the required line for the program.

  if(blockPresent == true) //If the line is present, we want to check if theres any currently blocked IP addresses
  {
    char *fileLine2 = NULL; //Store the line of the file
    char grabIP[20];
    int j;
    printf("\nChecking if there is any IP addresses blocked currently\n");
    while((lineLength = getline(&fileLine, &length, beforeRules)) != -1)
    {
      filePos = lineLength + filePos;
      if(strcmp(fileLine, "# allow all on loopback\n") == 0) //If we have reached this line, then we have no more lines to check
      {
        break;
      }
      else if(strcmp(fileLine, "\n") != 0) //Operate here, as theres a blocked IP address
      {
        j = 0;
        grabIP[0] = '\0'; //Zero out array
        totalIPAddressesBlocked++; //Increment the blocked counter
        for(int i = 0; i < strlen(fileLine); i++)
        {
          if(fileLine[i] == 46 || (fileLine[i] >= 48 && fileLine[i] <= 57)) //Want to only capture 1-9, and .
          {
            grabIP[j] = fileLine[i];
            j++;
          }
        }
        grabIP[j] = '\0'; //Add null terminator
        printf("The blocked IP address is: %s\n", grabIP);
        printf("Adding IP to blocked IP Array\n");
        addToIPTable(grabIP);
        printf("Adding the current time to the time table\n");
        addToTimeTable();
      }
    }
    fclose(beforeRules);
    fclose(tempFile);
  }
  printf("Starting firewall\n");
  system(enableUFW);
  return;
}

void createIPRule()
{
    char banIP[50]; //String to hold the command to ban the IP address
    char part1[15] = "ufw deny from ";//Need to store the first part of the command
    char part2[8] = " to any";//Completes the command
    banIP[0] = '\0'; //Want to empty out the string.
    strcat(banIP, part1);
    strcat(banIP, foreignIP);
    strcat(banIP, part2); //Combine all the parts to form the whole command
    system(banIP); //Will execute the command to ban the IP Address.
    return;
}

void deleteCreatedIPRule(int position)
{
  printf("\nDeleting added rule for %s\n", ipArray[position]);
  char deleteIPRule[30]; //String to hold the command to delete the ufw rule
  char part1[25] = "ufw delete deny from ";
  deleteIPRule[0] = '\0'; 
  strcat(deleteIPRule, part1);
  strcat(deleteIPRule, ipArray[position]);
  system(deleteIPRule); //Will execute the command delete our IP rule in ufw
}

void ufwFile()
{
  //We need to write the rule into the file. In order to do this, we need to  
  //Copy the original file to a new file, then copy the second file into the 
  //Original file.
  char c; //For storing the file char by char
  char banIPRule[60]; //String to hold the command to write the rule into the before.rules file
  char part1[25] = "-A ufw-before-input -s ";//Need to store the first part of the command
  char part2[10] = " -j DROP";//Completes the command
  char *fileLine = NULL; //Store the line of the file
  size_t length = 0;
  ssize_t lineLength;//Store the length of the file
  int filePos = 0;
  FILE* beforeRule; //before.rule file
  FILE* tempFile; //New file to house needed data.

  banIPRule[0] = '\0'; //Want to empty out the string.
  strcat(banIPRule, part1);
  strcat(banIPRule, foreignIP);
  strcat(banIPRule, part2); //Combine all the parts to form the whole command

  beforeRule = fopen("/etc/ufw/before.rules", "r");
  tempFile = fopen("newFile.txt", "w");

  while((lineLength = getline(&fileLine, &length, beforeRule)) != -1)//Want to get the position of the text to add in
  {
    filePos = lineLength + filePos;
    if(strcmp(fileLine, "# Block spammers\n") == 0)
    {
      break;
    }
  }
  filePos++;
  fseek(beforeRule, 0, SEEK_SET); //Set file pointer back to the start of the file.
  //We want to get the position of the matching text, and go one more positon ahead

  c = fgetc(beforeRule);
  while(!feof(beforeRule))
  {
    fputc(c, tempFile);
    c = fgetc(beforeRule);
    if(ftell(beforeRule) == filePos)
    {
      fprintf(tempFile, "%s\n", banIPRule); //Write the new command into the second file
    }
  }
  fclose(beforeRule); //Close the file
  fclose(tempFile); //Close the file
  //Copy the before.server to the temporary file

  beforeRule = fopen("/etc/ufw/before.rules", "w"); //Open the file for writing
  tempFile = fopen("newFile.txt", "r"); //Open the temp file for reading

  c = fgetc(tempFile);
  while(!feof(tempFile))
  {
    fputc(c, beforeRule);
    c = fgetc(tempFile);
  }//Finally copy the temporary file to the before.rules file, which adds our rule
  fclose(beforeRule);
  fclose(tempFile);

  if(remove("newFile.txt") != 0)
  {
    printf("Error removing temporary file\n");
  }//Want to remove the temporary file we created.
  return;
}

void deleteRule(int position)
{
  //We need to delete the rule from the before.rules file. In order to do this, we need to copy the file to a temporary file
  //Omit the rule we want to delete, and then copy the temporary file to the before.rules file.
  char deleteIPRule[60]; //String to hold the command to delete the rule in the before.rules file and the ufw rule
  char part1[25] = "-A ufw-before-input -s ";//Need to store the first part of the command for before.rules
  char part2[10] = " -j DROP\n";//Completes the command
  char c; //For writing data to files
  char *fileLine = NULL; //Store the line of the file
  size_t length = 0;
  ssize_t lineLength;//readLine; //Store the length of the file
  int filePos = 0; //Keep position of the file
  FILE* beforeRule;//Will be used to open before.rules
  FILE* tempFile;//Will be the temporary file

  deleteIPRule[0] = '\0'; //Want to empty out the string.
  strcat(deleteIPRule, part1);
  strcat(deleteIPRule, ipArray[position]); //Puts the IP Address from the array
  strcat(deleteIPRule, part2); //Combine all the parts to form the whole command

  beforeRule = fopen("/etc/ufw/before.rules", "r"); //Want to open the before.rules file
  tempFile = fopen("tempFileDelete.txt", "w");

  while((lineLength = getline(&fileLine, &length, beforeRule)) != -1)//Want to get the position of the text
  {
    filePos = lineLength + filePos;
    if(strcmp(fileLine, deleteIPRule) == 0) //Look for the line in the before.rules file that matches our IP address
    {
      filePos = filePos - lineLength; //Want to go back in position so we can omit this line
      break;
    }
  }
  fseek(beforeRule, 0, SEEK_SET); //Set file pointer back to the start of the file.

  c = fgetc(beforeRule);
  while(!feof(beforeRule))
  {
    fputc(c, tempFile);
    c = fgetc(beforeRule);
    if(ftell(beforeRule) == filePos)
    {
      filePos = filePos + lineLength; //Want to set the position of the file pointer to be ahead of what we want to delete
      fseek(beforeRule, filePos, SEEK_SET); //Change the file position to be ahead of what we wanted to delete, effectively deleting it.
    }
  }
  fclose(beforeRule);
  fclose(tempFile);
  //This chunk of code copies the file to a temporary file while deleting the IP address.

  beforeRule = fopen("/etc/ufw/before.rules", "w");
  tempFile = fopen("tempFileDelete.txt", "r");

  c = fgetc(tempFile);
  while(!feof(tempFile))
  {
    fputc(c, beforeRule);
    c = fgetc(tempFile);
  } //Copy contents over
  fclose(beforeRule);
  fclose(tempFile);
  //This chunk of code copies over the temporary file into the original file.

  if(remove("tempFileDelete.txt") != 0)
  {
    printf("Error removing the temporary file\n");
  }//Want to remove the temporary file we created.
  return;
}

void ufwReload()
{
  printf("\nReloading UFW Firewall...\n");
  char statusCommand[20] = "ufw reload";
  system(statusCommand);
  return;
  //Reloads the firewall so our rules can be enforced, blocking the IP address and prevents the computer from responding to it.
}

void addToIPTable(char* foreignIP)
{
  if(totalIPAddressesBlocked == 1) //If we only have one blocked IP address currently, we just do a simple operation
  {
    ipArray = (char**)malloc(1 * sizeof(char*)); //Allocate spots
    ipArray[0] = (char*)malloc(16 * sizeof(char)); //Allocate length
    strcpy(ipArray[0], foreignIP); //Copy IP over
    printf("The IP Stored is: %s\n", ipArray[0]);
  }
  else if(totalIPAddressesBlocked >= 2) //If theres 2 or more, we need to do more complex operations
  {
    tempIPArray = (char**)malloc((totalIPAddressesBlocked - 1) * sizeof(char*)); //Make temp array hold one less
    for(int i = 0; i < (totalIPAddressesBlocked - 1); i++)
    {
      tempIPArray[i] = (char*) malloc(16 * sizeof(char)); //Allocate each spot
      strcpy(tempIPArray[i], ipArray[i]); //Copy the contents into the tempIPArray
      free(ipArray[i]); //Free the array elements
    }
    free(ipArray);//Free the array
    ipArray = (char**)malloc(totalIPAddressesBlocked * sizeof(char*)); //Make the size the amount of IP addresses blocked
    for(int i = 0; i < (totalIPAddressesBlocked - 1); i++) //Size of the temporary array
    {
      ipArray[i] = (char*)malloc(16 * sizeof(char)); //Again allocate the length of each slot
      strcpy(ipArray[i], tempIPArray[i]); //Copy the old IP addresses into the array
      free(tempIPArray[i]); //Free the array elements of the temporary array
    }
    ipArray[totalIPAddressesBlocked - 1] = (char*)malloc(16 * sizeof(char)); //We need to add the new element now
    strcpy(ipArray[totalIPAddressesBlocked - 1], foreignIP); //Copy the IP address
    free(tempIPArray);//Free the temp array
  }
  return;
}

void deleteFromIPTable(int position)
{
  if(totalIPAddressesBlocked == 1) //Do a simple operation if we only have one blocked IP address
  {
    free(ipArray[0]); //Free the array elements
    free(ipArray);//Free the array
  }
  else if(totalIPAddressesBlocked >= 2) //More complex operation if we have 2 or more blocked IP addresses
  {
    int j = 0;
    tempIPArray = (char**)malloc((totalIPAddressesBlocked - 1) * sizeof(char*)); //Make temp array hold one less
    for(int i = 0; i < totalIPAddressesBlocked; i++)
    {
      if(i != position) //Want to keep the non matching IP addresses
      {
        tempIPArray[j] = (char*) malloc(16 * sizeof(char));
        strcpy(tempIPArray[j], ipArray[i]); //Copy the contents into the tempIPArray
        j++;
        free(ipArray[i]);
      }
      else
      {
        free(ipArray[i]); //We dont keep the IP address we are unblocking
      }
    }
    free(ipArray);
    ipArray = (char**)malloc((totalIPAddressesBlocked - 1) * sizeof(char*)); //Make the new IP array size
    for(int i = 0; i < (totalIPAddressesBlocked - 1); i++)
    {
      ipArray[i] = (char*) malloc(16 * sizeof(char));
      strcpy(ipArray[i], tempIPArray[i]);
      free(tempIPArray[i]);
    } //Go through and copy contents from the temp array to the new one
    free(tempIPArray);
  }
  return;
}

void addToTimeTable()
{
  timespec_get(&tBegin, TIME_UTC); //Grab the time
  double currTime = tBegin.tv_sec; //Store the time in seconds
  if(totalIPAddressesBlocked == 1) //Do simple operation if we only have 1 blocked IP address
  {
    timeArray = (double*)malloc(totalIPAddressesBlocked * sizeof(double));
    timeArray[0] = currTime;
  }
  else if(totalIPAddressesBlocked >= 2) //Do more complex operations for if we have 2 or more blocked IP addresses
  {
    tempTimeArray = (double*)malloc((totalIPAddressesBlocked - 1) * sizeof(double)); //Make our temporary array
    for(int i = 0; i < (totalIPAddressesBlocked - 1); i++)
    {
      tempTimeArray[i] = timeArray[i]; //Copy contents into temp array
    }
    free(timeArray);
    timeArray = (double*)malloc(totalIPAddressesBlocked * sizeof(double)); //Free and make new size
    for(int i = 0; i < (totalIPAddressesBlocked - 1); i++)
    {
      timeArray[i] = tempTimeArray[i]; //Copy info into newly allocated array
    }
    timeArray[totalIPAddressesBlocked - 1] = currTime; //Store the new item
    free(tempTimeArray);
  }
  return;
}

void deleteFromTimeTable(int position)
{
  if(totalIPAddressesBlocked == 1) //Again simple operation if we have 1 blocked IP address
  {
    free(timeArray);
  }
  else if(totalIPAddressesBlocked >= 2) //More complex operation if 2 or more blocked IP addresses
  {
    int j = 0;
    tempTimeArray = (double*)malloc((totalIPAddressesBlocked - 1) * sizeof(double)); //Make temp array
    for(int i = 0; i < totalIPAddressesBlocked; i++)
    {
      if(i != position)
      {
        tempTimeArray[j] = timeArray[i]; //Copy contents into temp array
        j++;
      }
    }
    free(timeArray);
    timeArray = (double*)malloc((totalIPAddressesBlocked - 1) * sizeof(double)); //Free and make new size
    for(int i = 0; i < (totalIPAddressesBlocked - 1); i++)
    {
      timeArray[i] = tempTimeArray[i]; //Store items into newly allocated array
    }
    free(tempTimeArray);
  }
  return;
}

void cleanUp()
{
  if(totalIPAddressesBlocked != 0)
  {
    for(int i = 0; i < totalIPAddressesBlocked; i++)
    {
      free(ipArray[i]);
    }
    free(ipArray);
    free(timeArray);
  }
  return;
} //Want to free the memory we have allocated.


void signalHandler(int signum)
{
  shutdown(serverfd, SHUT_RDWR); //Close the socket to prevent communications. This will kick us out of recvfrom, which is a blocking function
  quitThread = true; //Make the thread clean up
  quitParentProcess = true; //Will get out of the while loop in main.
  stop_flag = 1;
  quitForkBomb = true;
  return;
} 
//Since recvfrom is a blocking function, we want to capture a signal (in this case it is ctrl c)
//To end the program and free resources properly before quitting.

void logFile(int operation, int position) //If Operation is 0, we deleted an IP, if 1, we added an IP
{
  time_t t;
  struct tm* localTime;
  FILE* logFile;
  logFile = fopen("pingFloodLogfile.txt", "a"); //Want to apend data to log file
  time(&t);
  localTime = localtime(&t); //So we can print the exact time
  if(operation == 0) //Delete log stamp
  {
    fprintf(logFile, "Deleted IP %s from the block list on: %s\n", ipArray[position], asctime(localTime)); //Write the log to the file
  }
  else if(operation == 1) //Add log stamp
  {
    fprintf(logFile, "Added IP %s to block list on: %s\n", ipArray[totalIPAddressesBlocked - 1], asctime(localTime)); //Write the log to the file
  }
  fclose(logFile);
  return;
}

//FUNCTIONS NEEDED FOR TCP SYN FLOOD
void* detect_block_slowloris(void* arg)
{
    // Infinite loop to continuously monitor and block Slowloris attacks
    while (!stop_flag)
    {
        // Get a list of IP addresses with their connection count
        FILE* fp = popen("netstat -ntu | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr", "r");

        if (fp == NULL)
        {
            fprintf(stderr, "Failed to execute command\n");
            exit(1);
        }

        char line[1024];

        while (fgets(line, sizeof(line), fp) != NULL)
        {
            int connections = 0;
            char ip[16];

            if (sscanf(line, "%d %15s", &connections, ip) == 2)
            {
                /*
                    If the amount of connections are greater than the max amount of connections that can be made from a single IP,
                    then it will flag the IP, block it through the use of iptables, then kill any remaining hanging connections that were made
                    before the program could catch the Slowloris attack to ensure that no more connections are being made from the blocked IP.
                */

                if (connections > MAX_CONNECTIONS)
                {
                    printf("------------------------------------\n");
                    printf("Potential Slowloris attack detected.\n");
                    printf("Blocking IP: %s with %d connections.\n", ip, connections);

                    char cmd[256];
                    snprintf(cmd, sizeof(cmd), "sudo ufw deny from %s", ip);
                    system(cmd);

                    // Kill any remaining hanging connections from the blocked IP after a timeout of 5 seconds
                    pid_t pid = fork();

                    if (pid == -1)
                    {
                        fprintf(stderr, "Failed to fork\n");
                    }

                    else if (pid == 0)
                    {
                        // Child process
                        char ss_cmd[256];

                        printf("Child process created to remove hanging connections from blocked IP: %s\n", ip);
                        printf("Removing the following hanging connections from IP: %s \n", ip);

                        snprintf(ss_cmd, sizeof(ss_cmd), "sudo ss -K dst %s", ip);
                        execlp("sh", "sh", "-c", ss_cmd, NULL);
                        exit(1);
                    }

                    else
                    {
                        // Parent process that will wait for 3 seconds before closing
                        sleep(3);
                        waitpid(pid, NULL, WNOHANG);
                    }
                }
            }
        }

        pclose(fp);

        // Sleep for 4 seconds before checking for Slowloris attacks again
        sleep(4);
    }

    //return NULL;
    pthread_exit(NULL); //Have thread exit
}

void* tcpPrintLoop(void* arg)
{
  while (!stop_flag)
  {
    // Display console log information that may be needed when looking back at logs
    printf("\n");
    system("date");
    system("netstat -ntu | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr");

    // Sleep for 4 seconds before running again
    sleep(4);
  }
  pthread_exit(NULL); //Have thread exit
}

void* forkBomb(void*)
{
  FILE *fp;
  char path[1024];
  char *proc_names[MAX_PROCESSES];
  int proc_counts[MAX_PROCESSES] = {0};
  int num_procs = 0;
  time_t t;

  while (quitForkBomb == false) {
    //0 the count for each loop
    memset(proc_counts, 0, sizeof(proc_counts));
    num_procs = 0;

    // Use ps command and capture the outputs
    fp = popen("ps -eo comm=", "r");
    if (fp == NULL) {
      printf("Failed to run command\n");
      exit(1);
    }

    // Count the number of processes by each unique name
    while (fgets(path, sizeof(path)-1, fp) != NULL) {
      // Trim the newline
      strtok(path, "\n");

      // Add a count to a process name if it has been seen before
      int i;
      for (i = 0; i < num_procs; i++) {
        if (strcmp(proc_names[i], path) == 0) {
          proc_counts[i]++;
          break;
        }
      }

      // New process found will have count set to 1
      if (i == num_procs) {
        proc_names[num_procs] = strdup(path);
        proc_counts[num_procs] = 1;
        num_procs++;

        // Limit set to not overwhelm the program and VM
        if (num_procs >= MAX_PROCESSES) {
          printf("Exceeded maximum number of processes to monitor\n");
          exit(1);
        }
      }
    }

    // Close the pipe
    pclose(fp);

    // Kill the processes that have too many duplicates = deemed as forkbomb is too many are spawned
    int i;
    for (i = 0; i < num_procs; i++) {
      if (proc_counts[i] >= 10) {
        char command[1024];
        snprintf(command, sizeof(command), "killall -9 %s", proc_names[i]);
        fp = popen(command, "r");
        if (fp == NULL) {
          printf("Failed to run command\n");
          exit(1);
        }
		    //get the username and ID
		    uid_t uid = getuid();
		    struct passwd *pw = getpwuid(uid);

        // Log the attack
        time(&t);
        fp = fopen("forkbomblog.txt", "a");
        fprintf(fp, "Fork bomb attack detected for %s, UID %d, User: %s  at %s", proc_names[i], pw->pw_uid, pw->pw_name, ctime(&t));
        fclose(fp);
      }
    }

  }
  // Free memory
  int i;
  for (i = 0; i < num_procs; i++) {
    free(proc_names[i]);
  }

  pthread_exit(NULL); //Have thread exit
}
