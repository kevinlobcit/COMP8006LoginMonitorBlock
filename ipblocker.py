#!/usr/bin/python
#-----------------------------------------------------------------------------
 # SOURCE FILE:    ipblocker.py
 #
 # PROGRAM:        echoClient
 #
 # FUNCTIONS:      int main(char** argv)
 #                 
 # DATE:           February 21, 2021
 #
 # REVISIONS:      N/A
 #
 # DESIGNER:       Kevin Lo
 #
 # PROGRAMMER:     Kevin Lo
 #
 # NOTES:
 # This program monitors the /var/log/secure file for failed passwords
# --------------------------------------------------------------------------

import re
import os
import time
import configparser


#--------------------------------------------------------------------------
 # FUNCTION:       ipAdder
 #
 # DATE:           February 21, 2021
 #
 # REVISIONS:      N/A (Date and explanation of revisions if applicable)
 #
 # DESIGNER:       Kevin Lo
 #
 # PROGRAMMER:     Kevin Lo
 #
 # INTERFACE:      void ipAdder(ip, ipArray, ipAttemptCount, ipTimeBetween, ipLockArray, ipLockEnd, timeout, locktime, maxattempts)
 #                      ip: The failed password ip from the /var/log/secure file
 #                      ipArray: The array containing the IP addresses who have recently failed passwords
 #                      ipAttemptCount: The array containing the attempt count of IPs that have failed passwords
 #                      ipTimeBetween: The array containing the maximum time limit between password failure attempts for an IP
 #                      ipLockArray: The array containing the ip address of blocked IPs
 #                      ipLockEnd: The array containing the time to unblock a blocked IPs
 #                      timeout: The maximum time in seconds between failed password attempts before a attempt records are purged, eg 10sec, after 10 seconds
 #                               the attempt count will be reset back to 0
 #                      locktime: The time duration to block an ip in seconds, locktime=0 is blocked forever
 #                      maxattempts: Maximum number of failed password attempts before the IP is blocked
 #
 # RETURNS:        void
 #
 # NOTES:
 # Checks if the ip is in the ip array, If it is in the array, increment the attempt count.
 # if not in the array, 
 # -----------------------------------------------------------------------
def ipAdder(ip, ipArray, ipAttemptCount, ipTimeBetween, ipLockArray, ipLockEnd, timeout, locktime, maxattempts):
    currentTime = time.time()
    inArray = 0
    
    #already exists in list
    if ip in ipArray:
        inArray = 1
        #get index
        i = ipArray.index(ip)
        #attempt within timeout time
        if(currentTime <= ipTimeBetween[i]):
            ipAttemptCount[i] = ipAttemptCount[i] + 1
            ipTimeBetween[i] = currentTime + timeout
            if(ipAttemptCount[i] >= maxattempts):
                #create iptables rule and apply
                #add timer to turn it back off with ip to reference
                ipLockArray.append(ip)
                ipLockEnd.append(time.time() + locktime)
                rule = "iptables -A INPUT -s " + ip + " -j DROP" 
                os.system(rule)
                print("blocking ip " + ip + " for " + str(locktime) + " seconds. Time: " + str(time.time()))
        #attempt outside timeout time, currentTime > ipTimeBetween
        else:
            ipAttemptCount[i] = 1
            ipTimeBetween[i] = currentTime + timeout
    #not in list yet
    if(inArray == 0):
        ipArray.append(ip)
        ipAttemptCount.append(1)
        ipTimeBetween.append(currentTime + timeout)

#--------------------------------------------------------------------------
 # FUNCTION:       ipMain
 #
 # DATE:           February 21, 2021
 #
 # REVISIONS:      N/A (Date and explanation of revisions if applicable)
 #
 # DESIGNER:       Kevin Lo
 #
 # PROGRAMMER:     Kevin Lo
 #
 # INTERFACE:      void ipMain(newline, savelog, ipArray, ipAttemptCount, ipTimeBetween, ipLockArray, ipLockEnd, timeout, locktime, maxattempts)
 #                      newline: The incoming newline from the /var/log/secure file
 #                      savelog: The filename to save the the revelant failed password entries to
 #                      ipArray: The array containing the IP addresses who have recently failed passwords
 #                      ipAttemptCount: The array containing the attempt count of IPs that have failed passwords
 #                      ipTimeBetween: The array containing the maximum time limit between password failure attempts for an IP
 #                      ipLockArray: The array containing the ip address of blocked IPs
 #                      ipLockEnd: The array containing the time to unblock a blocked IPs
 #                      timeout: The maximum time in seconds between failed password attempts before a attempt records are purged, eg 10sec, after 10 seconds
 #                               the attempt count will be reset back to 0
 #                      locktime: The time duration to block an ip in seconds, locktime=0 is blocked forever
 #                      maxattempts: Maximum number of failed password attempts before the IP is blocked
 #
 # RETURNS:        void
 #
 # NOTES:
 # The main checker for checking the newline and seeing if its a failed password notification and then passing
 # it to ipAdder to process to add to the arrays or block
 # -----------------------------------------------------------------------
def ipMain(newline, savelog, ipArray, ipAttemptCount, ipTimeBetween, ipLockArray, ipLockEnd, timeout, locktime, maxattempts):
    if(newline != ''): 
        if((newline.find("Failed password for") != -1) or (newline.find("FAILED LOGIN") != -1)):
            #do failed password stuff
            filewrite = open(savelog, "a")
            filewrite.write(newline) #save the failed password line to file
            filewrite.close()
            print(newline.rstrip("\n"))
            ip = re.findall(r'[0-9]+(?:\.[0-9]+){3}', newline)
            ipAdder(ip[0], ipArray, ipAttemptCount, ipTimeBetween, ipLockArray, ipLockEnd, timeout, locktime, maxattempts)
            #print("Failed password attempt from " + ip[0])

#--------------------------------------------------------------------------
 # FUNCTION:       ipTimeCheck
 #
 # DATE:           February 21, 2021
 #
 # REVISIONS:      N/A (Date and explanation of revisions if applicable)
 #
 # DESIGNER:       Kevin Lo
 #
 # PROGRAMMER:     Kevin Lo
 #
 # INTERFACE:      void ipTimeCheck(ipArray, ipAttemptCount, ipTimeBetween)
 #                      ipArray: The array containing the IP addresses who have recently failed passwords
 #                      ipAttemptCount: The array containing the attempt count of IPs that have failed passwords
 #                      ipTimeBetween: The array containing the maximum time limit between password failure attempts for an IP
 #
 # RETURNS:        void
 #
 # NOTES:
 # The checker to see if any of the IP's timeout counter for between passwords attempts has expired
 # remove from arrays if the timer has expired
 # -----------------------------------------------------------------------                
def ipTimeCheck(ipArray, ipAttemptCount, ipTimeBetween):
    for i in range(len(ipTimeBetween)):
        #remove the ip and values from the arrays if exceeded the time limit between
        if(ipTimeBetween[i] <= time.time()):
            ipArray.pop(i)
            ipAttemptCount.pop(i)
            ipTimeBetween.pop(i)
          
#--------------------------------------------------------------------------
 # FUNCTION:       ipBlockCheck
 #
 # DATE:           February 21, 2021
 #
 # REVISIONS:      N/A (Date and explanation of revisions if applicable)
 #
 # DESIGNER:       Kevin Lo
 #
 # PROGRAMMER:     Kevin Lo
 #
 # INTERFACE:      void ipBlockCheck(ipLockArray, ipLockEnd, locktime)
 #                      ipLockArray: The array containing the ip address of blocked IPs
 #                      ipLockEnd: The array containing the time to unblock a blocked IPs
 #                      locktime: The time duration to block an ip in seconds, locktime=0 is blocked forever
 #
 # RETURNS:        void
 #
 # NOTES:
 # The checker to see if the blocked IP's block timer has expired
 # remove and unblock the ip when the timer has expired
 # -----------------------------------------------------------------------
def ipBlockCheck(ipLockArray, ipLockEnd, locktime):
    if(locktime != 0):
        for i in range(len(ipLockEnd)):
            if(time.time() >= ipLockEnd[i]): #lock time has expired
                rule = "iptables -D INPUT -s " + ipLockArray[i] + " -j DROP" 
                os.system(rule)
                print("unblocking ip " + ipLockArray[i] + " Time: " + str(time.time()))
                ipLockArray.pop(i)
                ipLockEnd.pop(i)

#--------------------------------------------------------------------------
 # FUNCTION:       mainloop
 #
 # DATE:           February 21, 2021
 #
 # REVISIONS:      N/A (Date and explanation of revisions if applicable)
 #
 # DESIGNER:       Kevin Lo
 #
 # PROGRAMMER:     Kevin Lo
 #
 # INTERFACE:      void mainloop(filein, savelog, ipArray, ipAttemptCount, ipTimeBetween, ipLockArray, ipLockEnd, timeout, locktime, maxattempts)
 #                      filein: The /var/log/secure file to monitor for failed password entries
 #                      savelog: The filename to save the the revelant failed password entries to
 #                      ipArray: The array containing the IP addresses who have recently failed passwords
 #                      ipAttemptCount: The array containing the attempt count of IPs that have failed passwords
 #                      ipTimeBetween: The array containing the maximum time limit between password failure attempts for an IP
 #                      ipLockArray: The array containing the ip address of blocked IPs
 #                      ipLockEnd: The array containing the time to unblock a blocked IPs
 #                      timeout: The maximum time in seconds between failed password attempts before a attempt records are purged, eg 10sec, after 10 seconds
 #                               the attempt count will be reset back to 0
 #                      locktime: The time duration to block an ip in seconds, locktime=0 is blocked forever
 #                      maxattempts: Maximum number of failed password attempts before the IP is blocked
 #
 # RETURNS:        void
 #
 # NOTES:
 # The main loop to run the ipblocker python program
 # -----------------------------------------------------------------------
def mainloop(filein, savelog, ipArray, ipAttemptCount, ipTimeBetween, ipLockArray, ipLockEnd, timeout, locktime, maxattempts):
    readfile = open(filein, 'r')

    #read until current
    while True:
        newline = readfile.readline()
        if(newline == ''): 
            break
    #this will read all the new text
    while True:
        newline = readfile.readline()
        ipMain(newline, savelog, ipArray, ipAttemptCount, ipTimeBetween, ipLockArray, ipLockEnd, timeout, locktime, maxattempts)
        ipTimeCheck(ipArray, ipAttemptCount, ipTimeBetween)
        ipBlockCheck(ipLockArray, ipLockEnd, locktime)
    
    readfile.close()

#--------------------------------------------------------------------------
 # FUNCTION:       main
 #
 # DATE:           February 21, 2021
 #
 # REVISIONS:      N/A (Date and explanation of revisions if applicable)
 #
 # DESIGNER:       Kevin Lo
 #
 # PROGRAMMER:     Kevin Lo
 #
 # INTERFACE:      void main()
 #
 # RETURNS:        void
 #
 # NOTES:
 # The main to run the program
 # -----------------------------------------------------------------------
def main():
    ipArray = []
    ipAttemptCount = []
    ipTimeBetween = []
    
    ipLockArray = []
    ipLockEnd = []
    
    config = configparser.ConfigParser()
    config.read('ipblocker.config')
    
    securelog = config.get('default', 'securelog')
    savelog = config.get('default', 'savelog')
    
    timeout = int(config.get('default', 'timeout'))
    locktime = int(config.get('default', 'locktime'))
    maxattempts = int(config.get('default', 'maxattempts'))

    print("Running IP blocker")
    print("Reading from: " + securelog)
    print("Saving entries to: " + savelog)
    print("Timeout: " + str(timeout) + " seconds")
    print("Lock Time: " + str(locktime) + " seconds")
    print("Maximum Attempts: " + str(maxattempts))
    
    mainloop(securelog, savelog, ipArray, ipAttemptCount, ipTimeBetween, ipLockArray, ipLockEnd, timeout, locktime, maxattempts)

main()

#rule = "iptables -A INPUT -s " + ip[0] + " -j DROP" 
#rule = "iptables -A INPUT -s " + ip[0] + " -j DROP" 