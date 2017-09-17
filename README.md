# wannakill
This script was designed to stop the spread of wannacry on infected systems across the network.
The goal was to not only remove the wannacry infection but also leave the device in a non-vulnerable state.

# What it is:

A Metasploit resource script designed to 

kill wannacry task mssecsvc.exe

deletes C:\Windows\mssecsvc.exe

deletes C:\Windows\tasksche.exe

Disables smbv1 using powershell


# How to use the script:

  Copy the *.rc files into the same directory you are running msfconsole from.

Cd /opt/metasploit-framework/

./msfconsole

resource configEB.rc

Set rhost x.x.x.x (this is where you insert the IP address of the infected host)

exploit

resource wannakill.rc  (if you are seeing errors loading powershell try wannakill2.rc instead) 
  

You will get a message if stopping the mssecsvc.exe was successful or if it is not found.

You will NOT receive any messages if deleting the files was successful.

Repeat as neccessary, this has worked great in my lab environment.  

Please do not use this against computer that does not belong to you.


# How can this be better?:

Wannakill.rb - post module, work in progress....

Automating set rhost x.x.x.x using rc files works as well with a little VIM magic

Advice and feedback appreciated.





