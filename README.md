# noMimikatz
This is a simple client (post exploitation) to send IRP to the mimidrv.sys driver without using mimikatz.

The mimidrv.sys driver is integrated. Administrator rights are required to install it (post exploitation)

We can choose between invoking the BSOD functionality (IRP Code 0x002) or assigning the token to each open cmd.exe and powershell.exe process
System (IRP Code 0x011).

![alt text](https://github.com/dottorvenom/noMimikatz/blob/main/img/1.PNG)

You can integrate other IRP code by referring to
'''
https://github.com/gentilkiwi/mimikatz/blob/master/mimidrv/ioctl.h
'''

Example of token assigned to the cmd.exe process

