# Copyright (c) 1998-2007, Purdue University
# All rights reserved.
#
# Redistribution and use in source and binary forms are permitted provided
# that:
#
# (1) source distributions retain this entire copyright notice and comment,
#     and
# (2) distributions including binaries display the following acknowledgement:
#
#        "This product includes software developed by Purdue University."
#
#     in the documentation or other materials provided with the distribution
#     and in all advertising materials mentioning features or use of this
#     software.
#
# The name of the University may not be used to endorse or promote products
# derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED "AS IS" AND WITHOUT ANY EXPRESS OR IMPLIED
# WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
#
# This software was developed by:
#    Curtis Smith
#
#    Purdue University
#    Engineering Computer Network
#    465 Northwestern Avenue
#    West Lafayette, Indiana 47907-2035 U.S.A.
#
# Send all comments, suggestions, or bug reports to:
#    software@ecn.purdue.edu

CFLAGS=/W3 /nologo /Zi

SYS_LIB=advapi32.lib wsock32.lib dhcpcsvc.lib iphlpapi.lib user32.lib
OFILES=check.obj eventlog.obj getopt.obj log.obj loop.obj main.obj registry.obj service.obj support.obj syslog.obj winevent.obj wsock.obj dhcp.obj

all:		evtsys.exe evtsys.dll

evtsys.exe:	$(OFILES) verexe.res
		link /INCREMENTAL:NO /DEBUG /OPT:REF /OPT:ICF /RELEASE /map:evtsys.map /DELAYLOAD:wevtapi.dll /out:evtsys.exe $(OFILES) verexe.res $(SYS_LIB)

check.obj:	check.c
		cl $(CFLAGS) /c /MT check.c

dhcp.obj:	dhcp.c
		cl $(CFLAGS) /c /MT dhcp.c

eventlog.obj:	eventlog.c
		cl $(CFLAGS) /c /MT eventlog.c

getopt.obj:	getopt.c
		cl $(CFLAGS) /c /MT getopt.c

log.obj:	log.c
		cl $(CFLAGS) /c /MT log.c

loop.obj:	loop.c
		cl $(CFLAGS) /c /MT loop.c

main.obj:	main.c
		cl $(CFLAGS) /c /MT main.c

registry.obj:	registry.c
		cl $(CFLAGS) /c /MT registry.c

service.obj:	service.c
		cl $(CFLAGS) /c /MT service.c

support.obj:	support.c
		cl $(CFLAGS) /c /MT support.c

syslog.obj:	syslog.c
		cl $(CFLAGS) /c /MT syslog.c
		
winevent.obj: winevent.c
		cl $(CFLAGS) /c /MT winevent.c

wsock.obj:	wsock.c
		cl $(CFLAGS) /c /MT wsock.c

verexe.res:	ver.rc
		rc /r /n /fo verexe.res ver.rc

evtsys.dll:	dllmain.obj dllmsg.res verdll.res
		link /dll /out:evtsys.dll dllmain.obj dllmsg.res verdll.res

dllmain.obj:	dllmain.c
		cl $(CFLAGS) /c dllmain.c

dllmsg.rc:	dllmsg.mc
		mc dllmsg.mc

dllmsg.res:	dllmsg.rc
		rc /r dllmsg.rc

verdll.res:	ver.rc
		rc /r /dVERDLL /n /fo verdll.res ver.rc

clean:
		-del evtsys.exe
		-del evtsys.dll
		-del evtsys.map
		-del dllmsg.rc
		-del dllmsg.h
		-del msg00001.bin
		-del evtsys.pdb
		-del vc100.pdb
		-del *.res
		-del *.obj

check.c:	main.h
check.c:	check.h
check.c:	log.h
check.c:	syslog.h
dhcp.c:		main.h
dhcp.c:		dhcp.h
dhcp.c:		log.h
dhcp.c:		syslog.h
eventlog.c:	main.h
eventlog.c:	check.h
eventlog.c:	eventlog.h
eventlog.c:	log.h
eventlog.c:	service.h
eventlog.c:	syslog.h
getopt.c:	main.h
getopt.c:	log.h
getopt.c:	getopt.h
log.c:		main.h
log.c:		log.h
log.c:		syslog.h
log.c:		wsock.h
loop.c:		main.h
loop.c:		eventlog.h
loop.c:		log.h
loop.c:		service.h
loop.c:		syslog.h
loop.c:		ver.h
main.c:		main.h
main.c:		check.h
main.c:		eventlog.h
main.c:		log.h
main.c:		syslog.h
main.c:		getopt.h
main.c:		wsock.h
registry.c:	main.h
registry.c:	log.h
registry.c:	syslog.h
registry.c:	eventlog.h
service.c:	main.h
service.c:	log.h
support.c:	main.h
support.c:	log.h
support.c:	syslog.h
syslog.c:   dhcp.h
syslog.c:	main.h
syslog.c:	syslog.h
syslog.c:	wsock.h
ver.rc:		ver.h
winevent.c: main.h
winevent.c: log.h
winevent.c: winevent.h
wsock.c:	main.h
wsock.c:	log.h
wsock.c:	syslog.h
wsock.c:	dhcp.h
wsock.c:	wsock.h