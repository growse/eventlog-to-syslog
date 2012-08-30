/*
  This code is a modification of the original Eventlog to Syslog Script written by
  Curtis Smith of Purdue University. The original copyright notice can be found below.
  
  The original program was modified by Sherwin Faria for Rochester Institute of Technology
  in July 2009 to provide bug fixes and add several new features. Additions include
  the ability to ignore specific events, add the event timestamp to outgoing messages,
  a service status file, and compatibility with the new Vista/2k8 Windows Events service.

     Sherwin Faria
	 Rochester Institute of Technology
	 Information & Technology Services Bldg. 10
	 1 Lomb Memorial Drive
	 Rochester, NY 14623 U.S.A.
	 
	Send all comments, suggestions, or bug reports to:
		sherwin.faria@gmail.com
*/
 
/*
  Copyright (c) 1998-2007, Purdue University
  All rights reserved.

  Redistribution and use in source and binary forms are permitted provided
  that:

  (1) source distributions retain this entire copyright notice and comment,
      and
  (2) distributions including binaries display the following acknowledgement:

         "This product includes software developed by Purdue University."

      in the documentation or other materials provided with the distribution
      and in all advertising materials mentioning features or use of this
      software.

  The name of the University may not be used to endorse or promote products
  derived from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED "AS IS" AND WITHOUT ANY EXPRESS OR IMPLIED
  WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
  MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.

  This software was developed by:
     Curtis Smith

     Purdue University
     Engineering Computer Network
     465 Northwestern Avenue
     West Lafayette, Indiana 47907-2035 U.S.A.

  Send all comments, suggestions, or bug reports to:
     software@ecn.purdue.edu

*/

/* Include files */
#include "main.h"
#include "eventlog.h"
#include "log.h"
#include "syslog.h"
#include "getopt.h"
#include "ver.h"
#include "check.h"
#include "winevent.h"
#include "wsock.h"

/* Main program */

/* Program variables */
static BOOL ProgramDebug = FALSE;
static BOOL ProgramInstall = FALSE;
static BOOL ProgramUninstall = FALSE;
static BOOL ProgramIncludeOnly = FALSE;
static char * ProgramName;
static char * ProgramSyslogFacility = NULL;
static char * ProgramSyslogLogHost = NULL;
static char * ProgramSyslogLogHost2 = NULL;
static char * ProgramSyslogPort = NULL;
static char * ProgramSyslogQueryDhcp = NULL;
static char * ProgramSyslogInterval = NULL;
static char * ProgramSyslogTag = NULL;
static char * ProgramLogLevel = NULL;
static EventList IgnoredEvents[MAX_IGNORED_EVENTS];

/* Operate on program flags */
static int mainOperateFlags()
{
	int status = 0;

	/* Install new service */
	if (ProgramInstall) {

		/* Install registry */
		if (RegistryInstall())
			return 1;

		/* Install service */
		if (ServiceInstall())
			return 1;

		/* Success */
		return 0;
	}

	/* Uninstall service */
	if (ProgramUninstall) {

		/* Remove service */
		if (ServiceRemove())
			status = 1;

		/* Remove registry settings */
		if (RegistryUninstall())
			status = 1;

		/* Return status */
		return status;
	}

	/* Load the current registry keys */
	if (RegistryRead())
		return 1;

    /* Open Syslog Connections */
    if(SyslogOpen())
        return 1;

	/* If in debug mode, call main loop directly */
	if (ProgramDebug)
		status = MainLoop();
	else
		/* Otherwise, start service dispatcher, that will eventually call MainLoop */
		status = ServiceStart();

	/* Close syslog connections */
	SyslogClose();

	/* Return status */
	return status;
}

/* Program usage information */
static void mainUsage()
{
	if (LogInteractive) {
		fprintf(stderr, "Version: %s (%s-bit)\n", VERSION,
#ifdef _WIN64
			"64"
#else
			"32"
#endif
		);
		fprintf(stderr, "Usage: %s -i|-u|-d [-h host] [-b host] [-f facility] [-p port]\n", ProgramName);
		fputs("       [-t tag] [-s minutes] [-l level] [-n]\n", stderr);
		fputs("  -i           Install service\n", stderr);
		fputs("  -u           Uninstall service\n", stderr);
		fputs("  -d           Debug: run as console program\n", stderr);
		fputs("  -h host      Name of log host\n", stderr);
		fputs("  -b host      Name of secondary log host\n", stderr);
		fputs("  -f facility  Facility level of syslog message\n", stderr);
		fputs("  -l level     Minimum level to send to syslog.\n", stderr);
		fputs("               0=All/Verbose, 1=Critical, 2=Error, 3=Warning, 4=Info\n", stderr);
		fputs("  -n           Include only those events specified in the config file.\n", stderr);
		fputs("  -p port      Port number of syslogd\n", stderr);
		fputs("  -q bool      Query the Dhcp server to obtain the syslog/port to log to\n", stderr);
		fputs("               (0/1 = disable/enable)\n", stderr);
		fputs("  -t tag       Include tag as program field in syslog message.\n", stderr);
		fputs("  -s minutes   Optional interval between status messages. 0 = Disabled\n", stderr);
		fputc('\n', stderr);
		fprintf(stderr, "Default port: %u\n", SYSLOG_DEF_PORT);
		fprintf(stderr, "Default facility: %s\n", SYSLOG_DEF_FAC_NAME);
		fprintf(stderr, "Default status interval: %u\n", SYSLOG_DEF_INTERVAL);
		fputs("Host (-h) required if installing.\n", stderr);
	} else
		Log(LOG_ERROR, "Invalid flag usage; Check startup parameters");
}

/* Process flags */
static int mainProcessFlags(int argc, char ** argv)
{
	int flag;

	/* Note all actions */
	while ((flag = GetOpt(argc, argv, "f:iudh:b:p:q:s:l:nt:")) != EOF) {
		switch (flag) {
			case 'd':
				ProgramDebug = TRUE;
				break;
			case 'f':
				ProgramSyslogFacility = GetOptArg;
				break;
			case 'h':
				ProgramSyslogLogHost = GetOptArg;
				break;
			case 'b':
				ProgramSyslogLogHost2 = GetOptArg;
				break;
			case 'i':
				ProgramInstall = TRUE;
				break;
			case 'p':
				ProgramSyslogPort = GetOptArg;
				break;
			case 'q':
				ProgramSyslogQueryDhcp = GetOptArg;
				break;
			case 's':
				ProgramSyslogInterval = GetOptArg;
				break;
			case 'u':
				ProgramUninstall = TRUE;
				break;
			case 'l':
				ProgramLogLevel = GetOptArg;
				break;
			case 'n':
				ProgramIncludeOnly = TRUE;
				break;
			case 't':
				ProgramSyslogTag = GetOptArg;
				break;
			default:
				mainUsage();
				return 1;
		}
	}
	argc -= GetOptInd;
	argv += GetOptInd;
	if (argc) {
		mainUsage();
		return 1;
	}

	/* Must have only one of */
	if (ProgramInstall + ProgramUninstall + ProgramDebug > 1) {
		Log(LOG_ERROR, "Pass only one of -i, -u or -d");
		return 1;
	}

	/* If installing, must have a log host */
	if (ProgramInstall && ProgramSyslogLogHost == NULL) {
		Log(LOG_ERROR, "Syslogd host name (-h) flag required");
		return 1;
	}

	/* Must have a primary if specifying a secondary host */
	if (ProgramSyslogLogHost2 && ProgramSyslogLogHost == NULL) {
		Log(LOG_ERROR, "Syslogd primary host (-h) flag required");
		return 1;
	}

	/* Check arguments */
	if (ProgramSyslogLogHost) {
		if (CheckSyslogLogHost(ProgramSyslogLogHost, 1))
			return 1;
	}
	if (ProgramSyslogLogHost2) {
		if (CheckSyslogLogHost(ProgramSyslogLogHost2, 2))
			return 1;
	}
	if (ProgramSyslogFacility) {
		if (CheckSyslogFacility(ProgramSyslogFacility))
			return 1;
	}
	if (ProgramSyslogPort) {
		if (CheckSyslogPort(ProgramSyslogPort))
			return 1;
	}
	if (ProgramSyslogInterval) {
		if (CheckSyslogInterval(ProgramSyslogInterval))
			return 1;
	}
	if (ProgramSyslogQueryDhcp) {
		if (CheckSyslogQueryDhcp(ProgramSyslogQueryDhcp))
			return 1;
	}
	if (ProgramLogLevel) {
		if (CheckSyslogLogLevel(ProgramLogLevel))
			return 1;
	}
	if (ProgramIncludeOnly)
		CheckSyslogIncludeOnly();

	if(ProgramSyslogTag)
		if(CheckSyslogTag(ProgramSyslogTag))
			return 1;

	/* Check for Ignore File */
	if(LogInteractive)
		printf("Checking ignore file...\n");
	if(CheckSyslogIgnoreFile(IgnoredEvents, CONFIG_FILE) != 0) {
		Log(LOG_ERROR, "File Check Failed!!!");
		return 1;
	}

	/* Proceed to do operation */
	return mainOperateFlags();
}

/* Main program */
int main(int argc, char ** argv)
{
	int status;

    SetConsoleCtrlHandler(ShutdownConsole, TRUE);

	/* Save program name */
	ProgramName = argv[0];

	/* Start eventlog */
	if (LogStart()) {
		return 1;
	} else {

		/* Start the network */
		if (WSockStart() == 0) {

			/* Process flags */
			status = mainProcessFlags(argc, argv);

			/* Stop network if needed */
			WSockStop();
		}
	}

	/* Show status */
	if (LogInteractive) {
		if (status)
			puts("Command did not complete due to a failure");
		else
			puts("Command completed successfully");
	}

	/* Stop event logging */
	LogStop();

	/* Success */
	return status;
}

/* Shut down the console cleanly */
BOOL WINAPI ShutdownConsole(DWORD dwCtrlType)
{
    Log(LOG_INFO, "Signal caught, shutting down and exiting...");
    switch(dwCtrlType)
    {
        case CTRL_C_EVENT:
        case CTRL_BREAK_EVENT:
        case CTRL_CLOSE_EVENT:
            if (CheckForWindowsEvents())
                WinEventCancelSubscribes();
            EventlogsClose();
            SyslogClose();
            break;
        default:
            return FALSE;
    }

    exit(0);
}