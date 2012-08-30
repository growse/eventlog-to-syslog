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
#include "log.h"
#include "syslog.h"
#include "check.h"

int IGNORED_LINES;

/* Facility conversion table */
static struct {
	char * name;
	int id;
} FacilityTable[] = {
	{ "auth", SYSLOG_AUTH },
	{ "authpriv", SYSLOG_AUTHPRIV },
	{ "cron", SYSLOG_CRON },
	{ "daemon", SYSLOG_DAEMON },
	{ "ftp", SYSLOG_FTP },
	{ "kern", SYSLOG_KERN },
	{ "local0", SYSLOG_LOCAL0 },
	{ "local1", SYSLOG_LOCAL1 },
	{ "local2", SYSLOG_LOCAL2 },
	{ "local3", SYSLOG_LOCAL3 },
	{ "local4", SYSLOG_LOCAL4 },
	{ "local5", SYSLOG_LOCAL5 },
	{ "local6", SYSLOG_LOCAL6 },
	{ "local7", SYSLOG_LOCAL7 },
	{ "lpr", SYSLOG_LPR },
	{ "mail", SYSLOG_MAIL },
	{ "news", SYSLOG_NEWS },
	{ "ntp", SYSLOG_NTP },
	{ "security", SYSLOG_SECURITY },
	{ "user", SYSLOG_USER },
	{ "uucp", SYSLOG_UUCP }
};

/* Check the minimum log level */
int CheckSyslogLogLevel(char * level)
{
	DWORD LogLevel;

	/* Convert interval to integer */
	LogLevel = atoi(level);

	/* Check for valid number */
	if (LogLevel < MIN_LOG_LEVEL || LogLevel > MAX_LOG_LEVEL) {
		Log(LOG_ERROR, "Bad level: %s \nMust be between %i and %i", level, MIN_LOG_LEVEL, MAX_LOG_LEVEL);
		return 1;
	}

	/* Store new value */
	SyslogLogLevel = LogLevel;

	/* Success */
	return 0;
}

/* Check facility name */
int CheckSyslogFacility(char * facility)
{
	int i;

	/* Try looking up name */
	for (i = 0; i < COUNT_OF(FacilityTable); i++)
		if (_stricmp(FacilityTable[i].name, facility) == 0)
			break;
	if (i == COUNT_OF(FacilityTable)) {
		Log(LOG_ERROR, "Invalid facility name: \"%s\"", facility);
		return 1;
	}

	/* Store new value */
	SyslogFacility = FacilityTable[i].id;

	/* Success */
	return 0;
}

/* Check port number */
int CheckSyslogPort(char * port)
{
	DWORD value;
	char * eos;
	struct servent * service;

	/* Try converting to integer */
	value = strtoul(port, &eos, 10);
	if (eos == port || *eos != '\0') {

		/* Try looking up name */
		service = getservbyname(port, "udp");
		if (service == NULL) {
			Log(LOG_ERROR, "Invalid service name: \"%s\"", port);
			return 1;
		}

		/* Convert back to host order */
		value = ntohs(service->s_port);
	} else {

		/* Check for valid number */
		if (value <= 0 || value > 0xffff) {
			Log(LOG_ERROR, "Invalid service number: %u", value);
			return 1;
		}
	}

	/* Store new value */
	SyslogPort = value;

	/* Success */
	return 0;
}

/* Check log host */
int CheckSyslogLogHost(char * loghostarg, int ID)
{
	char * ipstr = NULL;
    char * loghost = NULL;
    char * next_token = NULL;
    char delim[] = ";";

    /* Store new value */
    // Need to clean up the whole host storage mechanism
    // so much duplication is unacceptable
    if (ID == 1)
    {
        if (ConvertLogHostToIp(loghostarg, &ipstr) == 0)
	        strncpy_s(SyslogLogHost1, sizeof(SyslogLogHost1), ipstr, _TRUNCATE);
        else
            return 1;
    }
    else
    {
        loghost = strtok_s(loghostarg, delim, &next_token);
        if (loghost && ConvertLogHostToIp(loghost, &ipstr) == 0)
	        strncpy_s(SyslogLogHost2, sizeof(SyslogLogHost2), ipstr, _TRUNCATE);
        else
            return 1;

        loghost = strtok_s(NULL, delim, &next_token);
        if (loghost)
        {
            if (ConvertLogHostToIp(loghost, &ipstr) == 0)
	            strncpy_s(SyslogLogHost3, sizeof(SyslogLogHost3), ipstr, _TRUNCATE);
            else
                return 1;
        }

        loghost = strtok_s(NULL, delim, &next_token);
        if (loghost)
        {
            if (ConvertLogHostToIp(loghost, &ipstr) == 0)
	            strncpy_s(SyslogLogHost4, sizeof(SyslogLogHost4), ipstr, _TRUNCATE);
            else
                return 1;
        }
    }

	/* Success */
	return 0;
}

/* Check ignore file */
int CheckSyslogIgnoreFile(EventList * ignore_list, char * filename)
{
	FILE *file;
	fopen_s(&file, filename, "r");

	if (file != NULL)
	{
		char line[100];
		char strDelim[] = ":";
		char strComment[] = "'";
		char *strID,
			 *strSource,
			 *next_token;
		int comments = 1;
		int i = 0;

		while (fgets(line, sizeof(line), file) != NULL) { /* read a line */
			if (!(strncmp(line, strComment, 1))) {
				comments++;
			}
			else {
				strSource = strtok_s(line, strDelim, &next_token);
				strID = strtok_s(NULL, strDelim, &next_token);
				if (strSource == NULL || strID == NULL) {
					Log(LOG_ERROR,"File format incorrect: %s line: %i", filename, i + comments);
					Log(LOG_ERROR,"Format should be \"EventSource:EventID\" w/o quotes.");
					return -1;
				}

				/* Stop at MAX lines */
				if (i < MAX_IGNORED_EVENTS) {
					if (strID[0] == '*') {
						ignore_list[i].wild = TRUE;
						ignore_list[i].id = 0;
					}
					else {
						ignore_list[i].wild = FALSE;
						ignore_list[i].id = atoi(strID); /* Enter id into array */
					}
					/* Enter source into array */
					strncpy_s(ignore_list[i].source, sizeof(ignore_list[i].source), strSource, _TRUNCATE);

					//if(LogInteractive)
						//printf("IgnoredEvents[%i].id=%i \tIgnoredEvents[%i].source=%s\n",i,ignore_list[i].id,i,ignore_list[i].source);
				} else {
					/* Notify if there are too many lines */
					Log(LOG_ERROR,"Config file too large. Max size is %i lines. Truncating...", MAX_IGNORED_EVENTS);
					break;
				}
				i++;
			}
		}
		fclose (file);
		IGNORED_LINES = i;

	} else {
		Log(LOG_ERROR|LOG_SYS,"Error opening file: %s", filename);
		Log(LOG_INFO,"Creating file with filename: %s", filename);

		if (fopen_s(&file, filename, "w") != 0) {
			Log(LOG_ERROR|LOG_SYS,"File could not be created: %s", filename);
			return -1;
		}

		fprintf_s(file, "'!!!!THIS FILE IS REQUIRED FOR THE SERVICE TO FUNCTION!!!!\n'\n");
		fprintf_s(file, "'Comments must start with an apostrophe and\n");
		fprintf_s(file, "'must be the only thing on that line.\n'\n");
		fprintf_s(file, "'Do not combine comments and definitions on the same line!\n'\n");
		fprintf_s(file, "'Format is as follows - EventSource:EventID\n");
		fprintf_s(file, "'Use * as a wildcard to ignore all ID's from a given source\n");
		fprintf_s(file, "'E.g. Security-Auditing:*\n'\n");
		fprintf_s(file, "'In Vista/2k8 and upwards remove the 'Microsoft-Windows-' prefix\n");
		fprintf_s(file, "'**********************:**************************");

		fclose (file);
	}

	/* Can't run as IncludeOnly with no results set to include */
	if (SyslogIncludeOnly && IGNORED_LINES == 0)
	{
		Log(LOG_ERROR,"You cannot set the IncludeOnly flag and not specify any events to include!");
		return -1;
	}

	/* Success */
	return 0;
}

/* Check Syslog Status Interval */
int CheckSyslogInterval(char * interval)
{
	DWORD minutes;

	/* Convert interval to integer */
	minutes = atoi(interval);

	/* Check for valid number */
	if (minutes < 0 || minutes > 0xffff) {
		Log(LOG_ERROR, "Bad interval: %s \nMust be between 0 and 65,535 minutes", interval);
		return 1;
	}

	/* Store new value */
	SyslogStatusInterval = minutes;

	/* Success */
	return 0;
}

/* Check for DHCP flag */
int CheckSyslogQueryDhcp(char * arg)
{
	DWORD value;

	/* Try converting to integer */
	value = atoi(arg);

	/* Check for valid number */
	if (value < 0 || value > 0xffff) {
		Log(LOG_ERROR, "Invalid boolean value: %s", arg);
		return 1;
	}

	/* Store new value */
	SyslogQueryDhcp = value ? TRUE : FALSE;

	/* Success */
	return 0;
}

/* Check for IncludeOnly flag */
int CheckSyslogIncludeOnly()
{
	/* Store new value */
	SyslogIncludeOnly = TRUE;

	/* Success */
	return 0;
}

int CheckSyslogTag(char * arg)
{
	if(strlen(arg) > sizeof(SyslogTag)-1) {
		Log(LOG_ERROR, "Syslog tag too long: \"%s\"", arg);
		return 1;
	}
	
	SyslogIncludeTag = TRUE;
	strncpy_s(SyslogTag, sizeof(SyslogTag), arg, _TRUNCATE);

	return 0;
}

/* Check for new Crimson Log Service */
int CheckForWindowsEvents()
{
	HKEY hkey = NULL;
    BOOL winEvents = FALSE;

	/* Check if the new Windows Events Service is in use */
	/* If so we will use the new API's to sift through events */
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels\\ForwardedEvents", 0, KEY_READ, &hkey) != ERROR_SUCCESS)
		winEvents = FALSE;
	else
		winEvents = TRUE;
		
	if (hkey)
		RegCloseKey(hkey);

	/* A level of 1 (Critical) is not valid in this process prior
	 * to the new Windows Events. Set level to 2 (Error) */
	if (winEvents == FALSE && SyslogLogLevel == 1)
		SyslogLogLevel = 2;

    return winEvents;
}