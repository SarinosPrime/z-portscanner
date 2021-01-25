#include <WinSock2.h>
#pragma comment(lib, "ws2_32.lib")
#include <socketapi.h>
#include <netioapi.h>
#include <stdio.h> 
#include <stdlib.h> 
#include <string>
#include <string.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <errno.h>

int threadsCount;
int totalLines;
std::ofstream targetsOutputFileW;

int sockfd;
bool cont = true;

int totalAttempts;
int numOfTargetsSuccess;
int numOfTargetsFailed;
int numOfExitedThreads;

typedef struct ZPortScanStruct
{
	int sockfd;
	ULONG blockMode;
	const char *fileName;
	int listStartLine;
	int listEndLine;
	int port;
	struct sockaddr_in target_addr;
	fd_set setE, setW;
	timeval timeout;
	char errorReporting = 0;
	int errorLenght = 0;
} *PRDPScan;

ZPortScanStruct zpsi[600];