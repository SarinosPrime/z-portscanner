#include "ZPortScan.h"
/*

https://www.github.com/SarinosPrime/z-portscanner

*/

void UpdateStatus()
{
	while (cont)
	{
		if (numOfExitedThreads >= threadsCount)
			cont = false;
		system("cls");
		printf("Total connections made: %d\n", totalAttempts);
		printf("Total successfull connections: %d\n", numOfTargetsSuccess);
		printf("Total negative connections: %d\n", numOfTargetsFailed);
		Sleep(1000);
	}
}

void RestoreSocketFD(ZPortScanStruct *zpsThreadProto)
{
	closesocket(zpsThreadProto->sockfd);

	if ((zpsThreadProto->sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		printf("[1] Error on restoring socket file descriptor state: %s\n", strerror(errno));
		WSACleanup();
		system("pause");
	}

	u_long blockMode = 1;
	if (ioctlsocket(zpsThreadProto->sockfd, FIONBIO, &zpsThreadProto->blockMode) == SOCKET_ERROR) // Put socket in non-blocking mode
	{
		printf("[2] Error on restoring socket file descriptor state: %s\n", strerror(errno));
		WSACleanup();
		system("pause");
	}
}

void MainThreads(ZPortScanStruct * zpsThreadProto)
{
	int linesCount = 0;
	bool continueOp = false;
	std::string targetIP;

	std::ifstream listsFileR;
	listsFileR.open(zpsThreadProto->fileName, std::ios::in);

	if (!listsFileR.good())
	{
		system("pause");
	}

	while (std::getline(listsFileR, targetIP))
	{
		bool failed = false;

		if (linesCount == zpsThreadProto->listStartLine)
			continueOp = true;
		if (linesCount >= zpsThreadProto->listEndLine)
		{
			continueOp = false;
			break;
		}

		if (continueOp)
		{
			const char* targetIP_c = targetIP.c_str();

			zpsThreadProto->target_addr.sin_family = AF_INET;
			zpsThreadProto->target_addr.sin_addr.S_un.S_addr = inet_addr(targetIP_c);
			zpsThreadProto->target_addr.sin_port = htons(zpsThreadProto->port);

			failed = false;

			if (connect(sockfd, (struct sockaddr*)&zpsThreadProto->target_addr, sizeof(struct sockaddr)) == SOCKET_ERROR)
			{
				// If you don't put socket in non-blocking mode this point of codes will never reached until connect() return success/failed.
				if (!failed)
				{
					// Connection Still In Progress

					FD_ZERO(&zpsThreadProto->setW);
					FD_SET(zpsThreadProto->sockfd, &zpsThreadProto->setW);
					FD_ZERO(&zpsThreadProto->setE);
					FD_SET(zpsThreadProto->sockfd, &zpsThreadProto->setE);

					int ret = select(0, NULL, &zpsThreadProto->setW, &zpsThreadProto->setE, &zpsThreadProto->timeout);
					if (ret <= 0)
					{
						// Connection Timed Out
						if (ret == 0)
							WSASetLastError(WSAETIMEDOUT);
						numOfTargetsFailed++;
						failed = true;
					}

					if (FD_ISSET(zpsThreadProto->sockfd, &zpsThreadProto->setE) && !failed)
					{
						// Connection Failed
						getsockopt(zpsThreadProto->sockfd, SOL_SOCKET, SO_ERROR, &zpsThreadProto->errorReporting, &zpsThreadProto->errorLenght);
						WSASetLastError(zpsThreadProto->errorReporting);
						numOfTargetsFailed++;
						failed = true;
					}
				}
			}
			if (!failed)
			{
				numOfTargetsSuccess++;
				targetsOutputFileW << targetIP_c << ":3389" << std::endl;
				RestoreSocketFD(zpsThreadProto); // Restore sockfd state so we will able to connect again using the same socket file descriptor
			}

			totalAttempts++;
		}
		linesCount++;
	}

	numOfExitedThreads++;
}

int main(int argc, char *argv[])
{
	// Use GetLastError() instead of errno if you get "Unknown error" in errors description.

	WSADATA wsa;
	if (WSAStartup(0x101, &wsa) != 0)
	{
		printf("Error on startup: %s\n", strerror(errno));
		exit(errno);
	}

	int timeout, port;

	std::stringstream threadsCountIntP(argv[1]), timeoutIntP(argv[2]), portIntP(argv[3]);
	threadsCountIntP >> threadsCount;
	timeoutIntP >> timeout;
	portIntP >> port;
	const char *listFile = argv[4];

	std::ifstream listsFileR;
	listsFileR.open((const char*)listFile, std::ios::in);
	targetsOutputFileW.open("valid_targets.txt", std::ios::out);

	if (listsFileR.good() && targetsOutputFileW.good())
		printf("Files open success, reading file...\n");
	else
	{
		printf("Failed to open file: %s\n", listFile);
		system("pause");
	}

	std::string line;
	while (std::getline(listsFileR, line))
		totalLines++;
	
	std::getline(listsFileR, line).clear();
	printf("File %s has total lines of %d\n", listFile, totalLines);

	int latestFileLineStart = 0;
	int linesPerThread = totalLines / threadsCount;

	// You free to increase the max allowed ip's to scan, more RAM will be used.
	if (threadsCount > totalLines)
	{
		printf("Threads count can't be bigger than %s total lines!\n", listFile);
		system("pause");
	}

	printf("IPs per thread: %d\n", linesPerThread);

	for (int i = 0; i < threadsCount; i++)
	{
		zpsi[i] = {};
		memset(&zpsi[i], 0x00, sizeof(ZPortScanStruct));

		zpsi[i].fileName = listFile;

		if (latestFileLineStart == 0)
		{
			zpsi[i].listStartLine = 0;
			zpsi[i].listEndLine = linesPerThread;
			latestFileLineStart = zpsi[i].listEndLine;
		}
		else
		{
			zpsi[i].listStartLine = latestFileLineStart;
			zpsi[i].listEndLine = zpsi[i].listStartLine + linesPerThread;
			latestFileLineStart = zpsi[i].listEndLine;
		}

		zpsi[i].timeout = {};
		zpsi[i].timeout.tv_sec = timeout;
		zpsi[i].timeout.tv_usec = 0;

		zpsi[i].port = port;

		if ((zpsi[i].sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		{
			printf("[1] Error: %s\n", strerror(errno));
			WSACleanup();
			system("pause");
		}

		if (ioctlsocket(zpsi[i].sockfd, FIONBIO, &zpsi[i].blockMode) == SOCKET_ERROR) // Put socket in non-blocking mode, so connect() will no more pause the thread until connection complete.
		{
			printf("[2] Error: %s\n", strerror(errno));
			WSACleanup();
			system("pause");
		}

		CreateThread(0, 0, (LPTHREAD_START_ROUTINE)MainThreads, &zpsi[i], 0, 0);
	}

	CreateThread(0, 0, (LPTHREAD_START_ROUTINE)UpdateStatus, 0, 0, 0);

	while (cont) // This loop will hold the window until all threads exit
	{
		Sleep(90); // Increase this value if you fill there is more CPU Usage than it's should be
	}

	listsFileR.close();
	targetsOutputFileW.close();

	WSACleanup();

	printf("\nOperation Complete.\n");

	system("pause >nul");
	return 0;
}