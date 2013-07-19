#undef UNICODE

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include "tls.h"
#include "debug.h"

// Need to link with Ws2_32.lib
#pragma comment (lib, "Ws2_32.lib")
// #pragma comment (lib, "Mswsock.lib")

#define DEFAULT_BUFLEN 512
#define DEFAULT_PORT "27015"

bool parseClientHello(char *recvbuf){
	return true;
}

bool generateServerHello(char *sendbuf){
	return true;
}

bool generateServerCertificate(char *sendbuf){
	return true;
}

bool generateServerKeyExchange(char *sendbuf){
	return true;
}

bool generateServerHelloDone(char *sendbuf){
	return true;
}

bool parseClientKeyExchange(char *recvbuf){
	return true;
}

bool parseClientCertificateVerify(char *recvbuf){
	return true;
}

bool parseClientFinishedMessage(char *recvbuf){
	return true;
}

bool generateServerFinishedMessage(char *sendbuf){
	return true;
}

int __cdecl main(void) 
{
	ServerPhase serverphase;
	bool whileflag;
    WSADATA wsaData;
    int iResult;

    SOCKET ListenSocket = INVALID_SOCKET;
    SOCKET ClientSocket = INVALID_SOCKET;

    struct addrinfo *result = NULL;
    struct addrinfo hints;

    char recvbuf[DEFAULT_BUFLEN];
    int recvbuflen = DEFAULT_BUFLEN;
    char *sendbuf;

    // Initialize Winsock
    iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
    if (iResult != 0) {
        printf("WSAStartup failed with error: %d\n", iResult);
        return 1;
    }

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    // Resolve the server address and port
    iResult = getaddrinfo(NULL, DEFAULT_PORT, &hints, &result);
    if ( iResult != 0 ) {
        printf("getaddrinfo failed with error: %d\n", iResult);
        WSACleanup();
        return 1;
    }

    // Create a SOCKET for connecting to server
    ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (ListenSocket == INVALID_SOCKET) {
        printf("socket failed with error: %ld\n", WSAGetLastError());
        freeaddrinfo(result);
        WSACleanup();
        return 1;
    }

    // Setup the TCP listening socket
    iResult = bind( ListenSocket, result->ai_addr, (int)result->ai_addrlen);
    if (iResult == SOCKET_ERROR) {
        printf("bind failed with error: %d\n", WSAGetLastError());
        freeaddrinfo(result);
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    freeaddrinfo(result);

    iResult = listen(ListenSocket, SOMAXCONN);
    if (iResult == SOCKET_ERROR) {
        printf("listen failed with error: %d\n", WSAGetLastError());
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

	DEBUG("Server Started\n");

    // Accept a client socket
    ClientSocket = accept(ListenSocket, NULL, NULL);
	DEBUG("Get Sth\n");
    if (ClientSocket == INVALID_SOCKET) {
        printf("accept failed with error: %d\n", WSAGetLastError());
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

	DEBUG("Client Binded\n");

	// while loop for tls
	serverphase = TestS;
	whileflag = true;
	while(true){
		switch (serverphase) {
		case TestS: {
			recv(ClientSocket, recvbuf, recvbuflen, 0);
			printf("Test: recv\t%s", recvbuf);
			sendbuf = "Server Test";
			send(ClientSocket, sendbuf, (int)strlen(sendbuf), 0);
			serverphase = ExitS;
			break;
				   }
		case InitialS: {
			recv(ClientSocket, recvbuf, recvbuflen, 0);
			parseClientHello(recvbuf);
			generateServerHello(sendbuf);
			send(ClientSocket, sendbuf, (int)strlen(sendbuf), 0);
			generateServerCertificate(sendbuf);
			send(ClientSocket, sendbuf, (int)strlen(sendbuf), 0);
			generateServerKeyExchange(sendbuf);
			send(ClientSocket, sendbuf, (int)strlen(sendbuf), 0);
			generateServerHelloDone(sendbuf);
			send(ClientSocket, sendbuf, (int)strlen(sendbuf), 0);
			serverphase = HandshakeWaitClientKeyExchange;
			break;
					  }
		case HandshakeWaitClientKeyExchange: {
			recv(ClientSocket, recvbuf, recvbuflen, 0);
			parseClientKeyExchange(recvbuf);
			recv(ClientSocket, recvbuf, recvbuflen, 0);
			parseClientCertificateVerify(recvbuf);
			recv(ClientSocket, recvbuf, recvbuflen, 0);
			parseClientFinishedMessage(recvbuf);
			generateServerFinishedMessage(sendbuf);
			send(ClientSocket, sendbuf, (int)strlen(sendbuf), 0);
			serverphase = RecordLayer;
			break;
											 }
		case ExitS:{
			iResult = recv(ClientSocket, recvbuf, recvbuflen, 0);
			if ( iResult > 0 ){
				printf("%s\n", recvbuf);
				printf("Bytes received: %d\n", iResult);
			}
			else if ( iResult == 0 )
				printf("Connection closed\n");
			else
				printf("recv failed with error: %d\n", WSAGetLastError());

			// shutdown the connection since no more data will be sent
			iResult = shutdown(ClientSocket, SD_SEND);
			if (iResult == SOCKET_ERROR) {
				printf("shutdown failed with error: %d\n", WSAGetLastError());
				closesocket(ClientSocket);
				WSACleanup();
				return 1;
			}
			whileflag = false;
			break;
				   }
		}
	}

    // No longer need server socket
    closesocket(ListenSocket);

    // cleanup
    closesocket(ClientSocket);
    WSACleanup();

    return 0;
}