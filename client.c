#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <string.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>

#define SERVER_PORT 12345
#define SERVER_IP "127.0.0.1"

#define TRUE 1
#define FALSE 0

int listenSocket;
fd_set socks;
int isAuthenticated = FALSE;

char *serverIp;
int serverPort = SERVER_PORT;

enum PacketTypes
{
    Authenticate,
    SendMessage,
    AuthenticationAccepted,
    AuthenticationDenied,
    BroadcastMessage
};

typedef struct _Packet
{
    int length;
    int type;
    int valid;
    char *data;
} Packet;

void authenticate();

void err(const char *fmt, ...)
{
    va_list va;
    va_start(va, fmt);
    fprintf(stderr, "error:");
    vfprintf(stderr, fmt, va);
    fputc('\n', stderr);
    va_end(va);
    exit(-1);
}

char *currentTime()
{
    time_t timer;
    char *buffer = (char *)malloc(26);
    struct tm *tm_info;

    time(&timer);
    tm_info = localtime(&timer);

    strftime(buffer, 26, "%Y-%m-%d %H:%M:%S", tm_info);
    return buffer;
}

void connectToServer()
{
    listenSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (listenSocket < 0)
    {
        err("socket creation failed!");
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(serverIp);
    server_addr.sin_port = htons(serverPort);

    if (connect(listenSocket, (struct sockaddr *)&server_addr, sizeof(struct sockaddr)) != 0)
    {
        err("Could not connect");
    }

    printf("Connected to %s:%d.\n", serverIp, serverPort);
}

void buildSelectFD()
{
    FD_ZERO(&socks);
    FD_SET(0, &socks);
    FD_SET(listenSocket, &socks);
}

void closeConnection()
{
    close(listenSocket);
    FD_CLR(listenSocket, &socks);
}

void showMessage(Packet *packet)
{
    int userLen = packet->data[0];
    int messageLen = packet->length - userLen - 1;
    char *username = (char *)malloc(userLen + 1);
    char *message = (char *)malloc(messageLen + 1);
    memcpy(username, packet->data + 1, userLen);
    username[userLen] = 0;
    memcpy(message, packet->data + 1 + userLen, messageLen);
    message[messageLen] = 0;
    char *t = currentTime();
    printf("\b\b[%s] %s: %s\n", t, username, message);
}

void recvData()
{
    char buffer[1];
    Packet *packet = (Packet *)malloc(sizeof(Packet));
    packet->length = 0;
    packet->valid = TRUE;
    int firstRecv = TRUE;
    for (;;)
    {
        int receivedBytes = recv(listenSocket, buffer, sizeof(buffer), MSG_DONTWAIT);
        if (receivedBytes < 0)
        {
            if (errno != EWOULDBLOCK)
            {
                err("  recv() failed");
            }
            break;
        }

        if (receivedBytes == 0)
        {
            printf("Server closed");
            closeConnection();
            break;
        }

        int oldLength = packet->length;
        packet->length += receivedBytes - (firstRecv ? 1 : 0);
        if (packet->data == NULL)
            packet->data = (char *)malloc(packet->length);
        else
            packet->data = (char *)realloc(packet->data, packet->length);
        char *copyTo = packet->data + oldLength;
        char *copyFrom = buffer + (firstRecv ? 1 : 0);
        int toRecv = receivedBytes - (firstRecv ? 1 : 0);
        memcpy(copyTo, copyFrom, toRecv);
        if (firstRecv)
        {
            switch (buffer[0])
            {
            case AuthenticationAccepted:
                isAuthenticated = TRUE;
                printf("! Authenticated !\n");
                break;
            case AuthenticationDenied:
                printf("! Wrong credentials !\n");
                authenticate();
                break;
            case BroadcastMessage:
                packet->type = BroadcastMessage;
                break;
            default:
                break;
            }
        }
        firstRecv = FALSE;
    }
    if (packet->type == BroadcastMessage)
    {
        showMessage(packet);
    }
}

void sendPacket(Packet *packet)
{
    int dataLen = packet->length + 1;
    char *data = (char *)malloc(dataLen);
    data[0] = packet->type;
    memcpy(data + 1, packet->data, dataLen);
    int rc = send(listenSocket, data, dataLen, 0);
    if (rc < 0)
    {
        perror("  send() failed");
        closeConnection();
    }
    free(packet);
}

void authenticate()
{
    char username[64];
    char password[64];
    printf("Username: ");
    scanf("%s", username);
    printf("Password: ");
    scanf("%s", password);
    getchar();
    Packet *packet = (Packet *)malloc(sizeof(Packet));
    packet->type = Authenticate;
    packet->length = strlen(username) + strlen(password) + 2;
    packet->data = (char *)malloc(packet->length);
    packet->data[0] = strlen(username);
    packet->data[1] = strlen(password);
    memcpy(packet->data + 2, username, strlen(username));
    memcpy(packet->data + 2 + strlen(username), password, strlen(password));
    sendPacket(packet);
}

void setupIpAndPort()
{
    size_t size = 256;
    char *line = (char *)malloc(size);
    serverIp = (char *) malloc(17);
    serverIp = SERVER_IP;
    printf("Ip (default 127.0.0.1): ");
    getline(&line, &size, stdin);
    if (strlen(line) > 1)
    {
        serverIp = line;
    }
    printf("Port (default 12345): ");
    getline(&line, &size, stdin);
    if (strlen(line) > 1)
    {
        int port = strtol(line, NULL, 10);
        if (port)
        {
            serverPort = port;
        }
    }
}

int main()
{
    setupIpAndPort();
    connectToServer();
    authenticate();
    for (;;)
    {
        buildSelectFD();
        if (isAuthenticated)
        {
            printf("# ");
            fflush(stdout);
        }
        int rc = select(listenSocket + 1, &socks, NULL, NULL, NULL);
        if (rc < 0)
        {
            perror("select failed:");
            break;
        }
        if (rc == 0)
        {
            perror("select timeout");
            break;
        }

        if (FD_ISSET(listenSocket, &socks))
        {
            recvData();
        }
        else
        {
            char buffer[1000];
            int rc = read(STDIN_FILENO, buffer, 1000);
            Packet *packet = (Packet *)malloc(sizeof(Packet));
            int msgLen = rc - 1;
            packet->data = (char *)malloc(msgLen);
            memcpy(packet->data, buffer, msgLen);
            packet->length = msgLen;
            packet->type = SendMessage;
            sendPacket(packet);
        }
    }
}