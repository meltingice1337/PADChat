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

#define SAFE_ALLOC(var, type)                         \
    if ((var = (type *)malloc(sizeof(type))) == NULL) \
    err("cannot alloc pointer type")

#define SERVER_PORT 12345

#define TRUE 1
#define FALSE 0

#define notifyMsg "HAS JUST JOINED!"
//some changes done by emilion

enum PacketTypes
{
    Authenticate,
    SendMessage,
    AuthenticationAccepted,
    AuthenticationDenied,
    BroadcastMessage,
    UserAlreadyLoggedIn,
    UserJoined,
    UserLeftSession
};

typedef struct _Client
{
    int socket;
    char *name;
    int authenticated;
    struct _Client *next;
    struct _Client *previous;
} Client;

typedef struct _Packet
{
    Client *client;
    int length;
    int type;
    int valid;
    char *data;
} Packet;

Client *clients = NULL;
Client *lastClient = NULL;

int len, rc, on = 1;
int listen_sd, max_sd;
int desc_ready, end_server = FALSE;
int close_conn;
struct sockaddr_in6 addr;
struct timeval timeout;
fd_set socks;
int serverPort = SERVER_PORT;

void broadcastMessage(Packet *packet);
void processPacket(Packet *packet);
void notifyJoined(Client *client);
void notifyLeaving(Client *client);

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
    char *buffer = (char *)malloc(27);
    struct tm *tm_info;

    time(&timer);
    tm_info = localtime(&timer);

    strftime(buffer, 26, "%Y-%m-%d %H:%M:%S", tm_info);
    return buffer;
}

void initSocket()
{
    listen_sd = socket(AF_INET6, SOCK_STREAM, 0);
    if (listen_sd < 0)
    {
        err("socket creation failed!");
    }

    rc = setsockopt(listen_sd, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on));
    if (rc < 0)
    {
        close(listen_sd);
        err("setting reusable socket failed");
    }

    rc = ioctl(listen_sd, FIONBIO, (char *)&on);
    if (rc < 0)
    {
        close(listen_sd);
        err("socket setting to nonblocking failed");
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;

    memcpy(&addr.sin6_addr, &in6addr_any, sizeof(in6addr_any));
    addr.sin6_port = htons(serverPort);

    rc = bind(listen_sd, (struct sockaddr *)&addr, sizeof(addr));
    if (rc < 0)
    {
        close(listen_sd);
        err("binding the socket failed");
    }

    rc = listen(listen_sd, 32);
    if (rc < 0)
    {
        close(listen_sd);
        err("listen() failed");
    }

    timeout.tv_sec = 3 * 60;
    timeout.tv_usec = 0;

    printf("Started listenting on %d\n", serverPort);
}

void buildSelectFD()
{
    FD_ZERO(&socks);
    FD_SET(listen_sd, &socks);
    max_sd = listen_sd;
    Client *client = clients;
    while (client != NULL)
    {
        FD_SET(client->socket, &socks);
        if (client->socket > max_sd)
            max_sd = client->socket;
        client = client->next;
    }
    free(client);
}

//********function that checks if client is already logged in**
int isClientAlreadyLoggedIn(char *testName)
{
    if (clients == NULL)
        return FALSE; //if there are no clients then this is the first connection

    Client *client = clients;
    while (client->next != NULL)
    {
        if (strcmp(client->name, testName) == 0)
            return TRUE;
        client = client->next;
    }
    return FALSE;
}

//*************************************************************

void acceptNewCLients()
{
    int new_sd;
    do
    {
        new_sd = accept(listen_sd, NULL, NULL);
        if (new_sd < 0)
        {
            if (errno != EWOULDBLOCK)
            {
                perror("  accept() failed");
                end_server = TRUE;
            }
            break;
        }

        printf("  New incoming connection - %d\n", new_sd);
        FD_SET(new_sd, &socks);

        if (clients == NULL)
        {
            clients = (Client *)malloc(sizeof(Client));
            clients->socket = new_sd;
            clients->authenticated = FALSE;
            clients->name = NULL;
            clients->next = NULL;
            clients->previous = NULL;
            lastClient = clients;
        }
        else
        {
            Client *newClient = (Client *)malloc(sizeof(Client));
            newClient->socket = new_sd;
            newClient->authenticated = FALSE;
            newClient->name = NULL;
            newClient->next = NULL;
            newClient->previous = lastClient;
            lastClient->next = newClient;
            lastClient = newClient;
        }

        if (new_sd > max_sd)
            max_sd = new_sd;

    } while (new_sd != -1);
}

void closeConnection(Client *client)
{
    close(client->socket);
    FD_CLR(client->socket, &socks);
    if (client->authenticated)
    {
        printf("[%s] User %s has closed the connection \n", currentTime(), client->name);
        notifyLeaving(client);
        fflush(stdout);
    }
    if (client->socket == max_sd)
    {
        while (FD_ISSET(max_sd, &socks) == FALSE && max_sd > 1)
            max_sd -= 1;
    }
    if (client == clients)
    {
        client->previous = NULL;
        clients = client->next;
        if (client == lastClient)
            lastClient = clients;
    }
    else if (client == lastClient)
    {
        lastClient = client->previous;
        lastClient->next = NULL;
    }
    else
        client->previous->next = client->next;

    free(client);
}

Client *getClient(int socket)
{
    Client *client = clients;
    while (client != NULL)
    {

        if (client->socket == socket)
            return client;
        client = client->next;
    }
    return NULL;
}

void sendPacket(Packet *packet)
{
    int dataLen = packet->length + 1;
    char *data = (char *)malloc(dataLen);
    data[0] = packet->type;
    if (packet->data != NULL)
        memcpy(data + 1, packet->data, dataLen);
    int rc = send(packet->client->socket, data, dataLen, 0);
    if (rc < 0)
    {
        perror("  send() failed");
        closeConnection(packet->client);
    }
    free(data);
}

void authenticateUser(Packet *packet)
{
    if (packet->length == 0 || packet->data == NULL)
    {
        return;
    }
    int usernameLen = packet->data[0];
    int passwordLen = packet->data[1];
    char *account = malloc(usernameLen + passwordLen + 2);
    memcpy(account, packet->data + 2, usernameLen);
    account[usernameLen] = ':';
    memcpy(account + usernameLen + 1, packet->data + 2 + usernameLen, passwordLen);
    int accountLen = usernameLen + 1 + passwordLen;
    account[accountLen] = 0;
    char *line = NULL;
    FILE *f = fopen("users.db", "r");
    size_t len;
    int read;
    if (f == NULL)
        err("cannot open users.db");

    //*************************************
    char *name = malloc(usernameLen + 1);
    memcpy(name, account, usernameLen);
    name[usernameLen] = 0;
    if (isClientAlreadyLoggedIn(name))
    {
        printf("[%s] User %s has already connected to the server and is trying again!\n", currentTime(), name);
        free(name);

        Packet *alreadyLoggedPacket = (Packet *)malloc(sizeof(Packet));
        alreadyLoggedPacket->type = UserAlreadyLoggedIn;
        alreadyLoggedPacket->length = 0;
        alreadyLoggedPacket->client = packet->client;
        alreadyLoggedPacket->data = NULL;
        sendPacket(alreadyLoggedPacket);
        fclose(f);
        return;
    }

    while ((read = getline(&line, &len, f)) != -1)
    {
        int lineLen = line[strlen(line) - 1] == '\n' ? strlen(line) - 1 : strlen(line);
        if (memcmp(line, account, accountLen) == 0 && (accountLen) == lineLen)
        {
            Packet *acceptPacket = (Packet *)malloc(sizeof(Packet));
            acceptPacket->type = AuthenticationAccepted;
            acceptPacket->length = 0;
            acceptPacket->data = NULL;
            acceptPacket->client = packet->client;
            sendPacket(acceptPacket);
            packet->client->authenticated = TRUE;
            char *username = (char *)malloc(usernameLen + 1);
            memcpy(username, account, usernameLen);
            username[usernameLen] = 0;
            packet->client->name = username;
            printf("[%s] User %s has connected to the server\n", currentTime(), username);
            fclose(f);
            free(line);
            notifyJoined(packet->client);
            return;
        }
    }
    Packet *acceptPacket = (Packet *)malloc(sizeof(Packet));
    acceptPacket->type = AuthenticationDenied;
    acceptPacket->length = 0;
    acceptPacket->client = packet->client;
    sendPacket(acceptPacket);
    fclose(f);
    free(line);
}

void notifyJoined(Client *client)
{
    Client *c = clients;

    while (c != NULL)
    {
        if (c == client)
        {
            c = c->next;
            continue;
        }

        Packet *p = (Packet *)malloc(sizeof(Packet));
        p->type = UserJoined;
        p->data = (char *)malloc(strlen(client->name));
        memcpy(p->data, client->name, strlen(client->name));
        p->data[strlen(client->name)] = 0;
        p->client = c;
        p->length = strlen(client->name);
        sendPacket(p);
        free(p->data);
        free(p);
        c = c->next;
    }
}

void notifyLeaving(Client *client)
{
    Client *c = clients;

    while (c != NULL)
    {
        if (c == client)
        {
            c = c->next;
            continue;
        }

        Packet *p = (Packet *)malloc(sizeof(Packet));
        p->type = UserLeftSession;
        p->data = (char *)malloc(strlen(client->name));
        memcpy(p->data, client->name, strlen(client->name));
        p->data[strlen(client->name)] = 0;
        p->client = c;
        p->length = strlen(client->name);
        sendPacket(p);
        free(p->data);
        free(p);
        c = c->next;
    }
}

void broadcastMessage(Packet *packet)
{
    Client *client = clients;
    Packet *p = (Packet *)malloc(sizeof(Packet));
    p->type = BroadcastMessage;
    int len = packet->length + strlen(packet->client->name) + 1;
    p->data = (char *)malloc(len);
    p->data[0] = strlen(packet->client->name);
    p->client = client;
    p->length = len;
    memcpy(p->data + 1, packet->client->name, strlen(packet->client->name));
    memcpy(p->data + strlen(packet->client->name) + 1, packet->data, packet->length);
    packet->data[packet->length] = 0;
    printf("[%s] %s: %s\n", currentTime(), packet->client->name, packet->data);
    while (client != NULL)
    {
        if (client == packet->client)
        {
            client = client->next;
            continue;
        }
        if (client->authenticated)
        {
            p->client = client;
            sendPacket(p);
        }
        client = client->next;
    }
    free(p);
    free(p->data);
    free(client);
}

void processPacket(Packet *packet)
{
    if (packet->type == Authenticate)
    {
        authenticateUser(packet);
    }
    else if (packet->type == SendMessage && packet->data != NULL)
    {
        broadcastMessage(packet);
    }
}

void recvData(Client *client)
{
    char buffer[80];
    Packet *packet = (Packet *)malloc(sizeof(Packet));
    packet->client = client;
    packet->length = 0;
    packet->data = NULL;
    packet->valid = 1;
    int firstRecv = TRUE;
    do
    {
        rc = recv(client->socket, buffer, sizeof(buffer), MSG_DONTWAIT);
        if (rc < 0)
        {
            if (errno != EWOULDBLOCK)
            {
                perror("  recv() failed");
                closeConnection(client);
            }
            break;
        }

        if (rc == 0)
        {
            closeConnection(client);
            break;
        }

        len = rc;
        int oldLength = packet->length;
        if (packet->length == 0)
        {
            switch (buffer[0])
            {
            case Authenticate:
                packet->type = Authenticate;
                break;
            case SendMessage:
                packet->type = SendMessage;
                break;
            default:
                printf("Invalid packet from client %d", client->socket);
                packet->valid = 0;
                break;
            }
        }
        packet->length += len;
        if (firstRecv)
            packet->length--;
        if (packet->data == NULL)
            packet->data = (char *)malloc(packet->length);
        else
            packet->data = (char *)realloc(packet->data, packet->length);

        memcpy(packet->data + oldLength, buffer + (firstRecv), len - (firstRecv));

        firstRecv = FALSE;
    } while (TRUE);
    if (packet->valid && (client->authenticated || packet->type == Authenticate))
        processPacket(packet);
    free(packet);
}

void setupPort()
{
    size_t size = 256;
    char *line = (char *)malloc(size);
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

int main(int argc, char *argv[])
{
    setupPort();
    initSocket();
    int i;
    do
    {
        buildSelectFD();
        // printf("Waiting on select()...\n");
        rc = select(max_sd + 1, &socks, NULL, NULL, NULL);
        if (rc < 0)
        {
            perror("  select() failed");
            break;
        }
        if (rc == 0)
        {
            printf("  select() timed out.  End program.\n");
            break;
        }

        desc_ready = rc;
        for (i = 0; i <= max_sd && desc_ready > 0; ++i)
        {
            if (FD_ISSET(i, &socks))
            {
                desc_ready -= 1;

                if (i == listen_sd)
                {
                    acceptNewCLients();
                }
                else
                {
                    recvData(getClient(i));
                }
            }
        }

    } while (end_server == FALSE);

    for (i = 0; i <= max_sd; ++i)
    {
        if (FD_ISSET(i, &socks))
            close(i);
    }
}
