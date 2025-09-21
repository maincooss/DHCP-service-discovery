  #define _WINSOCK_DEPRECATED_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN

#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <string.h>
#include <time.h>
#include <process.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

#define DHCP_SERVER_PORT 67
#define DHCP_CLIENT_PORT 68
#define MAX_DHCP_SERVERS 32
#define MAX_ADAPTERS 32

typedef struct {
    char server_ip[16];
    time_t first_seen;
    int used;
} DHCPServer;

typedef struct {
    char AdapterName[256];
    char Description[256];
    char Ip[16];
    unsigned char Mac[8];
} AdapterInfo;

DHCPServer found_servers[MAX_DHCP_SERVERS];
int found_count = 0;
CRITICAL_SECTION cs_servers;

AdapterInfo adapters[MAX_ADAPTERS];
int adapters_count = 0;

// 清屏函数，兼容Win10/11命令行
void clear_screen() {
    HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    DWORD count, cellCount;
    COORD homeCoords = { 0, 0 };
    if (hStdOut == INVALID_HANDLE_VALUE) return;
    if (!GetConsoleScreenBufferInfo(hStdOut, &csbi)) return;
    cellCount = csbi.dwSize.X * csbi.dwSize.Y;
    if (!FillConsoleOutputCharacter(hStdOut, (TCHAR)' ', cellCount, homeCoords, &count)) return;
    if (!FillConsoleOutputAttribute(hStdOut, csbi.wAttributes, cellCount, homeCoords, &count)) return;
    SetConsoleCursorPosition(hStdOut, homeCoords);
}

void print_server_list() {
    clear_screen();
    EnterCriticalSection(&cs_servers);
    printf("[DHCP服务器列表]\n");
    printf("编号 | 首次发现时间        | 服务器IP\n");
    printf("---- | ------------------- | ---------------\n");
    for (int i = 0; i < found_count; ++i) {
        if (found_servers[i].used) {
            char timestr[32];
            struct tm tm_info;
            localtime_s(&tm_info, &found_servers[i].first_seen);
            strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", &tm_info);
            printf("%-4d | %-19s | %-15s\n", i + 1, timestr, found_servers[i].server_ip);
        }
    }
    printf("\n");
    LeaveCriticalSection(&cs_servers);
}

void print_adapter_list() {
    ULONG buflen = 15000;
    IP_ADAPTER_INFO* pAdapterInfo = (IP_ADAPTER_INFO*)malloc(buflen);
    if (GetAdaptersInfo(pAdapterInfo, &buflen) == ERROR_BUFFER_OVERFLOW) {
        free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO*)malloc(buflen);
    }
    if (GetAdaptersInfo(pAdapterInfo, &buflen) == NO_ERROR) {
        IP_ADAPTER_INFO* p = pAdapterInfo;
        int idx = 0;
        while (p && idx < MAX_ADAPTERS) {
            strncpy_s(adapters[idx].AdapterName, sizeof(adapters[idx].AdapterName), p->AdapterName, _TRUNCATE);
            strncpy_s(adapters[idx].Description, sizeof(adapters[idx].Description), p->Description, _TRUNCATE);
            strncpy_s(adapters[idx].Ip, sizeof(adapters[idx].Ip), p->IpAddressList.IpAddress.String, _TRUNCATE);
            memset(adapters[idx].Mac, 0, sizeof(adapters[idx].Mac));
            memcpy(adapters[idx].Mac, p->Address, p->AddressLength > 8 ? 8 : p->AddressLength);

            printf(" [%d] %s (%s) IP: %s\n", idx + 1, p->AdapterName, p->Description, p->IpAddressList.IpAddress.String);

            p = p->Next;
            idx++;
        }
        adapters_count = idx;
    }
    free(pAdapterInfo);
}

int server_exists(const char* ip) {
    for (int i = 0; i < found_count; ++i) {
        if (found_servers[i].used && strcmp(ip, found_servers[i].server_ip) == 0)
            return i;
    }
    return -1;
}

void add_server(const char* ip) {
    EnterCriticalSection(&cs_servers);
    if (server_exists(ip) == -1 && found_count < MAX_DHCP_SERVERS) {
        strncpy_s(found_servers[found_count].server_ip, sizeof(found_servers[found_count].server_ip), ip, _TRUNCATE);
        found_servers[found_count].first_seen = time(NULL);
        found_servers[found_count].used = 1;
        found_count++;
        print_server_list();
    }
    LeaveCriticalSection(&cs_servers);
}

// 构造DHCP Discover包
int build_dhcp_discover(unsigned char* buf, int bufsize, unsigned char* mac, int maclen, unsigned int xid) {
    if (bufsize < 548) return 0; // DHCP最小包长度
    memset(buf, 0, bufsize);

    buf[0] = 1; // op: BOOTREQUEST
    buf[1] = 1; // htype: Ethernet
    buf[2] = 6; // hlen: MAC length
    buf[3] = 0; // hops
    *(unsigned int*)&buf[4] = htonl(xid); // xid
    buf[8] = 0; buf[9] = 0; // secs
    buf[10] = 0x80; buf[11] = 0x00; // flags: broadcast
    // ciaddr/yiaddr/siaddr/giaddr: 0
    // chaddr
    memcpy(&buf[28], mac, maclen > 16 ? 16 : maclen);

    // magic cookie
    buf[236] = 99; buf[237] = 130; buf[238] = 83; buf[239] = 99;

    int idx = 240;
    // DHCP message type
    buf[idx++] = 53; buf[idx++] = 1; buf[idx++] = 1; // DHCP Discover
    // Parameter Request List (option 55)
    buf[idx++] = 55; buf[idx++] = 3; buf[idx++] = 1; buf[idx++] = 3; buf[idx++] = 6;
    // End option
    buf[idx++] = 0xff;
    return idx; // 返回包长度
}

// 捕获DHCP OFFER/ACK消息，提取server identifier
void process_dhcp_packet(const char* buf, int len, const char* ifname) {
    if (len < 240) return; // 不可能是DHCP
    const unsigned char* pkt = (const unsigned char*)buf;
    if (pkt[236] != 99 || pkt[237] != 130 || pkt[238] != 83 || pkt[239] != 99)
        return; // magic cookie不符

    int idx = 240;
    int found_offer = 0;
    while (idx < len) {
        unsigned char option = pkt[idx++];
        if (option == 0xff) break;
        if (option == 0) continue;
        if (idx >= len) break;
        unsigned char optlen = pkt[idx++];
        if (idx + optlen > len) break;
        if (option == 53) {
            if (pkt[idx] == 2 || pkt[idx] == 5) // OFFER/ACK
                found_offer = 1;
        }
        if (option == 54 && optlen == 4) {
            char sip[16];
            snprintf(sip, 16, "%u.%u.%u.%u", pkt[idx], pkt[idx + 1], pkt[idx + 2], pkt[idx + 3]);
            if (found_offer) {
                add_server(sip);
            }
            return;
        }
        idx += optlen;
    }
}

typedef struct {
    SOCKET sock;
    AdapterInfo* adapter;
    struct sockaddr_in to;
} ThreadArgs;

unsigned __stdcall sender_thread(void* arg) {
    ThreadArgs* args = (ThreadArgs*)arg;
    unsigned char discover[548];
    unsigned int xid = (unsigned int)time(NULL);
    while (1) {
        int discover_len = build_dhcp_discover(discover, sizeof(discover), args->adapter->Mac, 6, xid++);
        sendto(args->sock, (const char*)discover, discover_len, 0, (struct sockaddr*)&args->to, sizeof(args->to));
        Sleep(1000);
    }
    return 0;
}

unsigned __stdcall receiver_thread(void* arg) {
    ThreadArgs* args = (ThreadArgs*)arg;
    char buf[1024];
    struct sockaddr_in from;
    int fromlen = sizeof(from);
    while (1) {
        fd_set readfds;
        struct timeval tv;
        FD_ZERO(&readfds);
        FD_SET(args->sock, &readfds);
        tv.tv_sec = 0;
        tv.tv_usec = 300000;
        int ready = select(0, &readfds, NULL, NULL, &tv);
        if (ready > 0 && FD_ISSET(args->sock, &readfds)) {
            int ret = recvfrom(args->sock, buf, sizeof(buf), 0, (struct sockaddr*)&from, &fromlen);
            if (ret > 0) {
                process_dhcp_packet(buf, ret, args->adapter->Description);
            }
        }
    }
    return 0;
}

int main() {
    WSADATA wsaData;
    SOCKET sock;
    struct sockaddr_in local, to;
    int fromlen = sizeof(struct sockaddr_in);

    InitializeCriticalSection(&cs_servers);

    printf("可用网卡列表:\n");
    print_adapter_list();
    if (adapters_count == 0) {
        printf("未检测到可用网卡！\n");
        return 1;
    }

    int sel = 0;
    printf("请选择网卡序号（1~%d）：\n", adapters_count);
    while (1) {
        if (scanf_s("%d", &sel) != 1 || sel < 1 || sel > adapters_count) {
            printf("输入无效，请重新输入(1~%d)：\n", adapters_count);
            while (getchar() != '\n');
        }
        else {
            break;
        }
    }

    AdapterInfo* adapter = &adapters[sel - 1];

    if (strlen(adapter->Ip) == 0 || strcmp(adapter->Ip, "0.0.0.0") == 0) {
        printf("所选网卡无有效IP地址。\n");
        return 1;
    }
    printf("监听网卡: %s (%s), IP: %s\n", adapter->AdapterName, adapter->Description, adapter->Ip);

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup错误\n");
        return 1;
    }

    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        printf("创建socket失败\n");
        WSACleanup();
        return 1;
    }

    BOOL yes = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char*)&yes, sizeof(yes));
    setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (char*)&yes, sizeof(yes));

    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_port = htons(DHCP_CLIENT_PORT);
    local.sin_addr.s_addr = inet_addr(adapter->Ip);
    if (bind(sock, (struct sockaddr*)&local, sizeof(local)) < 0) {
        printf("绑定失败，可能需要管理员权限\n");
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_port = htons(DHCP_SERVER_PORT);
    to.sin_addr.s_addr = INADDR_BROADCAST;

    ThreadArgs args;
    args.sock = sock;
    args.adapter = adapter;
    args.to = to;

    uintptr_t th1 = _beginthreadex(NULL, 0, sender_thread, &args, 0, NULL);
    uintptr_t th2 = _beginthreadex(NULL, 0, receiver_thread, &args, 0, NULL);

    printf("正在多线程轮询发送DHCP Discover包，并监听响应...\n按Ctrl+C退出\n");

    // 主线程等待子线程结束
    WaitForSingleObject((HANDLE)th1, INFINITE);
    WaitForSingleObject((HANDLE)th2, INFINITE);

    closesocket(sock);
    WSACleanup();
    DeleteCriticalSection(&cs_servers);
    return 0;
}
