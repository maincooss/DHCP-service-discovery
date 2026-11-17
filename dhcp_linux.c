#define _GNU_SOURCE

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <ifaddrs.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <locale.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define DHCP_SERVER_PORT 67
#define DHCP_CLIENT_PORT 68
#define DHCP_PACKET_SIZE 576
#define DHCP_SCAN_WINDOW_MS 2000
#define DHCP_RETRY_INTERVAL_MS 1000
#define ARP_PROBES_PER_OFFER 6
#define ARP_PROBE_INTERVAL_MS 100
#define TABLE_MAX_COLUMNS 8
#define TABLE_CELL_CAPACITY 512
#define MAX_ADAPTER_NAME 256
#define MAX_ADAPTERS 256

typedef struct {
    char name[MAX_ADAPTER_NAME];
    char description[256];
    char ipv4[INET_ADDRSTRLEN];
    unsigned char mac[6];
    unsigned int interface_index;
    int has_ipv4;
    int has_mac;
    int is_up;
} AdapterInfo;

typedef struct {
    char server_ip[INET_ADDRSTRLEN];
    char server_mac[18];
    char device_vendor[160];
    char assigned_ip[INET_ADDRSTRLEN];
    char subnet_mask[INET_ADDRSTRLEN];
    char gateway[96];
    char dns[96];
    char lease[32];
    unsigned long long response_ms;
    struct tm discovered_at;
    size_t adapter_number;
} DHCPServer;

typedef struct {
    char server_ip[INET_ADDRSTRLEN];
    char assigned_ip[INET_ADDRSTRLEN];
    char subnet_mask[INET_ADDRSTRLEN];
    char gateway[96];
    char dns[96];
    char hostname[64];
    char vendor_class[64];
    char lease[32];
} DHCPOffer;

typedef struct {
    unsigned char prefix[6];
    unsigned char prefix_nibbles;
    char vendor[160];
} OUIRecord;

static DHCPServer *g_servers;
static size_t g_server_count;
static size_t g_server_capacity;
static OUIRecord *g_oui_records;
static size_t g_oui_record_count;
static size_t g_oui_record_capacity;
static volatile sig_atomic_t g_running = 1;
static int g_color_enabled;

static unsigned long long monotonic_ms(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return 0;
    return (unsigned long long)now.tv_sec * 1000ULL +
        (unsigned long long)now.tv_nsec / 1000000ULL;
}

static void handle_signal(int signal_number)
{
    (void)signal_number;
    g_running = 0;
}

static void copy_ipv4(char *destination, size_t capacity,
                      const unsigned char *address)
{
    struct in_addr ipv4;
    memcpy(&ipv4.s_addr, address, sizeof(ipv4.s_addr));
    if (!inet_ntop(AF_INET, &ipv4, destination, (socklen_t)capacity))
        destination[0] = '\0';
}

static void copy_option_text(char *destination, size_t capacity,
                             const unsigned char *value, size_t length)
{
    size_t i;
    size_t copied = 0;
    for (i = 0; i < length && copied + 1 < capacity; ++i) {
        unsigned char c = value[i];
        if (c == 0)
            break;
        destination[copied++] =
            (c >= 32 && c <= 126 && c != '|') ? (char)c : '_';
    }
    destination[copied] = '\0';
}

static void format_address_list(char *destination, size_t capacity,
                                const unsigned char *value, size_t length)
{
    size_t offset = 0;
    size_t i;
    destination[0] = '\0';
    for (i = 0; i + 4 <= length; i += 4) {
        char address[INET_ADDRSTRLEN];
        int written;
        copy_ipv4(address, sizeof(address), value + i);
        if (address[0] == '\0')
            continue;
        written = snprintf(destination + offset, capacity - offset, "%s%s",
                           offset ? ", " : "", address);
        if (written < 0 || (size_t)written >= capacity - offset)
            break;
        offset += (size_t)written;
    }
}

static void format_mac(char *destination, size_t capacity,
                       const unsigned char *mac)
{
    snprintf(destination, capacity, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static int hex_nibble(char value)
{
    if (value >= '0' && value <= '9')
        return value - '0';
    if (value >= 'A' && value <= 'F')
        return value - 'A' + 10;
    if (value >= 'a' && value <= 'f')
        return value - 'a' + 10;
    return -1;
}

static int parse_oui_line(const char *line, OUIRecord *record)
{
    const char *marker = strstr(line, "(hex)");
    const char *cursor = line;
    const char *vendor;
    const char *end;
    unsigned char nibbles[12];
    size_t nibble_count = 0;
    size_t i;

    if (!marker)
        return 0;
    while (cursor < marker) {
        int value = hex_nibble(*cursor);
        if (value >= 0) {
            if (nibble_count == sizeof(nibbles))
                return 0;
            nibbles[nibble_count++] = (unsigned char)value;
        } else if (*cursor != '-' && *cursor != ':' &&
                   *cursor != ' ' && *cursor != '\t') {
            return 0;
        }
        ++cursor;
    }
    if (nibble_count < 6)
        return 0;

    memset(record, 0, sizeof(*record));
    record->prefix_nibbles = (unsigned char)nibble_count;
    for (i = 0; i < nibble_count; ++i) {
        if ((i & 1) == 0)
            record->prefix[i / 2] = (unsigned char)(nibbles[i] << 4);
        else
            record->prefix[i / 2] |= nibbles[i];
    }

    vendor = marker + 5;
    while (*vendor == ' ' || *vendor == '\t')
        ++vendor;
    end = vendor + strlen(vendor);
    while (end > vendor && (end[-1] == '\r' || end[-1] == '\n' ||
                            end[-1] == ' ' || end[-1] == '\t'))
        --end;
    if (end == vendor)
        return 0;
    {
        size_t vendor_length = (size_t)(end - vendor);
        if (vendor_length >= sizeof(record->vendor))
            vendor_length = sizeof(record->vendor) - 1;
        memcpy(record->vendor, vendor, vendor_length);
        record->vendor[vendor_length] = '\0';
    }
    return record->vendor[0] != '\0';
}

static int executable_oui_path(char *path, size_t capacity)
{
    ssize_t length = readlink("/proc/self/exe", path, capacity - 1);
    char *slash;
    if (length <= 0 || (size_t)length >= capacity - 1)
        return 0;
    path[length] = '\0';
    slash = strrchr(path, '/');
    if (!slash)
        return 0;
    slash[1] = '\0';
    if (strlen(path) + sizeof("oui.txt") > capacity)
        return 0;
    strcat(path, "oui.txt");
    return 1;
}

static int download_oui_file(const char *path)
{
    pid_t child = fork();
    int status;
    char temporary_path[4096];

    if (snprintf(temporary_path, sizeof(temporary_path), "%s.tmp.%ld",
                 path, (long)getpid()) >= (int)sizeof(temporary_path)) {
        fprintf(stderr, "oui.txt 路径过长。\n");
        return 0;
    }
    if (child < 0) {
        fprintf(stderr, "启动 curl 下载 OUI 数据库失败: %s\n", strerror(errno));
        return 0;
    }
    if (child == 0) {
        execlp("curl", "curl", "--fail", "--location", "--silent",
               "--show-error", "--output", temporary_path,
               "https://standards-oui.ieee.org/oui/oui.txt", (char *)NULL);
        _exit(127);
    }
    if (waitpid(child, &status, 0) < 0 || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0) {
        unlink(temporary_path);
        fprintf(stderr,
                "下载 IEEE OUI 数据库失败；请安装 curl 或将 oui.txt 放在程序旁。\n");
        return 0;
    }
    if (rename(temporary_path, path) != 0) {
        fprintf(stderr, "保存 oui.txt 到程序目录失败: %s\n", strerror(errno));
        unlink(temporary_path);
        return 0;
    }
    return 1;
}

static FILE *open_oui_file(void)
{
    char path[4096];
    FILE *file;
    struct stat status;

    if (!executable_oui_path(path, sizeof(path))) {
        fprintf(stderr, "无法获取程序目录，不能定位 oui.txt。\n");
        return NULL;
    }
    file = fopen(path, "r");
    if (file) {
        printf("正在使用程序同目录下的 oui.txt。\n");
        return file;
    }
    if (stat(path, &status) == 0) {
        fprintf(stderr, "程序同目录下的 oui.txt 存在但无法读取: %s\n",
                strerror(errno));
        return NULL;
    }

    printf("程序同目录下未找到 oui.txt，正在从 IEEE 下载...\n");
    if (!download_oui_file(path))
        return NULL;
    file = fopen(path, "r");
    if (!file) {
        fprintf(stderr, "IEEE OUI 文件已下载，但无法读取: %s\n",
                strerror(errno));
        return NULL;
    }
    printf("IEEE oui.txt 已下载到程序同目录。\n");
    return file;
}

static size_t load_oui_database(void)
{
    char line[512];
    FILE *file = open_oui_file();
    if (!file)
        return 0;

    while (fgets(line, sizeof(line), file)) {
        OUIRecord record;
        if (!parse_oui_line(line, &record))
            continue;
        if (g_oui_record_count == g_oui_record_capacity) {
            size_t new_capacity = g_oui_record_capacity
                ? g_oui_record_capacity * 2 : 128;
            OUIRecord *records = realloc(g_oui_records,
                                         new_capacity * sizeof(*records));
            if (!records) {
                fprintf(stderr, "扩展 OUI 数据库内存失败。\n");
                break;
            }
            g_oui_records = records;
            g_oui_record_capacity = new_capacity;
        }
        g_oui_records[g_oui_record_count++] = record;
    }
    fclose(file);
    return g_oui_record_count;
}

static const char *lookup_oui_vendor(const unsigned char *mac)
{
    size_t i;
    const OUIRecord *best_match = NULL;
    for (i = 0; i < g_oui_record_count; ++i) {
        const OUIRecord *record = &g_oui_records[i];
        size_t nibble;
        int matches = 1;
        for (nibble = 0; nibble < record->prefix_nibbles; ++nibble) {
            unsigned char actual = (nibble & 1)
                ? (unsigned char)(mac[nibble / 2] & 0x0F)
                : (unsigned char)(mac[nibble / 2] >> 4);
            unsigned char expected = (nibble & 1)
                ? (unsigned char)(record->prefix[nibble / 2] & 0x0F)
                : (unsigned char)(record->prefix[nibble / 2] >> 4);
            if (actual != expected) {
                matches = 0;
                break;
            }
        }
        if (matches && (!best_match ||
                        record->prefix_nibbles > best_match->prefix_nibbles))
            best_match = record;
    }
    return best_match ? best_match->vendor : "未知厂商";
}

static void append_text(char *destination, size_t capacity, const char *text)
{
    size_t length = strnlen(destination, capacity);
    size_t available;
    size_t append_length;
    if (length >= capacity)
        return;
    available = capacity - length - 1;
    append_length = strnlen(text, available);
    memcpy(destination + length, text, append_length);
    destination[length + append_length] = '\0';
}

static void build_device_vendor(char *destination, size_t capacity,
                                const unsigned char *mac, const DHCPOffer *offer)
{
    const char *oui_vendor = lookup_oui_vendor(mac);
    destination[0] = '\0';
    append_text(destination, capacity, oui_vendor);
    if (offer->vendor_class[0]) {
        append_text(destination, capacity, "; ");
        append_text(destination, capacity, offer->vendor_class);
    }
    if (offer->hostname[0]) {
        append_text(destination, capacity, "; ");
        append_text(destination, capacity, offer->hostname);
    }
}

static int get_adapters(AdapterInfo **adapters_out, size_t *count_out)
{
    struct ifaddrs *interfaces = NULL;
    struct ifaddrs *item;
    AdapterInfo *adapters;
    size_t capacity = 16;
    size_t count = 0;

    *adapters_out = NULL;
    *count_out = 0;
    if (getifaddrs(&interfaces) != 0) {
        fprintf(stderr, "枚举网卡失败: %s\n", strerror(errno));
        return 0;
    }
    adapters = calloc(capacity, sizeof(*adapters));
    if (!adapters) {
        fprintf(stderr, "分配网卡列表失败。\n");
        freeifaddrs(interfaces);
        return 0;
    }

    for (item = interfaces; item; item = item->ifa_next) {
        size_t index;
        AdapterInfo *adapter;
        if (!item->ifa_name || !item->ifa_addr ||
            (item->ifa_addr->sa_family != AF_INET &&
             item->ifa_addr->sa_family != AF_PACKET))
            continue;
        for (index = 0; index < count; ++index) {
            if (strcmp(adapters[index].name, item->ifa_name) == 0)
                break;
        }
        if (index == count) {
            if (count == MAX_ADAPTERS)
                continue;
            if (count == capacity) {
                size_t new_capacity = capacity * 2;
                AdapterInfo *new_adapters;
                if (new_capacity > MAX_ADAPTERS)
                    new_capacity = MAX_ADAPTERS;
                new_adapters = realloc(adapters,
                                       new_capacity * sizeof(*new_adapters));
                if (!new_adapters) {
                    fprintf(stderr, "扩展网卡列表失败。\n");
                    free(adapters);
                    freeifaddrs(interfaces);
                    return 0;
                }
                adapters = new_adapters;
                capacity = new_capacity;
            }
            memset(&adapters[count], 0, sizeof(adapters[count]));
            snprintf(adapters[count].name, sizeof(adapters[count].name),
                     "%s", item->ifa_name);
            snprintf(adapters[count].description,
                     sizeof(adapters[count].description), "%s", item->ifa_name);
            adapters[count].interface_index = if_nametoindex(item->ifa_name);
            adapters[count].is_up = !!(item->ifa_flags & IFF_UP);
            index = count++;
        }
        adapter = &adapters[index];
        if (item->ifa_addr->sa_family == AF_INET && !adapter->has_ipv4 &&
            inet_ntop(AF_INET, &((struct sockaddr_in *)item->ifa_addr)->sin_addr,
                      adapter->ipv4, sizeof(adapter->ipv4)))
            adapter->has_ipv4 = 1;
        if (item->ifa_addr->sa_family == AF_PACKET) {
            struct sockaddr_ll *link = (struct sockaddr_ll *)item->ifa_addr;
            if (link->sll_hatype == ARPHRD_ETHER &&
                link->sll_halen >= sizeof(adapter->mac)) {
                memcpy(adapter->mac, link->sll_addr, sizeof(adapter->mac));
                adapter->has_mac = 1;
            }
        }
    }
    freeifaddrs(interfaces);

    *adapters_out = adapters;
    *count_out = count;
    return 1;
}

static size_t text_display_width(const char *text)
{
    mbstate_t state;
    const char *cursor = text;
    size_t width = 0;
    memset(&state, 0, sizeof(state));
    while (*cursor) {
        wchar_t codepoint;
        size_t count = mbrtowc(&codepoint, cursor, MB_CUR_MAX, &state);
        if (count == (size_t)-1 || count == (size_t)-2) {
            memset(&state, 0, sizeof(state));
            ++cursor;
            ++width;
            continue;
        }
        if (count == 0)
            break;
        {
            int columns = wcwidth(codepoint);
            if (columns > 0)
                width += (size_t)columns;
        }
        cursor += count;
    }
    return width;
}

static void print_table_border(const size_t *widths, size_t column_count)
{
    size_t column;
    putchar('+');
    for (column = 0; column < column_count; ++column) {
        size_t i;
        for (i = 0; i < widths[column] + 2; ++i)
            putchar('-');
        putchar('+');
    }
    putchar('\n');
}

static void print_table_row(const char *const *cells, const size_t *widths,
                            size_t column_count)
{
    size_t column;
    putchar('|');
    for (column = 0; column < column_count; ++column) {
        size_t width = text_display_width(cells[column]);
        size_t padding;
        printf(" %s", cells[column]);
        for (padding = width; padding < widths[column]; ++padding)
            putchar(' ');
        fputs(" |", stdout);
    }
    putchar('\n');
}

static void print_colored_table_header(const char *const *cells,
                                       const size_t *widths,
                                       const char *const *colors,
                                       size_t column_count)
{
    size_t column;
    putchar('|');
    for (column = 0; column < column_count; ++column) {
        size_t width = text_display_width(cells[column]);
        size_t padding;
        printf(" ");
        if (g_color_enabled)
            fputs(colors[column], stdout);
        fputs(cells[column], stdout);
        if (g_color_enabled)
            fputs("\033[0m", stdout);
        for (padding = width; padding < widths[column]; ++padding)
            putchar(' ');
        fputs(" |", stdout);
    }
    putchar('\n');
}

static void update_column_widths(size_t *widths, const char *const *cells,
                                 size_t column_count)
{
    size_t column;
    for (column = 0; column < column_count; ++column) {
        size_t width = text_display_width(cells[column]);
        if (width > widths[column])
            widths[column] = width;
    }
}

static void make_adapter_cells(const AdapterInfo *adapter, size_t adapter_number,
                               char cells[TABLE_MAX_COLUMNS][TABLE_CELL_CAPACITY])
{
    snprintf(cells[0], TABLE_CELL_CAPACITY, "%zu", adapter_number);
    snprintf(cells[1], TABLE_CELL_CAPACITY, "%s",
             adapter->is_up ? "启用" : "停用");
    snprintf(cells[2], TABLE_CELL_CAPACITY, "%s",
             adapter->has_ipv4 ? adapter->ipv4 : "无 IPv4");
    cells[3][0] = '\0';
    append_text(cells[3], TABLE_CELL_CAPACITY,
                adapter->description[0] ? adapter->description : adapter->name);
    append_text(cells[3], TABLE_CELL_CAPACITY, " (");
    append_text(cells[3], TABLE_CELL_CAPACITY, adapter->name);
    append_text(cells[3], TABLE_CELL_CAPACITY, ")");
}

static void print_adapters(const AdapterInfo *adapters, size_t count)
{
    static const char *headers[] = { "网卡序号", "状态", "IPv4", "名称" };
    size_t widths[4] = { 0 };
    size_t i;
    printf("检测到 %zu 张网卡：\n", count);
    for (i = 0; i < 4; ++i)
        widths[i] = text_display_width(headers[i]);
    for (i = 0; i < count; ++i) {
        char cells[TABLE_MAX_COLUMNS][TABLE_CELL_CAPACITY] = { { 0 } };
        const char *row[4];
        size_t column;
        make_adapter_cells(&adapters[i], i + 1, cells);
        for (column = 0; column < 4; ++column)
            row[column] = cells[column];
        update_column_widths(widths, row, 4);
    }
    print_table_border(widths, 4);
    print_table_row(headers, widths, 4);
    print_table_border(widths, 4);
    for (i = 0; i < count; ++i) {
        char cells[TABLE_MAX_COLUMNS][TABLE_CELL_CAPACITY] = { { 0 } };
        const char *row[4];
        size_t column;
        make_adapter_cells(&adapters[i], i + 1, cells);
        for (column = 0; column < 4; ++column)
            row[column] = cells[column];
        print_table_row(row, widths, 4);
    }
    print_table_border(widths, 4);
}

static void make_server_cells(const DHCPServer *server, size_t sequence,
                              int parameters,
                              char cells[TABLE_MAX_COLUMNS][TABLE_CELL_CAPACITY])
{
    if (parameters) {
        snprintf(cells[0], TABLE_CELL_CAPACITY, "%zu", sequence);
        snprintf(cells[1], TABLE_CELL_CAPACITY, "%s", server->assigned_ip);
        snprintf(cells[2], TABLE_CELL_CAPACITY, "%s", server->subnet_mask);
        snprintf(cells[3], TABLE_CELL_CAPACITY, "%s", server->gateway);
        snprintf(cells[4], TABLE_CELL_CAPACITY, "%s", server->dns);
        snprintf(cells[5], TABLE_CELL_CAPACITY, "%s", server->lease);
        snprintf(cells[6], TABLE_CELL_CAPACITY, "%llu ms",
                 server->response_ms);
        return;
    }

    snprintf(cells[0], TABLE_CELL_CAPACITY, "%zu", sequence);
    snprintf(cells[1], TABLE_CELL_CAPACITY, "%zu", server->adapter_number);
    snprintf(cells[2], TABLE_CELL_CAPACITY,
             "%04d-%02d-%02d %02d:%02d:%02d",
             server->discovered_at.tm_year + 1900,
             server->discovered_at.tm_mon + 1,
             server->discovered_at.tm_mday, server->discovered_at.tm_hour,
             server->discovered_at.tm_min, server->discovered_at.tm_sec);
    snprintf(cells[3], TABLE_CELL_CAPACITY, "%s", server->server_ip);
    snprintf(cells[4], TABLE_CELL_CAPACITY, "%s", server->server_mac);
    snprintf(cells[5], TABLE_CELL_CAPACITY, "%s", server->device_vendor);
}

static void print_server_table(int parameters)
{
    static const char *const identity_colors[] = {
        "\033[96m", "\033[93m", "\033[92m",
        "\033[94m", "\033[95m", "\033[91m"
    };
    static const char *const parameter_colors[] = {
        "\033[96m", "\033[93m", "\033[92m", "\033[94m",
        "\033[95m", "\033[91m", "\033[36m"
    };
    static const char *const identity_headers[] = {
        "发现序号", "网卡序号", "发现时间", "服务器 IP", "服务器 MAC", "设备/厂商"
    };
    static const char *const parameter_headers[] = {
        "发现序号", "分配 IP", "子网掩码", "网关", "DNS", "租期", "响应时间"
    };
    const char *const *headers = parameters ? parameter_headers : identity_headers;
    const char *const *colors = parameters ? parameter_colors : identity_colors;
    size_t column_count = parameters ? 7 : 6;
    size_t widths[TABLE_MAX_COLUMNS] = { 0 };
    size_t i;

    for (i = 0; i < column_count; ++i)
        widths[i] = text_display_width(headers[i]);
    for (i = 0; i < g_server_count; ++i) {
        char cells[TABLE_MAX_COLUMNS][TABLE_CELL_CAPACITY] = { { 0 } };
        const char *row[TABLE_MAX_COLUMNS];
        size_t column;
        make_server_cells(&g_servers[i], i + 1, parameters, cells);
        for (column = 0; column < column_count; ++column)
            row[column] = cells[column];
        update_column_widths(widths, row, column_count);
    }

    printf("\n%s：\n", parameters ? "DHCP 分配参数" : "DHCP 服务器信息");
    print_table_border(widths, column_count);
    print_colored_table_header(headers, widths, colors, column_count);
    print_table_border(widths, column_count);
    for (i = 0; i < g_server_count; ++i) {
        char cells[TABLE_MAX_COLUMNS][TABLE_CELL_CAPACITY] = { { 0 } };
        const char *row[TABLE_MAX_COLUMNS];
        size_t column;
        make_server_cells(&g_servers[i], i + 1, parameters, cells);
        for (column = 0; column < column_count; ++column)
            row[column] = cells[column];
        print_table_row(row, widths, column_count);
    }
    print_table_border(widths, column_count);
}

static int delete_arp_entry(unsigned int interface_index,
                            struct in_addr target_address)
{
    struct {
        struct nlmsghdr header;
        struct ndmsg message;
        unsigned char attribute_buffer[256];
    } request;
    struct rtattr *attribute;
    struct sockaddr_nl kernel;
    int fd;
    size_t message_length;

    memset(&request, 0, sizeof(request));
    request.header.nlmsg_len = NLMSG_LENGTH(sizeof(request.message));
    request.header.nlmsg_type = RTM_DELNEIGH;
    request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    request.header.nlmsg_seq = (uint32_t)monotonic_ms();
    request.message.ndm_family = AF_INET;
    request.message.ndm_ifindex = (int)interface_index;
    request.message.ndm_state = NUD_PERMANENT;

    attribute = (struct rtattr *)((char *)&request +
                                  NLMSG_ALIGN(request.header.nlmsg_len));
    attribute->rta_type = NDA_DST;
    attribute->rta_len = RTA_LENGTH(sizeof(target_address));
    memcpy(RTA_DATA(attribute), &target_address, sizeof(target_address));
    request.header.nlmsg_len = (uint32_t)(NLMSG_ALIGN(request.header.nlmsg_len) +
                                          RTA_ALIGN(attribute->rta_len));

    fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0)
        return errno;
    memset(&kernel, 0, sizeof(kernel));
    kernel.nl_family = AF_NETLINK;
    message_length = request.header.nlmsg_len;
    if (sendto(fd, &request, message_length, 0,
               (struct sockaddr *)&kernel, sizeof(kernel)) < 0) {
        int saved_errno = errno;
        close(fd);
        return saved_errno;
    }
    {
        unsigned char response[4096];
        ssize_t received = recv(fd, response, sizeof(response), 0);
        int saved_errno = errno;
        close(fd);
        if (received < 0)
            return saved_errno;
        {
            struct nlmsghdr *header;
            int remaining = (int)received;
            for (header = (struct nlmsghdr *)response;
                 NLMSG_OK(header, remaining);
                 header = NLMSG_NEXT(header, remaining)) {
                if (header->nlmsg_type == NLMSG_ERROR) {
                    struct nlmsgerr *error = NLMSG_DATA(header);
                    return error->error ? -error->error : 0;
                }
            }
        }
    }
    return 0;
}

static int send_arp_request(int arp_socket, const AdapterInfo *adapter,
                            struct in_addr target_address)
{
    struct {
        struct ethhdr ethernet;
        struct arphdr arp;
        unsigned char sender_mac[6];
        unsigned char sender_ip[4];
        unsigned char target_mac[6];
        unsigned char target_ip[4];
    } __attribute__((packed)) packet;
    struct sockaddr_ll destination;

    memset(&packet, 0, sizeof(packet));
    memset(packet.ethernet.h_dest, 0xFF, ETH_ALEN);
    memcpy(packet.ethernet.h_source, adapter->mac, ETH_ALEN);
    packet.ethernet.h_proto = htons(ETH_P_ARP);
    packet.arp.ar_hrd = htons(ARPHRD_ETHER);
    packet.arp.ar_pro = htons(ETH_P_IP);
    packet.arp.ar_hln = ETH_ALEN;
    packet.arp.ar_pln = sizeof(struct in_addr);
    packet.arp.ar_op = htons(ARPOP_REQUEST);
    memcpy(packet.sender_mac, adapter->mac, ETH_ALEN);
    if (adapter->has_ipv4) {
        struct in_addr sender_address;
        if (inet_pton(AF_INET, adapter->ipv4, &sender_address) == 1)
            memcpy(packet.sender_ip, &sender_address, sizeof(sender_address));
    }
    memcpy(packet.target_ip, &target_address, sizeof(target_address));

    memset(&destination, 0, sizeof(destination));
    destination.sll_family = AF_PACKET;
    destination.sll_ifindex = (int)adapter->interface_index;
    destination.sll_halen = ETH_ALEN;
    memset(destination.sll_addr, 0xFF, ETH_ALEN);
    return (int)sendto(arp_socket, &packet, sizeof(packet), 0,
                       (struct sockaddr *)&destination, sizeof(destination));
}

static int collect_arp_replies(int arp_socket, struct in_addr target_address,
                               unsigned char macs[][6], size_t *mac_count,
                               size_t mac_capacity, int wait_ms)
{
    unsigned long long deadline = monotonic_ms() + (unsigned long long)wait_ms;
    int found = 0;
    for (;;) {
        unsigned long long now = monotonic_ms();
        int remaining;
        struct pollfd descriptor;
        int ready;
        unsigned char frame[2048];
        ssize_t length;
        struct ethhdr *ethernet;
        struct arphdr *arp;
        unsigned char *sender_mac;
        struct in_addr sender_ip;

        if (now >= deadline)
            return found;
        remaining = (int)(deadline - now);
        descriptor.fd = arp_socket;
        descriptor.events = POLLIN;
        descriptor.revents = 0;
        ready = poll(&descriptor, 1, remaining);
        if (ready < 0 && errno == EINTR)
            continue;
        if (ready <= 0)
            return found;
        length = recv(arp_socket, frame, sizeof(frame), 0);
        if (length < (ssize_t)(sizeof(*ethernet) + sizeof(*arp) +
                               2 * ETH_ALEN + 2 * sizeof(struct in_addr)))
            continue;
        ethernet = (struct ethhdr *)frame;
        if (ntohs(ethernet->h_proto) != ETH_P_ARP)
            continue;
        arp = (struct arphdr *)(frame + sizeof(*ethernet));
        if (ntohs(arp->ar_hrd) != ARPHRD_ETHER ||
            ntohs(arp->ar_pro) != ETH_P_IP ||
            arp->ar_hln != ETH_ALEN || arp->ar_pln != sizeof(struct in_addr) ||
            ntohs(arp->ar_op) != ARPOP_REPLY)
            continue;
        sender_mac = (unsigned char *)(arp + 1);
        memcpy(&sender_ip, sender_mac + ETH_ALEN, sizeof(sender_ip));
        if (sender_ip.s_addr != target_address.s_addr ||
            memcmp(sender_mac, ethernet->h_source, ETH_ALEN) != 0)
            continue;
        {
            size_t i;
            int exists = 0;
            for (i = 0; i < *mac_count; ++i) {
                if (memcmp(macs[i], sender_mac, ETH_ALEN) == 0) {
                    exists = 1;
                    break;
                }
            }
            if (!exists && *mac_count < mac_capacity) {
                memcpy(macs[(*mac_count)++], sender_mac, ETH_ALEN);
                found = 1;
            }
        }
    }
}

static int resolve_macs(const AdapterInfo *adapter, int arp_socket,
                        const char *server_ip, unsigned char macs[][6],
                        size_t *mac_count, int *arp_delete_error)
{
    struct in_addr target_address;
    int probe;
    *mac_count = 0;
    if (inet_pton(AF_INET, server_ip, &target_address) != 1)
        return 0;
    for (probe = 0; probe < ARP_PROBES_PER_OFFER; ++probe) {
        int delete_result = delete_arp_entry(adapter->interface_index,
                                             target_address);
        if (delete_result != 0 && delete_result != ENOENT &&
            delete_result != ESRCH && *arp_delete_error == 0)
            *arp_delete_error = delete_result;
        if (arp_socket >= 0) {
            if (send_arp_request(arp_socket, adapter, target_address) < 0) {
                if (errno != EPERM && errno != EACCES)
                    fprintf(stderr, "网卡 %s 发送 ARP 请求失败: %s\n",
                            adapter->name, strerror(errno));
            } else
                collect_arp_replies(arp_socket, target_address, macs,
                                    mac_count, ARP_PROBES_PER_OFFER,
                                    ARP_PROBE_INTERVAL_MS);
        }
    }
    return *mac_count != 0;
}

static int parse_offer(const unsigned char *packet, size_t length,
                       uint32_t xid, const AdapterInfo *adapter,
                       const struct sockaddr_in *source, DHCPOffer *offer)
{
    size_t offset = 240;
    int message_type = 0;
    uint32_t wire_xid = htonl(xid);

    if (length < 240 || packet[0] != 2 || packet[1] != 1 || packet[2] != 6)
        return 0;
    if (memcmp(packet + 4, &wire_xid, sizeof(wire_xid)) != 0 ||
        memcmp(packet + 28, adapter->mac, sizeof(adapter->mac)) != 0)
        return 0;
    if (packet[236] != 99 || packet[237] != 130 ||
        packet[238] != 83 || packet[239] != 99)
        return 0;

    memset(offer, 0, sizeof(*offer));
    copy_ipv4(offer->assigned_ip, sizeof(offer->assigned_ip), packet + 16);
    while (offset < length) {
        unsigned char option = packet[offset++];
        unsigned char option_length;
        const unsigned char *value;
        if (option == 255)
            break;
        if (option == 0)
            continue;
        if (offset >= length)
            return 0;
        option_length = packet[offset++];
        if (offset + option_length > length)
            return 0;
        value = packet + offset;
        switch (option) {
        case 1:
            if (option_length == 4)
                copy_ipv4(offer->subnet_mask, sizeof(offer->subnet_mask), value);
            break;
        case 3:
            format_address_list(offer->gateway, sizeof(offer->gateway),
                                value, option_length);
            break;
        case 6:
            format_address_list(offer->dns, sizeof(offer->dns),
                                value, option_length);
            break;
        case 12:
            copy_option_text(offer->hostname, sizeof(offer->hostname),
                             value, option_length);
            break;
        case 51:
            if (option_length == 4) {
                uint32_t lease_seconds = ((uint32_t)value[0] << 24) |
                    ((uint32_t)value[1] << 16) |
                    ((uint32_t)value[2] << 8) | value[3];
                if (lease_seconds == UINT32_MAX)
                    snprintf(offer->lease, sizeof(offer->lease), "无限");
                else
                    snprintf(offer->lease, sizeof(offer->lease),
                             "%u 秒", lease_seconds);
            }
            break;
        case 53:
            if (option_length == 1)
                message_type = value[0];
            break;
        case 54:
            if (option_length == 4)
                copy_ipv4(offer->server_ip, sizeof(offer->server_ip), value);
            break;
        case 60:
            copy_option_text(offer->vendor_class, sizeof(offer->vendor_class),
                             value, option_length);
            break;
        default:
            break;
        }
        offset += option_length;
    }
    if (message_type != 2)
        return 0;
    if (!offer->server_ip[0] &&
        !inet_ntop(AF_INET, &source->sin_addr, offer->server_ip,
                   sizeof(offer->server_ip)))
        return 0;
    return 1;
}

static int find_server(size_t adapter_number, const char *server_ip,
                       const char *server_mac)
{
    size_t i;
    for (i = 0; i < g_server_count; ++i) {
        if (g_servers[i].adapter_number == adapter_number &&
            strcmp(g_servers[i].server_ip, server_ip) == 0 &&
            strcmp(g_servers[i].server_mac, server_mac) == 0)
            return (int)i;
    }
    return -1;
}

static void update_server_offer(DHCPServer *server, const DHCPOffer *offer,
                                unsigned long long response_ms)
{
    snprintf(server->assigned_ip, sizeof(server->assigned_ip), "%s",
             offer->assigned_ip[0] ? offer->assigned_ip : "未提供");
    snprintf(server->subnet_mask, sizeof(server->subnet_mask), "%s",
             offer->subnet_mask[0] ? offer->subnet_mask : "未提供");
    snprintf(server->gateway, sizeof(server->gateway), "%s",
             offer->gateway[0] ? offer->gateway : "未提供");
    snprintf(server->dns, sizeof(server->dns), "%s",
             offer->dns[0] ? offer->dns : "未提供");
    snprintf(server->lease, sizeof(server->lease), "%s",
             offer->lease[0] ? offer->lease : "未提供");
    server->response_ms = response_ms;
}

static int store_server(size_t adapter_number, const DHCPOffer *offer,
                        const unsigned char *mac, const char *mac_text,
                        unsigned long long response_ms)
{
    DHCPServer *server;
    int existing_index = find_server(adapter_number, offer->server_ip, mac_text);
    if (existing_index >= 0)
        return 0;

    if (strcmp(mac_text, "未知") != 0) {
        int unknown_index = find_server(adapter_number, offer->server_ip, "未知");
        if (unknown_index >= 0) {
            server = &g_servers[unknown_index];
            snprintf(server->server_mac, sizeof(server->server_mac), "%s", mac_text);
            build_device_vendor(server->device_vendor,
                                sizeof(server->device_vendor), mac, offer);
            update_server_offer(server, offer, response_ms);
            return 1;
        }
    }

    if (g_server_count == g_server_capacity) {
        size_t new_capacity = g_server_capacity ? g_server_capacity * 2 : 16;
        DHCPServer *new_servers = realloc(g_servers,
                                           new_capacity * sizeof(*new_servers));
        if (!new_servers) {
            fprintf(stderr, "保存 DHCP 服务器结果失败。\n");
            return -1;
        }
        g_servers = new_servers;
        g_server_capacity = new_capacity;
    }

    server = &g_servers[g_server_count];
    memset(server, 0, sizeof(*server));
    snprintf(server->server_ip, sizeof(server->server_ip), "%s", offer->server_ip);
    snprintf(server->server_mac, sizeof(server->server_mac), "%s", mac_text);
    build_device_vendor(server->device_vendor, sizeof(server->device_vendor),
                        mac, offer);
    update_server_offer(server, offer, response_ms);
    server->adapter_number = adapter_number;
    time_t discovered = time(NULL);
    localtime_r(&discovered, &server->discovered_at);
    ++g_server_count;
    return 1;
}

static int add_server(size_t adapter_number, const AdapterInfo *adapter,
                      int arp_socket, const DHCPOffer *offer,
                      unsigned long long response_ms)
{
    unsigned char macs[ARP_PROBES_PER_OFFER][6];
    size_t mac_count = 0;
    size_t i;
    int arp_delete_error = 0;
    int added_count = 0;

    resolve_macs(adapter, arp_socket, offer->server_ip, macs,
                 &mac_count, &arp_delete_error);
    if (arp_delete_error != 0 && arp_delete_error != ENOENT &&
        arp_delete_error != ESRCH) {
        fprintf(stderr,
                "网卡 %s 删除 %s 的 ARP 缓存失败: %s；请以 root 或具备 CAP_NET_ADMIN 的权限运行。\n",
                adapter->name, offer->server_ip, strerror(arp_delete_error));
    }
    if (mac_count == 0) {
        unsigned char unknown_mac[6] = { 0 };
        int added = store_server(adapter_number, offer, unknown_mac, "未知",
                                 response_ms);
        if (added < 0)
            return -1;
        fprintf(stderr,
                "网卡 %s 对 DHCP 服务器 %s 的 %d 次 ARP 探测均未得到 MAC；检查 root/CAP_NET_RAW 权限。\n",
                adapter->name, offer->server_ip, ARP_PROBES_PER_OFFER);
        return added;
    }

    for (i = 0; i < mac_count; ++i) {
        char mac_text[18];
        int added;
        format_mac(mac_text, sizeof(mac_text), macs[i]);
        added = store_server(adapter_number, offer, macs[i], mac_text,
                             response_ms);
        if (added < 0)
            return -1;
        added_count += added;
    }
    return added_count;
}

static int build_dhcp_discover(unsigned char *packet, size_t capacity,
                               const unsigned char *mac, uint32_t xid)
{
    static const unsigned char parameter_request_list[] = {
        1, 3, 6, 12, 15, 51, 54, 58, 59, 66, 67
    };
    uint32_t wire_xid = htonl(xid);
    size_t offset = 240;
    if (capacity < 300)
        return 0;
    memset(packet, 0, capacity);
    packet[0] = 1;
    packet[1] = 1;
    packet[2] = 6;
    memcpy(packet + 4, &wire_xid, sizeof(wire_xid));
    packet[10] = 0x80;
    memcpy(packet + 28, mac, 6);
    packet[236] = 99;
    packet[237] = 130;
    packet[238] = 83;
    packet[239] = 99;
    packet[offset++] = 53;
    packet[offset++] = 1;
    packet[offset++] = 1;
    packet[offset++] = 55;
    packet[offset++] = sizeof(parameter_request_list);
    memcpy(packet + offset, parameter_request_list,
           sizeof(parameter_request_list));
    offset += sizeof(parameter_request_list);
    packet[offset++] = 255;
    return 300;
}

static int open_dhcp_socket(const AdapterInfo *adapter)
{
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);
    int enabled = 1;
    struct sockaddr_in local;
    if (fd < 0) {
        fprintf(stderr, "网卡 %s 创建 DHCP socket 失败: %s\n",
                adapter->name, strerror(errno));
        return -1;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled)) < 0 ||
        setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &enabled, sizeof(enabled)) < 0 ||
        setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, adapter->name,
                   (socklen_t)(strlen(adapter->name) + 1)) < 0) {
        fprintf(stderr, "网卡 %s 配置 DHCP socket 失败: %s\n",
                adapter->name, strerror(errno));
        close(fd);
        return -1;
    }
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_port = htons(DHCP_CLIENT_PORT);
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0) {
        fprintf(stderr,
                "网卡 %s 绑定 UDP 68 失败: %s（检查 root 权限或 DHCP 客户端服务）\n",
                adapter->name, strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

static int open_arp_socket(const AdapterInfo *adapter)
{
    int fd = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(ETH_P_ARP));
    struct sockaddr_ll local;
    if (fd < 0) {
        fprintf(stderr,
                "网卡 %s 创建原始 ARP socket 失败: %s；同 IP 多 MAC 探测需要 root/CAP_NET_RAW。\n",
                adapter->name, strerror(errno));
        return -1;
    }
    memset(&local, 0, sizeof(local));
    local.sll_family = AF_PACKET;
    local.sll_protocol = htons(ETH_P_ARP);
    local.sll_ifindex = (int)adapter->interface_index;
    if (bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0) {
        fprintf(stderr, "网卡 %s 绑定 ARP socket 失败: %s\n",
                adapter->name, strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

static int scan_adapter(const AdapterInfo *adapter, size_t adapter_number)
{
    int dhcp_socket = open_dhcp_socket(adapter);
    int arp_socket;
    struct sockaddr_in destination;
    uint32_t xid = (uint32_t)(monotonic_ms() ^
                              (adapter_number * 2654435761U) ^ getpid());
    int found_in_window;

    if (dhcp_socket < 0)
        return 0;
    arp_socket = open_arp_socket(adapter);
    memset(&destination, 0, sizeof(destination));
    destination.sin_family = AF_INET;
    destination.sin_port = htons(DHCP_SERVER_PORT);
    destination.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    printf("\n扫描网卡 %zu: %s (%s)\n", adapter_number, adapter->name,
           adapter->has_ipv4 ? adapter->ipv4 : "无 IPv4");

    do {
        unsigned char packet[DHCP_PACKET_SIZE];
        int packet_length;
        unsigned long long window_start = monotonic_ms();
        unsigned long long next_send = window_start;
        found_in_window = 0;
        ++xid;
        packet_length = build_dhcp_discover(packet, sizeof(packet),
                                            adapter->mac, xid);
        if (!packet_length) {
            if (arp_socket >= 0)
                close(arp_socket);
            close(dhcp_socket);
            return 0;
        }

        while (g_running && monotonic_ms() - window_start < DHCP_SCAN_WINDOW_MS) {
            unsigned long long now = monotonic_ms();
            unsigned long long elapsed;
            unsigned long long until_send;
            struct pollfd descriptor;
            int timeout;
            int ready;

            if (now >= next_send) {
                if (sendto(dhcp_socket, packet, (size_t)packet_length, 0,
                           (struct sockaddr *)&destination,
                           sizeof(destination)) < 0) {
                    fprintf(stderr, "网卡 %s 发送 DHCP Discover 失败: %s\n",
                            adapter->name, strerror(errno));
                    if (arp_socket >= 0)
                        close(arp_socket);
                    close(dhcp_socket);
                    return 0;
                }
                next_send = now + DHCP_RETRY_INTERVAL_MS;
            }
            now = monotonic_ms();
            elapsed = now - window_start;
            if (elapsed >= DHCP_SCAN_WINDOW_MS)
                break;
            until_send = next_send > now ? next_send - now : 0;
            timeout = (int)(DHCP_SCAN_WINDOW_MS - elapsed);
            if (until_send < (unsigned long long)timeout)
                timeout = (int)until_send;
            descriptor.fd = dhcp_socket;
            descriptor.events = POLLIN;
            descriptor.revents = 0;
            ready = poll(&descriptor, 1, timeout);
            if (ready < 0) {
                if (errno == EINTR)
                    continue;
                fprintf(stderr, "网卡 %s 等待 DHCP 响应失败: %s\n",
                        adapter->name, strerror(errno));
                if (arp_socket >= 0)
                    close(arp_socket);
                close(dhcp_socket);
                return 0;
            }
            if (ready > 0 && (descriptor.revents & POLLIN)) {
                unsigned char response[1500];
                struct sockaddr_in source;
                socklen_t source_length = sizeof(source);
                ssize_t received = recvfrom(dhcp_socket, response, sizeof(response), 0,
                                            (struct sockaddr *)&source,
                                            &source_length);
                if (received < 0) {
                    if (errno == EINTR || errno == EAGAIN)
                        continue;
                    fprintf(stderr, "网卡 %s 接收 DHCP 响应失败: %s\n",
                            adapter->name, strerror(errno));
                    continue;
                }
                {
                    DHCPOffer offer;
                    if (parse_offer(response, (size_t)received, xid,
                                    adapter, &source, &offer)) {
                        unsigned long long response_ms =
                            monotonic_ms() - window_start;
                        int added = add_server(adapter_number, adapter,
                                               arp_socket, &offer, response_ms);
                        if (added < 0) {
                            if (arp_socket >= 0)
                                close(arp_socket);
                            close(dhcp_socket);
                            return 0;
                        }
                        if (added > 0)
                            found_in_window = 1;
                    }
                }
            }
        }
        if (found_in_window)
            printf("网卡 %zu 本轮发现新服务器，继续扫描 2 秒以查找其他服务器。\n",
                   adapter_number);
    } while (g_running && found_in_window);

    if (arp_socket >= 0)
        close(arp_socket);
    close(dhcp_socket);
    printf("网卡 %zu 本轮无新服务器，切换到下一张网卡。\n", adapter_number);
    return 1;
}

int main(void)
{
    AdapterInfo *adapters = NULL;
    size_t adapter_count = 0;
    size_t oui_count;
    size_t i;

    setlocale(LC_ALL, "");
    g_color_enabled = isatty(STDOUT_FILENO);
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    oui_count = load_oui_database();
    if (oui_count)
        printf("已加载 %zu 条 OUI 记录。\n", oui_count);
    else
        fprintf(stderr, "OUI 数据库不可用；厂商名称将显示为“未知厂商”。\n");

    if (!get_adapters(&adapters, &adapter_count)) {
        free(g_oui_records);
        return 1;
    }
    print_adapters(adapters, adapter_count);
    if (adapter_count == 0) {
        printf("未检测到 IPv4 网卡。\n");
        free(adapters);
        free(g_oui_records);
        return 1;
    }

    for (i = 0; i < adapter_count && g_running; ++i) {
        if (!adapters[i].is_up)
            continue;
        if (adapters[i].interface_index == 0 || !adapters[i].has_mac) {
            printf("网卡 %zu 缺少有效接口索引或 MAC，跳过扫描。\n", i + 1);
            continue;
        }
        scan_adapter(&adapters[i], i + 1);
    }

    printf("\n扫描完成，共发现 %zu 个 DHCP 服务器记录。\n", g_server_count);
    if (g_server_count) {
        print_server_table(0);
        print_server_table(1);
    }
    free(g_servers);
    free(g_oui_records);
    free(adapters);
    return 0;
}
