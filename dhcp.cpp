#define WIN32_LEAN_AND_MEAN
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#ifdef _MSC_VER
#pragma execution_character_set("utf-8")
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <urlmon.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "urlmon.lib")

#define DHCP_SERVER_PORT 67
#define DHCP_CLIENT_PORT 68
#define DHCP_PACKET_SIZE 576
#define DHCP_SCAN_WINDOW_MS 2000
#define DHCP_RETRY_INTERVAL_MS 1000
#define ARP_PROBES_PER_OFFER 6
#define ARP_PROBE_INTERVAL_MS 100
#define TABLE_MAX_COLUMNS 8
#define TABLE_CELL_CAPACITY 512
#define HEADER_COLOR_DISCOVERY \
    (FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY)

typedef struct {
    char name[256];
    char description[256];
    char ipv4[INET_ADDRSTRLEN];
    unsigned char mac[6];
    ULONG interface_index;
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
    char gateway[INET_ADDRSTRLEN];
    char dns[96];
    char lease[32];
    unsigned long long response_ms;
    SYSTEMTIME discovered_at;
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

static DHCPServer* g_servers;
static size_t g_server_count;
static size_t g_server_capacity;
static OUIRecord* g_oui_records;
static size_t g_oui_record_count;
static size_t g_oui_record_capacity;
static HANDLE g_console_handle = INVALID_HANDLE_VALUE;
static WORD g_console_attributes;
static int g_console_colors_enabled;

static void copy_ipv4(char* destination, size_t capacity, const unsigned char* address)
{
    struct in_addr ipv4;
    memcpy(&ipv4.s_addr, address, sizeof(ipv4.s_addr));
    if (InetNtopA(AF_INET, &ipv4, destination, (DWORD)capacity) == NULL)
        destination[0] = '\0';
}

static void copy_option_text(char* destination, size_t capacity,
                             const unsigned char* value, size_t length)
{
    size_t i;
    size_t copied = 0;
    for (i = 0; i < length && copied + 1 < capacity; ++i) {
        unsigned char c = value[i];
        if (c == 0)
            break;
        destination[copied++] = (c >= 32 && c <= 126 && c != '|') ? (char)c : '_';
    }
    destination[copied] = '\0';
}

static int format_address_list(char* destination, size_t capacity,
                               const unsigned char* value, size_t length)
{
    size_t offset = 0;
    size_t i;
    destination[0] = '\0';
    for (i = 0; i + 4 <= length; i += 4) {
        char address[INET_ADDRSTRLEN];
        size_t used;
        copy_ipv4(address, sizeof(address), value + i);
        if (address[0] == '\0')
            continue;
        used = strlen(destination);
        if (used && used + 2 < capacity) {
            destination[used++] = ',';
            destination[used++] = ' ';
            destination[used] = '\0';
        }
        if (used < capacity)
            offset = used;
        if (offset >= capacity)
            break;
        if (strncpy_s(destination + offset, capacity - offset, address, _TRUNCATE) != 0)
            break;
    }
    return destination[0] != '\0';
}

static void format_mac(char* destination, size_t capacity, const unsigned char* mac)
{
    _snprintf_s(destination, capacity, _TRUNCATE, "%02X:%02X:%02X:%02X:%02X:%02X",
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

static int parse_oui_line(const char* line, OUIRecord* record)
{
    const char* marker = strstr(line, "(hex)");
    const char* cursor = line;
    const char* vendor;
    const char* end;
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

static FILE* open_oui_file(void)
{
    static const wchar_t oui_url[] =
        L"https://standards-oui.ieee.org/oui/oui.txt";
    wchar_t path[MAX_PATH];
    wchar_t* file_name;
    DWORD path_length;
    FILE* file = NULL;
    HRESULT download_result;

    path_length = GetModuleFileNameW(NULL, path, MAX_PATH);
    if (path_length == 0 || path_length >= MAX_PATH) {
        fprintf(stderr, "无法获取程序路径，不能定位同目录下的 oui.txt。\n");
        return NULL;
    }

    file_name = wcsrchr(path, L'\\');
    if (!file_name) {
        fprintf(stderr, "程序路径格式无效，不能定位同目录下的 oui.txt。\n");
        return NULL;
    }
    ++file_name;
    if (wcscpy_s(file_name, MAX_PATH - (size_t)(file_name - path), L"oui.txt") != 0) {
        fprintf(stderr, "oui.txt 路径过长。\n");
        return NULL;
    }

    if (_wfopen_s(&file, path, L"rt") == 0) {
        printf("正在使用程序同目录下的 oui.txt。\n");
        return file;
    }
    if (GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES) {
        fprintf(stderr, "程序同目录下的 oui.txt 存在但无法读取，厂商识别不可用。\n");
        return NULL;
    }

    printf("程序同目录下未找到 oui.txt，正在从 IEEE 下载...\n");
    download_result = URLDownloadToFileW(NULL, oui_url, path, 0, NULL);
    if (FAILED(download_result)) {
        DeleteFileW(path);
        fprintf(stderr, "下载 IEEE OUI 数据库失败（HRESULT 0x%08lX），厂商识别不可用。\n",
                (unsigned long)download_result);
        return NULL;
    }

    if (_wfopen_s(&file, path, L"rt") != 0) {
        fprintf(stderr, "IEEE OUI 文件已下载，但无法从程序目录读取；请检查目录权限。\n");
        return NULL;
    }
    printf("IEEE oui.txt 已下载到程序同目录。\n");
    return file;
}

static size_t load_oui_database(void)
{
    char line[512];
    FILE* file = open_oui_file();
    if (!file)
        return 0;

    while (fgets(line, sizeof(line), file)) {
        OUIRecord record;
        OUIRecord* records;
        size_t write_index;
        if (!parse_oui_line(line, &record))
            continue;
        write_index = g_oui_record_count;
        if (write_index >= g_oui_record_capacity) {
            size_t new_capacity = g_oui_record_capacity
                ? g_oui_record_capacity * 2 : 128;
            records = (OUIRecord*)realloc(g_oui_records,
                                          new_capacity * sizeof(*records));
            if (!records) {
                fprintf(stderr, "扩展 OUI 数据库内存失败，已保留已加载条目。\n");
                break;
            }
            g_oui_records = records;
            g_oui_record_capacity = new_capacity;
        }
        if (write_index >= g_oui_record_capacity) {
            fprintf(stderr, "OUI 数据库容量校验失败，停止加载。\n");
            break;
        }
        g_oui_records[write_index] = record;
        g_oui_record_count = write_index + 1;
    }
    fclose(file);
    return g_oui_record_count;
}

static const char* lookup_oui_vendor(const unsigned char* mac)
{
    size_t i;
    const OUIRecord* best_match = NULL;
    for (i = 0; i < g_oui_record_count; ++i) {
        const OUIRecord* record = &g_oui_records[i];
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
    if (best_match)
        return best_match->vendor;
    return "未知厂商";
}

static void build_device_vendor(char* destination, size_t capacity,
                               const unsigned char* mac, const DHCPOffer* offer)
{
    const char* oui_vendor = lookup_oui_vendor(mac);
    if (offer->vendor_class[0] && offer->hostname[0]) {
        _snprintf_s(destination, capacity, _TRUNCATE, "%s; %s; %s",
                    oui_vendor, offer->vendor_class, offer->hostname);
    } else if (offer->vendor_class[0]) {
        _snprintf_s(destination, capacity, _TRUNCATE, "%s; %s",
                    oui_vendor, offer->vendor_class);
    } else if (offer->hostname[0]) {
        _snprintf_s(destination, capacity, _TRUNCATE, "%s; %s",
                    oui_vendor, offer->hostname);
    } else {
        strncpy_s(destination, capacity, oui_vendor, _TRUNCATE);
    }
}

static int get_adapters(AdapterInfo** adapters_out, size_t* count_out)
{
    ULONG buffer_size = 15000;
    ULONG result;
    IP_ADAPTER_ADDRESSES* addresses = NULL;
    IP_ADAPTER_ADDRESSES* current;
    AdapterInfo* adapters;
    size_t count = 0;
    size_t index = 0;

    *adapters_out = NULL;
    *count_out = 0;
    for (;;) {
        addresses = (IP_ADAPTER_ADDRESSES*)malloc(buffer_size);
        if (!addresses) {
            fprintf(stderr, "分配网卡信息缓冲区失败。\n");
            return 0;
        }
        result = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX,
                                      NULL, addresses, &buffer_size);
        if (result != ERROR_BUFFER_OVERFLOW)
            break;
        free(addresses);
        addresses = NULL;
    }
    if (result != NO_ERROR) {
        fprintf(stderr, "枚举网卡失败，错误码: %lu\n", result);
        free(addresses);
        return 0;
    }

    for (current = addresses; current; current = current->Next)
        ++count;
    adapters = (AdapterInfo*)calloc(count ? count : 1, sizeof(*adapters));
    if (!adapters) {
        fprintf(stderr, "分配网卡列表失败。\n");
        free(addresses);
        return 0;
    }

    for (current = addresses; current; current = current->Next) {
        IP_ADAPTER_UNICAST_ADDRESS* unicast;
        AdapterInfo* adapter = &adapters[index];
        strncpy_s(adapter->name, sizeof(adapter->name), current->AdapterName, _TRUNCATE);
        if (current->FriendlyName) {
            WideCharToMultiByte(CP_UTF8, 0, current->FriendlyName, -1,
                                adapter->description, (int)sizeof(adapter->description),
                                NULL, NULL);
        }
        adapter->interface_index = current->IfIndex;
        adapter->is_up = current->OperStatus == IfOperStatusUp;
        if (current->PhysicalAddressLength >= sizeof(adapter->mac)) {
            memcpy(adapter->mac, current->PhysicalAddress, sizeof(adapter->mac));
            adapter->has_mac = 1;
        }

        for (unicast = current->FirstUnicastAddress; unicast; unicast = unicast->Next) {
            struct sockaddr_in* address;
            if (unicast->Address.lpSockaddr->sa_family != AF_INET)
                continue;
            address = (struct sockaddr_in*)unicast->Address.lpSockaddr;
            if (InetNtopA(AF_INET, &address->sin_addr, adapter->ipv4,
                          (DWORD)sizeof(adapter->ipv4)) != NULL)
                adapter->has_ipv4 = 1;
            break;
        }
        ++index;
    }

    free(addresses);
    *adapters_out = adapters;
    *count_out = count;
    return 1;
}

static int is_wide_codepoint(unsigned int codepoint)
{
    return (codepoint >= 0x1100 && codepoint <= 0x115F) ||
        (codepoint >= 0x2329 && codepoint <= 0x232A) ||
        (codepoint >= 0x2E80 && codepoint <= 0xA4CF) ||
        (codepoint >= 0xAC00 && codepoint <= 0xD7A3) ||
        (codepoint >= 0xF900 && codepoint <= 0xFAFF) ||
        (codepoint >= 0xFE10 && codepoint <= 0xFE19) ||
        (codepoint >= 0xFE30 && codepoint <= 0xFE6F) ||
        (codepoint >= 0xFF00 && codepoint <= 0xFF60) ||
        (codepoint >= 0xFFE0 && codepoint <= 0xFFE6) ||
        (codepoint >= 0x1F300 && codepoint <= 0x1FAFF) ||
        (codepoint >= 0x20000 && codepoint <= 0x3FFFD);
}

static int is_combining_codepoint(unsigned int codepoint)
{
    return (codepoint >= 0x0300 && codepoint <= 0x036F) ||
        (codepoint >= 0x1AB0 && codepoint <= 0x1AFF) ||
        (codepoint >= 0x1DC0 && codepoint <= 0x1DFF) ||
        (codepoint >= 0x20D0 && codepoint <= 0x20FF) ||
        (codepoint >= 0xFE20 && codepoint <= 0xFE2F);
}

static size_t text_display_width(const char* text)
{
    wchar_t wide[1024];
    int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text, -1,
                                    wide, (int)(sizeof(wide) / sizeof(wide[0])));
    size_t width = 0;
    int i;

    if (count == 0)
        return strlen(text);
    for (i = 0; i < count - 1; ++i) {
        unsigned int codepoint = (unsigned int)wide[i];
        if (codepoint >= 0xD800 && codepoint <= 0xDBFF &&
            i + 1 < count - 1 && wide[i + 1] >= 0xDC00 && wide[i + 1] <= 0xDFFF) {
            codepoint = 0x10000 + ((codepoint - 0xD800) << 10) +
                ((unsigned int)wide[++i] - 0xDC00);
        }
        if (is_combining_codepoint(codepoint))
            continue;
        width += is_wide_codepoint(codepoint) ? 2 : 1;
    }
    return width;
}

static void print_table_border(const size_t* widths, size_t column_count)
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

static void print_table_row(const char* const* cells, const size_t* widths,
                            size_t column_count)
{
    size_t column;
    putchar('|');
    for (column = 0; column < column_count; ++column) {
        size_t width = text_display_width(cells[column]);
        size_t padding;
        putchar(' ');
        fputs(cells[column], stdout);
        for (padding = width; padding < widths[column]; ++padding)
            putchar(' ');
        fputs(" |", stdout);
    }
    putchar('\n');
}

static void initialize_console_colors(void)
{
    CONSOLE_SCREEN_BUFFER_INFO info;
    g_console_handle = GetStdHandle(STD_OUTPUT_HANDLE);
    if (g_console_handle != INVALID_HANDLE_VALUE &&
        GetConsoleScreenBufferInfo(g_console_handle, &info)) {
        g_console_attributes = info.wAttributes;
        g_console_colors_enabled = 1;
    }
}

static void set_console_foreground(WORD foreground)
{
    if (g_console_colors_enabled) {
        WORD attributes = (WORD)((g_console_attributes & 0xFFF0) |
                                 (foreground & 0x000F));
        SetConsoleTextAttribute(g_console_handle, attributes);
    }
}

static void print_colored_table_header(const char* const* cells,
                                       const size_t* widths,
                                       const WORD* colors,
                                       size_t column_count)
{
    size_t column;
    putchar('|');
    for (column = 0; column < column_count; ++column) {
        size_t width = text_display_width(cells[column]);
        size_t padding;
        putchar(' ');
        set_console_foreground(colors[column]);
        fputs(cells[column], stdout);
        set_console_foreground(g_console_attributes & 0x000F);
        for (padding = width; padding < widths[column]; ++padding)
            putchar(' ');
        fputs(" |", stdout);
    }
    putchar('\n');
}

static void update_column_widths(size_t* widths, const char* const* cells,
                                 size_t column_count)
{
    size_t column;
    for (column = 0; column < column_count; ++column) {
        size_t width = text_display_width(cells[column]);
        if (width > widths[column])
            widths[column] = width;
    }
}

static void make_adapter_cells(const AdapterInfo* adapter, size_t adapter_number,
                               char cells[TABLE_MAX_COLUMNS][TABLE_CELL_CAPACITY])
{
    _snprintf_s(cells[0], TABLE_CELL_CAPACITY, _TRUNCATE, "%zu", adapter_number);
    strncpy_s(cells[1], TABLE_CELL_CAPACITY, adapter->is_up ? "启用" : "停用", _TRUNCATE);
    strncpy_s(cells[2], TABLE_CELL_CAPACITY,
              adapter->has_ipv4 ? adapter->ipv4 : "无 IPv4", _TRUNCATE);
    _snprintf_s(cells[3], TABLE_CELL_CAPACITY, _TRUNCATE, "%s (%s)",
                adapter->description[0] ? adapter->description : adapter->name,
                adapter->name);
}

static void print_adapters(const AdapterInfo* adapters, size_t count)
{
    static const char* headers[] = { "网卡序号", "状态", "IPv4", "名称" };
    size_t widths[4] = { 0, 0, 0, 0 };
    size_t i;

    printf("检测到 %zu 张网卡：\n", count);
    for (i = 0; i < 4; ++i)
        widths[i] = text_display_width(headers[i]);
    for (i = 0; i < count; ++i) {
        char cells[TABLE_MAX_COLUMNS][TABLE_CELL_CAPACITY] = { 0 };
        const char* row[4];
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
        char cells[TABLE_MAX_COLUMNS][TABLE_CELL_CAPACITY] = { 0 };
        const char* row[4];
        size_t column;
        make_adapter_cells(&adapters[i], i + 1, cells);
        for (column = 0; column < 4; ++column)
            row[column] = cells[column];
        print_table_row(row, widths, 4);
    }
    print_table_border(widths, 4);
}

static size_t make_server_cells(const DHCPServer* server, size_t sequence,
                                int parameters,
                                char cells[TABLE_MAX_COLUMNS][TABLE_CELL_CAPACITY])
{
    if (parameters) {
        _snprintf_s(cells[0], TABLE_CELL_CAPACITY, _TRUNCATE, "%zu", sequence);
        strncpy_s(cells[1], TABLE_CELL_CAPACITY, server->assigned_ip, _TRUNCATE);
        strncpy_s(cells[2], TABLE_CELL_CAPACITY, server->subnet_mask, _TRUNCATE);
        strncpy_s(cells[3], TABLE_CELL_CAPACITY, server->gateway, _TRUNCATE);
        strncpy_s(cells[4], TABLE_CELL_CAPACITY, server->dns, _TRUNCATE);
        strncpy_s(cells[5], TABLE_CELL_CAPACITY, server->lease, _TRUNCATE);
        _snprintf_s(cells[6], TABLE_CELL_CAPACITY, _TRUNCATE, "%llu ms",
                    server->response_ms);
        return 7;
    }

    _snprintf_s(cells[0], TABLE_CELL_CAPACITY, _TRUNCATE, "%zu", sequence);
    _snprintf_s(cells[1], TABLE_CELL_CAPACITY, _TRUNCATE, "%zu",
                server->adapter_number);
    _snprintf_s(cells[2], TABLE_CELL_CAPACITY, _TRUNCATE,
                "%04u-%02u-%02u %02u:%02u:%02u",
                (unsigned)server->discovered_at.wYear,
                (unsigned)server->discovered_at.wMonth,
                (unsigned)server->discovered_at.wDay,
                (unsigned)server->discovered_at.wHour,
                (unsigned)server->discovered_at.wMinute,
                (unsigned)server->discovered_at.wSecond);
    strncpy_s(cells[3], TABLE_CELL_CAPACITY, server->server_ip, _TRUNCATE);
    strncpy_s(cells[4], TABLE_CELL_CAPACITY, server->server_mac, _TRUNCATE);
    strncpy_s(cells[5], TABLE_CELL_CAPACITY, server->device_vendor, _TRUNCATE);
    return 6;
}

static void print_server_table(int parameters)
{
    static const WORD identity_colors[] = {
        HEADER_COLOR_DISCOVERY,
        FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY,
        FOREGROUND_GREEN | FOREGROUND_INTENSITY,
        FOREGROUND_BLUE | FOREGROUND_INTENSITY,
        FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY,
        FOREGROUND_RED | FOREGROUND_INTENSITY
    };
    static const WORD parameter_colors[] = {
        HEADER_COLOR_DISCOVERY,
        FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY,
        FOREGROUND_GREEN | FOREGROUND_INTENSITY,
        FOREGROUND_BLUE | FOREGROUND_INTENSITY,
        FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY,
        FOREGROUND_RED | FOREGROUND_INTENSITY,
        FOREGROUND_GREEN | FOREGROUND_BLUE
    };
    static const char* identity_headers[] = {
        "发现序号", "网卡序号", "发现时间", "服务器 IP", "服务器 MAC", "设备/厂商"
    };
    static const char* parameter_headers[] = {
        "发现序号", "分配 IP", "子网掩码", "网关", "DNS", "租期", "响应时间"
    };
    const char* const* headers = parameters ? parameter_headers : identity_headers;
    const WORD* colors = parameters ? parameter_colors : identity_colors;
    size_t column_count = parameters ? 7 : 6;
    size_t widths[TABLE_MAX_COLUMNS] = { 0 };
    size_t i;

    for (i = 0; i < column_count; ++i)
        widths[i] = text_display_width(headers[i]);
    for (i = 0; i < g_server_count; ++i) {
        char cells[TABLE_MAX_COLUMNS][TABLE_CELL_CAPACITY] = { 0 };
        const char* row[TABLE_MAX_COLUMNS];
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
        char cells[TABLE_MAX_COLUMNS][TABLE_CELL_CAPACITY] = { 0 };
        const char* row[TABLE_MAX_COLUMNS];
        size_t column;
        make_server_cells(&g_servers[i], i + 1, parameters, cells);
        for (column = 0; column < column_count; ++column)
            row[column] = cells[column];
        print_table_row(row, widths, column_count);
    }
    print_table_border(widths, column_count);
}

static int resolve_mac(const AdapterInfo* adapter, const char* server_ip,
                       unsigned char* mac, DWORD* arp_delete_error)
{
    ULONG physical_address[2] = { 0, 0 };
    ULONG physical_address_length = 6;
    IPAddr source_address = 0;
    struct in_addr target_address;
    MIB_IPNETROW arp_entry;
    DWORD delete_result;

    if (InetPtonA(AF_INET, server_ip, &target_address) != 1)
        return 0;
    if (adapter->has_ipv4)
        InetPtonA(AF_INET, adapter->ipv4, &source_address);

    memset(&arp_entry, 0, sizeof(arp_entry));
    arp_entry.dwIndex = adapter->interface_index;
    arp_entry.dwAddr = target_address.s_addr;
    delete_result = DeleteIpNetEntry(&arp_entry);
    if (delete_result != NO_ERROR && delete_result != ERROR_NOT_FOUND &&
        delete_result != ERROR_FILE_NOT_FOUND && arp_delete_error &&
        *arp_delete_error == NO_ERROR)
        *arp_delete_error = delete_result;

    if (SendARP(target_address.s_addr, source_address, physical_address,
                &physical_address_length) != NO_ERROR || physical_address_length < 6)
        return 0;
    memcpy(mac, physical_address, 6);
    return 1;
}

static int parse_offer(const unsigned char* packet, int length, unsigned int xid,
                       const AdapterInfo* adapter, const struct sockaddr_in* from,
                       DHCPOffer* offer)
{
    size_t offset = 240;
    int message_type = 0;
    unsigned int wire_xid = htonl(xid);
    struct in_addr source_address;

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
    while (offset < (size_t)length) {
        unsigned char option = packet[offset++];
        unsigned char option_length;
        const unsigned char* value;

        if (option == 255)
            break;
        if (option == 0)
            continue;
        if (offset >= (size_t)length)
            return 0;
        option_length = packet[offset++];
        if (offset + option_length > (size_t)length)
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
            format_address_list(offer->dns, sizeof(offer->dns), value, option_length);
            break;
        case 12:
            copy_option_text(offer->hostname, sizeof(offer->hostname),
                             value, option_length);
            break;
        case 51:
            if (option_length == 4) {
                unsigned long lease_seconds = ((unsigned long)value[0] << 24) |
                    ((unsigned long)value[1] << 16) |
                    ((unsigned long)value[2] << 8) | (unsigned long)value[3];
                if (lease_seconds == 0xFFFFFFFFUL)
                    strncpy_s(offer->lease, sizeof(offer->lease), "无限", _TRUNCATE);
                else
                    _snprintf_s(offer->lease, sizeof(offer->lease), _TRUNCATE,
                                "%lu 秒", lease_seconds);
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
    if (!offer->server_ip[0]) {
        source_address = from->sin_addr;
        if (InetNtopA(AF_INET, &source_address, offer->server_ip,
                      (DWORD)sizeof(offer->server_ip)) == NULL)
            return 0;
    }
    return 1;
}

static int find_server(size_t adapter_number, const char* server_ip, const char* server_mac)
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

static void update_server_offer(DHCPServer* server, const DHCPOffer* offer,
                                unsigned long long response_ms)
{
    strncpy_s(server->assigned_ip, sizeof(server->assigned_ip),
              offer->assigned_ip[0] ? offer->assigned_ip : "未提供", _TRUNCATE);
    strncpy_s(server->subnet_mask, sizeof(server->subnet_mask),
              offer->subnet_mask[0] ? offer->subnet_mask : "未提供", _TRUNCATE);
    strncpy_s(server->gateway, sizeof(server->gateway),
              offer->gateway[0] ? offer->gateway : "未提供", _TRUNCATE);
    strncpy_s(server->dns, sizeof(server->dns),
              offer->dns[0] ? offer->dns : "未提供", _TRUNCATE);
    strncpy_s(server->lease, sizeof(server->lease),
              offer->lease[0] ? offer->lease : "未提供", _TRUNCATE);
    server->response_ms = response_ms;
}

static int store_server(size_t adapter_number, const DHCPOffer* offer,
                        const unsigned char* mac,
                        const char* mac_text, unsigned long long response_ms)
{
    DHCPServer* server;
    int existing_index = find_server(adapter_number, offer->server_ip, mac_text);

    if (existing_index >= 0)
        return 0;

    if (strcmp(mac_text, "未知") != 0) {
        int unknown_index = find_server(adapter_number, offer->server_ip, "未知");
        if (unknown_index >= 0) {
            server = &g_servers[unknown_index];
            strncpy_s(server->server_mac, sizeof(server->server_mac), mac_text, _TRUNCATE);
            build_device_vendor(server->device_vendor, sizeof(server->device_vendor),
                                mac, offer);
            update_server_offer(server, offer, response_ms);
            return 1;
        }
    }

    if (g_server_count == g_server_capacity) {
        size_t new_capacity = g_server_capacity ? g_server_capacity * 2 : 16;
        DHCPServer* new_servers = (DHCPServer*)realloc(
            g_servers, new_capacity * sizeof(*g_servers));
        if (!new_servers) {
            fprintf(stderr, "保存 DHCP 服务器结果失败。\n");
            return -1;
        }
        g_servers = new_servers;
        g_server_capacity = new_capacity;
    }

    server = &g_servers[g_server_count];
    memset(server, 0, sizeof(*server));
    strncpy_s(server->server_ip, sizeof(server->server_ip), offer->server_ip, _TRUNCATE);
    strncpy_s(server->server_mac, sizeof(server->server_mac), mac_text, _TRUNCATE);
    build_device_vendor(server->device_vendor, sizeof(server->device_vendor), mac, offer);
    update_server_offer(server, offer, response_ms);
    server->adapter_number = adapter_number;
    GetLocalTime(&server->discovered_at);

    ++g_server_count;
    return 1;
}

static int add_server(size_t adapter_number, const AdapterInfo* adapter,
                      const DHCPOffer* offer, unsigned long long response_ms)
{
    unsigned char mac[6] = { 0 };
    char mac_text[18];
    DWORD arp_delete_error = NO_ERROR;
    int resolved_count = 0;
    int added_count = 0;
    int probe;

    for (probe = 0; probe < ARP_PROBES_PER_OFFER; ++probe) {
        int added;
        if (resolve_mac(adapter, offer->server_ip, mac, &arp_delete_error)) {
            ++resolved_count;
            format_mac(mac_text, sizeof(mac_text), mac);
            added = store_server(adapter_number, offer, mac,
                                 mac_text, response_ms);
            if (added < 0)
                return -1;
            added_count += added;
        }
        if (probe + 1 < ARP_PROBES_PER_OFFER)
            Sleep(ARP_PROBE_INTERVAL_MS);
    }

    if (arp_delete_error != NO_ERROR) {
        fprintf(stderr,
                "网卡 %zu 删除服务器 %s 的 ARP 缓存失败（错误码 %lu）；请以管理员身份运行以提高不同 MAC 的识别率。\n",
                adapter_number, offer->server_ip, arp_delete_error);
    }
    if (resolved_count == 0) {
        strncpy_s(mac_text, sizeof(mac_text), "未知", _TRUNCATE);
        added_count = store_server(adapter_number, offer, mac,
                                   mac_text, response_ms);
        if (added_count < 0)
            return -1;
        fprintf(stderr,
                "网卡 %zu 对 DHCP 服务器 %s 的 %d 次 ARP 查询均未获得 MAC。\n",
                adapter_number, offer->server_ip, ARP_PROBES_PER_OFFER);
    }
    return added_count;
}

static int build_dhcp_discover(unsigned char* packet, size_t capacity,
                               const unsigned char* mac, unsigned int xid)
{
    static const unsigned char parameter_request_list[] = {
        1, 3, 6, 12, 15, 51, 54, 58, 59, 66, 67
    };
    unsigned int wire_xid = htonl(xid);
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
    packet[offset++] = (unsigned char)sizeof(parameter_request_list);
    memcpy(packet + offset, parameter_request_list, sizeof(parameter_request_list));
    offset += sizeof(parameter_request_list);
    packet[offset++] = 255;
    return 300;
}

static int scan_adapter(const AdapterInfo* adapter, size_t adapter_number)
{
    SOCKET socket_handle;
    struct sockaddr_in local;
    struct sockaddr_in destination;
    ULONGLONG ticks = GetTickCount64();
    unsigned int xid = (unsigned int)(ticks ^ (ticks >> 32) ^
                                     (adapter_number * 2654435761ULL));
    int option = 1;
    int found_in_window;

    socket_handle = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_handle == INVALID_SOCKET) {
        fprintf(stderr, "网卡 %zu 创建 socket 失败: %d\n", adapter_number, WSAGetLastError());
        return 0;
    }
    if (setsockopt(socket_handle, SOL_SOCKET, SO_REUSEADDR,
                   (const char*)&option, sizeof(option)) == SOCKET_ERROR ||
        setsockopt(socket_handle, SOL_SOCKET, SO_BROADCAST,
                   (const char*)&option, sizeof(option)) == SOCKET_ERROR) {
        fprintf(stderr, "网卡 %zu 设置 socket 选项失败: %d\n",
                adapter_number, WSAGetLastError());
        closesocket(socket_handle);
        return 0;
    }

#ifdef IP_UNICAST_IF
    {
        DWORD interface_index = htonl(adapter->interface_index);
        if (setsockopt(socket_handle, IPPROTO_IP, IP_UNICAST_IF,
                       (const char*)&interface_index, sizeof(interface_index)) == SOCKET_ERROR) {
            fprintf(stderr, "网卡 %zu 绑定出口接口失败: %d\n",
                    adapter_number, WSAGetLastError());
            closesocket(socket_handle);
            return 0;
        }
    }
#endif

    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_port = htons(DHCP_CLIENT_PORT);
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(socket_handle, (struct sockaddr*)&local, sizeof(local)) == SOCKET_ERROR) {
        fprintf(stderr, "网卡 %zu 绑定 DHCP 客户端端口失败: %d（可能需要管理员权限或端口已被占用）\n",
                adapter_number, WSAGetLastError());
        closesocket(socket_handle);
        return 0;
    }

    memset(&destination, 0, sizeof(destination));
    destination.sin_family = AF_INET;
    destination.sin_port = htons(DHCP_SERVER_PORT);
    destination.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    printf("\n扫描网卡 %zu: %s (%s)\n", adapter_number,
           adapter->description, adapter->has_ipv4 ? adapter->ipv4 : "无 IPv4");

    do {
        unsigned char packet[DHCP_PACKET_SIZE];
        int packet_length;
        ULONGLONG window_start = GetTickCount64();
        ULONGLONG next_send = window_start;
        found_in_window = 0;
        ++xid;
        packet_length = build_dhcp_discover(packet, sizeof(packet), adapter->mac, xid);
        if (!packet_length) {
            closesocket(socket_handle);
            return 0;
        }

        while (GetTickCount64() - window_start < DHCP_SCAN_WINDOW_MS) {
            ULONGLONG now = GetTickCount64();
            ULONGLONG elapsed;
            ULONGLONG until_send;
            struct timeval timeout;
            fd_set read_set;

            if (now >= next_send) {
                if (sendto(socket_handle, (const char*)packet, packet_length, 0,
                           (struct sockaddr*)&destination, sizeof(destination)) == SOCKET_ERROR) {
                    fprintf(stderr, "网卡 %zu 发送 DHCP Discover 失败: %d\n",
                            adapter_number, WSAGetLastError());
                    closesocket(socket_handle);
                    return 0;
                }
                next_send = now + DHCP_RETRY_INTERVAL_MS;
            }

            now = GetTickCount64();
            elapsed = now - window_start;
            if (elapsed >= DHCP_SCAN_WINDOW_MS)
                break;
            until_send = next_send > now ? next_send - now : 0;
            if (until_send > 200)
                until_send = 200;
            timeout.tv_sec = (long)(until_send / 1000);
            timeout.tv_usec = (long)((until_send % 1000) * 1000);
            FD_ZERO(&read_set);
            FD_SET(socket_handle, &read_set);
            if (select(0, &read_set, NULL, NULL, &timeout) == SOCKET_ERROR) {
                fprintf(stderr, "网卡 %zu 等待 DHCP 响应失败: %d\n",
                        adapter_number, WSAGetLastError());
                closesocket(socket_handle);
                return 0;
            }
            if (FD_ISSET(socket_handle, &read_set)) {
                unsigned char response[1500];
                struct sockaddr_in from;
                int from_length = sizeof(from);
                int received = recvfrom(socket_handle, (char*)response, sizeof(response), 0,
                                        (struct sockaddr*)&from, &from_length);
                if (received == SOCKET_ERROR) {
                    fprintf(stderr, "网卡 %zu 接收 DHCP 响应失败: %d\n",
                            adapter_number, WSAGetLastError());
                    closesocket(socket_handle);
                    return 0;
                }
                {
                    DHCPOffer offer;
                    if (parse_offer(response, received, xid, adapter, &from, &offer)) {
                        unsigned long long response_ms = GetTickCount64() - window_start;
                        int added = add_server(adapter_number, adapter, &offer,
                                               response_ms);
                        if (added < 0) {
                            closesocket(socket_handle);
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
    } while (found_in_window);

    closesocket(socket_handle);
    printf("网卡 %zu 本轮无新服务器，切换到下一张网卡。\n", adapter_number);
    return 1;
}

int main(void)
{
    WSADATA winsock_data;
    AdapterInfo* adapters = NULL;
    size_t adapter_count = 0;
    size_t oui_count;
    size_t i;

    SetConsoleOutputCP(CP_UTF8);
    initialize_console_colors();
    if (WSAStartup(MAKEWORD(2, 2), &winsock_data) != 0) {
        fprintf(stderr, "WSAStartup 初始化失败。\n");
        return 1;
    }
    oui_count = load_oui_database();
    if (oui_count != 0)
        printf("已加载 %zu 条 OUI 记录。\n", oui_count);
    else
        fprintf(stderr, "OUI 数据库没有有效条目，厂商名称将显示为“未知厂商”。\n");

    if (!get_adapters(&adapters, &adapter_count)) {
        free(g_oui_records);
        WSACleanup();
        return 1;
    }
    print_adapters(adapters, adapter_count);
    if (adapter_count == 0) {
        printf("未检测到网卡。\n");
        free(adapters);
        free(g_oui_records);
        WSACleanup();
        return 1;
    }

    for (i = 0; i < adapter_count; ++i) {
        if (!adapters[i].is_up)
            continue;
        if (adapters[i].interface_index == 0 || !adapters[i].has_mac) {
            printf("网卡 %zu 缺少有效接口索引或 MAC，跳过扫描。\n", i + 1);
            continue;
        }
        scan_adapter(&adapters[i], i + 1);
    }

    printf("\n扫描完成，共发现 %zu 个 DHCP 服务器记录。\n", g_server_count);
    if (g_server_count != 0) {
        print_server_table(0);
        print_server_table(1);
    }
    free(g_servers);
    free(adapters);
    free(g_oui_records);
    WSACleanup();
    return 0;
}
