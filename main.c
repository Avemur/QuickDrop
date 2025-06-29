// QuickDrop main.c
// Compile with: g++ -std=c++11 main.c -o QuickDrop

#include <iostream>
#include <vector>
#include <thread>
#include <chrono>
#include <cstring>
#include <atomic>
#include <string>

#ifdef _WIN32
  #include <winsock2.h>
  #pragma comment(lib, "Ws2_32.lib")
  using socklen_t = int;
  #define CLOSE_SOCKET closesocket
#else
  #include <sys/socket.h>
  #include <arpa/inet.h>
  #include <unistd.h>
  #include <netinet/in.h>
  #define CLOSE_SOCKET close
#endif

// Configuration constants
static const int CHUNK_SIZE = 64 * 1024;  // 64 KB
static const int PORT_DEFAULT = 9000;
static const int DISCOVERY_PORT = 9001;
static const char* DISCOVERY_MESSAGE = "QUICKDROP_DISCOVERY";

namespace FileTransfer {

bool initSockets() {
#ifdef _WIN32
    WSADATA wsa;
    return WSAStartup(MAKEWORD(2,2), &wsa) == 0;
#else
    return true;
#endif
}

void cleanupSockets() {
#ifdef _WIN32
    WSACleanup();
#endif
}

int createListener(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); exit(1); }
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    if (bind(fd, (sockaddr*)&addr, sizeof(addr)) < 0) { perror("bind"); exit(1); }
    if (listen(fd, 1) < 0) { perror("listen"); exit(1); }
    return fd;
}

int createConnection(const std::string &host, int port) {
    std::cout << "[DEBUG] Connecting to " << host << ":" << port << std::endl;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return -1; }
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) <= 0) {
        perror("inet_pton"); CLOSE_SOCKET(fd); return -1;
    }
    if (connect(fd, (sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect"); CLOSE_SOCKET(fd); return -1;
    }
    std::cout << "[DEBUG] Connected successfully" << std::endl;
    return fd;
}

void sendFile(int fd, const std::string &path) {
    std::cout << "[DEBUG] Sending file: " << path << std::endl;
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) { perror("fopen sendFile"); return; }
    char buf[CHUNK_SIZE]; size_t n;
    while ((n = fread(buf,1,CHUNK_SIZE,f)) > 0) {
        size_t sent = 0;
        while (sent < n) {
            ssize_t s = send(fd, buf + sent, n - sent, 0);
            if (s <= 0) { perror("send"); fclose(f); return; }
            sent += s;
        }
    }
    fclose(f);
    std::cout << "[DEBUG] Finished sending file" << std::endl;
}

void receiveFile(int fd, const std::string &out) {
    std::cout << "[DEBUG] Receiving to: " << out << std::endl;
    FILE* f = fopen(out.c_str(), "wb");
    if (!f) { perror("fopen receiveFile"); return; }
    char buf[CHUNK_SIZE]; ssize_t n;
    while ((n = recv(fd, buf, CHUNK_SIZE, 0)) > 0) {
        fwrite(buf,1,n,f);
    }
    if (n < 0) perror("recv");
    fclose(f);
    std::cout << "[DEBUG] Finished receiving file" << std::endl;
}

} // namespace FileTransfer

namespace Discovery {

int createUDPSocket(bool reuse=false, bool broadcast=false) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return -1;
    int opt = 1;
    if (reuse) setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    if (broadcast) setsockopt(s, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt));
    return s;
}

void broadcastAvailability(int port) {
    int s = createUDPSocket(false, true);
    sockaddr_in b{};
    b.sin_family = AF_INET;
    b.sin_port = htons(DISCOVERY_PORT);
    b.sin_addr.s_addr = INADDR_BROADCAST;
    std::string msg = std::string(DISCOVERY_MESSAGE) + ":" + std::to_string(port);
    while (true) {
        sendto(s, msg.c_str(), msg.size(), 0, (sockaddr*)&b, sizeof(b));
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }
    CLOSE_SOCKET(s);
}

struct Receiver { std::string ip; int port; };

std::vector<Receiver> discover(int timeoutSec = 3) {
    std::vector<Receiver> out;
    int s = createUDPSocket(true, true);
    if (s < 0) return out;
    sockaddr_in bindAddr{};
    bindAddr.sin_family = AF_INET;
    bindAddr.sin_port = htons(DISCOVERY_PORT);
    bindAddr.sin_addr.s_addr = INADDR_ANY;
    if (bind(s, (sockaddr*)&bindAddr, sizeof(bindAddr)) < 0) {
        perror("discovery bind"); CLOSE_SOCKET(s); return out;
    }
    struct timeval tv{}; tv.tv_sec = timeoutSec; tv.tv_usec = 0;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    char buf[256]; sockaddr_in from{}; socklen_t len = sizeof(from);
    std::cout << "[DEBUG] Discovering receivers..." << std::endl;
    ssize_t n = recvfrom(s, buf, sizeof(buf)-1, 0, (sockaddr*)&from, &len);
    if (n > 0) {
        buf[n] = '\0'; std::string msg(buf);
        if (msg.rfind(DISCOVERY_MESSAGE, 0) == 0) {
            Receiver r;
            r.ip = inet_ntoa(from.sin_addr);
            size_t pos = msg.find(':');
            r.port = (pos != std::string::npos) ? std::stoi(msg.substr(pos+1)) : PORT_DEFAULT;
            std::cout << "[DEBUG] Found receiver: " << r.ip << ":" << r.port << std::endl;
            out.push_back(r);
        }
    }
    CLOSE_SOCKET(s);
    return out;
}

} // namespace Discovery

int main(int argc, char* argv[]) {
    FileTransfer::initSockets();
    std::string cmd = (argc > 1 ? argv[1] : "");

    if (cmd == "listen") {
        // start broadcasting
        std::thread bc(Discovery::broadcastAvailability, PORT_DEFAULT);
        bc.detach();

        int lst = FileTransfer::createListener(PORT_DEFAULT);
        std::cout << "QuickDrop listening on port " << PORT_DEFAULT << ". Press Ctrl-C to quit." << std::endl;

        while (true) {
            sockaddr_in peer{}; socklen_t len = sizeof(peer);
            int conn = accept(lst, (sockaddr*)&peer, &len);
            if (conn < 0) {
                perror("accept");
                break;
            }
            std::cout << "[DEBUG] Connection from " << inet_ntoa(peer.sin_addr) << std::endl;
            FileTransfer::receiveFile(conn, "received.bin");
            CLOSE_SOCKET(conn);
        }

        CLOSE_SOCKET(lst);
        FileTransfer::cleanupSockets();
        return 0;
    }
    else if (cmd == "discover") {
        auto peers = Discovery::discover();
        if (peers.empty()) std::cout << "No receivers found." << std::endl;
        else for (size_t i=0; i<peers.size(); ++i)
            std::cout << "  " << (i+1) << ": " << peers[i].ip << ":" << peers[i].port << std::endl;
    }
    else if (cmd == "send" && argc == 3) {
        std::string filepath = argv[2];
        auto peers = Discovery::discover();
        if (peers.empty()) { std::cerr << "No receivers to send to." << std::endl; return 1; }
        auto target = peers[0];
        std::cout << "Sending '" << filepath << "' to " << target.ip << ":" << target.port << std::endl;
        int sock = FileTransfer::createConnection(target.ip, target.port);
        if (sock < 0) return 1;
        FileTransfer::sendFile(sock, filepath);
        CLOSE_SOCKET(sock);
    }
    else if (cmd == "send-to" && argc == 4) {
        std::string filepath = argv[2];
        std::string target = argv[3];
        size_t pos = target.find(':');
        std::string ip = target.substr(0, pos);
        int port = (pos != std::string::npos) ? std::stoi(target.substr(pos+1)) : PORT_DEFAULT;
        int sock = FileTransfer::createConnection(ip, port);
        if (sock < 0) return 1;
        FileTransfer::sendFile(sock, filepath);
        CLOSE_SOCKET(sock);
    }
    else {
        std::cout << "Usage:\n"
                  << "  QuickDrop listen               # wait and receive files\n"
                  << "  QuickDrop discover            # find receivers\n"
                  << "  QuickDrop send <file>         # discover + send to first peer\n"
                  << "  QuickDrop send-to <f> <ip:port> # send to specified peer\n";
    }

    FileTransfer::cleanupSockets();
    return 0;
}
