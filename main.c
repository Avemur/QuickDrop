// main.cpp
// Compile with:
//   g++ -std=c++11 main.cpp compression.cpp crypto.cpp encryption.cpp -lsodium -lzstd -I/opt/homebrew/include -L/opt/homebrew/lib -o QuickDrop

#include <iostream>
#include <vector>
#include <thread>
#include <chrono>
#include <cstring>
#include <atomic>
#include <string>
#include <cstdint>
#include <sys/stat.h>
#include <iomanip>

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

#include "compression.h"   // compressChunk, decompressChunk
#include "crypto.h"        // doKeyExchange
#include "encryption.h"    // encryptChunk, decryptChunk

// Configuration constants
static const int    CHUNK_SIZE       = 64 * 1024;  // 64 KB
static const int    PORT_DEFAULT     = 9000;
static const int    DISCOVERY_PORT   = 9001;
static const char*  DISCOVERY_MESSAGE = "QUICKDROP_DISCOVERY";

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
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(port);
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
    addr.sin_port   = htons(port);
    if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) <= 0) {
        perror("inet_pton"); CLOSE_SOCKET(fd); return -1;
    }
    if (connect(fd, (sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect"); CLOSE_SOCKET(fd); return -1;
    }
    std::cout << "[DEBUG] Connected successfully" << std::endl;
    return fd;
}

void sendFile(int fd, const std::string &path, const std::vector<unsigned char>& sessionKey) {
    std::cout << "[DEBUG] Sending file: " << path << std::endl;
    // Determine total file size for progress
    struct stat st;
    if (stat(path.c_str(), &st) != 0) {
        perror("stat"); return;
    }
    size_t totalSize = st.st_size;
    
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) { perror("fopen sendFile"); return; }

    std::vector<char> buffer(CHUNK_SIZE);
    size_t bytesRead;
    uint64_t chunkCounter = 0;
    size_t bytesProcessed = 0;
    auto startTime = std::chrono::steady_clock::now();  // <-- start timer

    while ((bytesRead = fread(buffer.data(), 1, CHUNK_SIZE, f)) > 0) {
        bytesProcessed += bytesRead;

        // compute percentage and MB/s
        auto now     = std::chrono::steady_clock::now();
        double elapsed = std::chrono::duration<double>(now - startTime).count();
        double mbps    = (bytesProcessed / (1024.0 * 1024.0)) / (elapsed > 0 ? elapsed : 1.0);
        int pct       = int((double)bytesProcessed / totalSize * 100);

        // updated progress line with MB/s
        std::cout << "\rProgress: " << pct << "% (" 
                  << std::fixed << std::setprecision(1) 
                  << mbps << " MB/s)" 
                  << std::flush;

        // Compress
        std::vector<char> raw(buffer.begin(), buffer.begin() + bytesRead);
        std::vector<char> comp;
        if (!compressChunk(raw, comp)) { fclose(f); return; }

        // Encrypt
        std::vector<unsigned char> cipher;
        if (!encryptChunk(comp, cipher, sessionKey, chunkCounter++)) {
            std::cerr << "\nEncryption failed" << std::endl;
            fclose(f);
            return;
        }

        // Send header: original size and cipher size
        uint32_t orig = htonl((uint32_t)bytesRead);
        uint32_t cps  = htonl((uint32_t)cipher.size());
        send(fd, (char*)&orig, sizeof(orig), 0);
        send(fd, (char*)&cps,  sizeof(cps),  0);

        // Send the encrypted data
        size_t sent = 0;
        while (sent < cipher.size()) {
            ssize_t s = send(fd, reinterpret_cast<char*>(cipher.data()) + sent, cipher.size() - sent, 0);
            if (s <= 0) { perror("send data"); fclose(f); return; }
            sent += s;
        }
    }

    fclose(f);

    // final line: ensure 100%
    std::cout << "\rProgress: 100% (" 
              << std::fixed << std::setprecision(1)
              << ((bytesProcessed / (1024.0 * 1024.0)) / 
                 (std::chrono::duration<double>(std::chrono::steady_clock::now() - startTime).count())) 
              << " MB/s)\n";
    std::cout << "[DEBUG] Finished sending file" << std::endl;
}

void receiveFile(int fd, const std::string &outPath, const std::vector<unsigned char>& sessionKey) {
    std::cout << "[DEBUG] Receiving to: " << outPath << std::endl;
    FILE* f = fopen(outPath.c_str(), "wb");
    if (!f) { perror("fopen receiveFile"); return; }

    uint64_t chunkCounter = 0;
    while (true) {
        uint32_t orig_n, cps_n;
        if (recv(fd, reinterpret_cast<char*>(&orig_n), sizeof(orig_n), 0) <= 0) break;
        if (recv(fd, reinterpret_cast<char*>(&cps_n),  sizeof(cps_n),  0) <= 0) break;

        size_t orig = ntohl(orig_n);
        size_t cps  = ntohl(cps_n);

        std::vector<unsigned char> cipher(cps);
        size_t recvd = 0;
        while (recvd < cps) {
            ssize_t r = recv(fd, reinterpret_cast<char*>(cipher.data()) + recvd, cps - recvd, 0);
            if (r <= 0) { perror("recv data"); fclose(f); return; }
            recvd += r;
        }

        // Decrypt
        std::vector<char> comp;
        if (!decryptChunk(cipher, comp, sessionKey, chunkCounter++)) {
            std::cerr << "Decryption/auth failed" << std::endl;
            fclose(f);
            return;
        }

        // Decompress
        std::vector<char> decomp;
        if (!decompressChunk(comp, decomp, orig)) {
            std::cerr << "Decompression failed" << std::endl;
            fclose(f);
            return;
        }

        fwrite(decomp.data(), 1, decomp.size(), f);
    }

    fclose(f);
    std::cout << "[DEBUG] Finished receiving file" << std::endl;
}

} // namespace FileTransfer

namespace Discovery {

int createUDPSocket(bool reuse=false, bool broadcast=false) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return -1;
    int opt = 1;
    if (reuse)     setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
    if (broadcast) setsockopt(s, SOL_SOCKET, SO_BROADCAST,   (char*)&opt, sizeof(opt));
    return s;
}

void broadcastAvailability(int port, const std::string &alias) {
    int s = createUDPSocket(false, true);
    sockaddr_in b{};
    b.sin_family      = AF_INET;
    b.sin_port        = htons(DISCOVERY_PORT);
    b.sin_addr.s_addr = INADDR_BROADCAST;
    std::string msg = std::string(DISCOVERY_MESSAGE) + ":" + std::to_string(port) + ":" + alias;
    while (true) {
        sendto(s, msg.c_str(), msg.size(), 0, (sockaddr*)&b, sizeof(b));
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }
    CLOSE_SOCKET(s);
}

struct Receiver { std::string ip; int port; std::string alias; };

std::vector<Receiver> discover(int timeoutSec = 3) {
    std::vector<Receiver> out;
    int s = createUDPSocket(true, true);
    if (s < 0) return out;
    sockaddr_in bindAddr{};
    bindAddr.sin_family      = AF_INET;
    bindAddr.sin_port        = htons(DISCOVERY_PORT);
    bindAddr.sin_addr.s_addr = INADDR_ANY;
    if (bind(s, (sockaddr*)&bindAddr, sizeof(bindAddr)) < 0) { perror("discovery bind"); CLOSE_SOCKET(s); return out; }
    struct timeval tv{}; tv.tv_sec = timeoutSec; tv.tv_usec = 0;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    char buf[256]; sockaddr_in from{}; socklen_t len = sizeof(from);
    ssize_t n = recvfrom(s, buf, sizeof(buf)-1, 0, (sockaddr*)&from, &len);
    if (n > 0) {
        buf[n] = '\0'; std::string msg(buf);
        if (msg.rfind(DISCOVERY_MESSAGE, 0) == 0) {
            size_t p1 = msg.find(':');
            size_t p2 = msg.find(':', p1+1);
            if (p1 != std::string::npos && p2 != std::string::npos) {
                Receiver r;
                r.ip    = inet_ntoa(from.sin_addr);
                r.port  = std::stoi(msg.substr(p1+1, p2-p1-1));
                r.alias = msg.substr(p2+1);
                out.push_back(r);
            }
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
        std::string alias = (argc > 2 ? argv[2] : "QuickDropPeer");
        std::string outFile = (argc > 3 ? argv[3] : "received.bin");
        std::thread bc(Discovery::broadcastAvailability, PORT_DEFAULT, alias);
        bc.detach();
        int lst = FileTransfer::createListener(PORT_DEFAULT);
        std::cout << "QuickDrop listening as '" << alias << "' on port " << PORT_DEFAULT << ". Ctrl-C to quit." << std::endl;
        while (true) {
            sockaddr_in peer{}; socklen_t len = sizeof(peer);
            int conn = accept(lst, (sockaddr*)&peer, &len);
            if (conn < 0) { perror("accept"); break; }
            std::cout << "[DEBUG] Connection from " << inet_ntoa(peer.sin_addr) << std::endl;
            std::vector<unsigned char> sessionKey;
            if (!doKeyExchange(conn, sessionKey)) {
                std::cerr << "Key exchange failed" << std::endl;
                CLOSE_SOCKET(conn);
                continue;
            }
            FileTransfer::receiveFile(conn, outFile, sessionKey);
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
            std::cout << "  " << (i+1) << ": " << peers[i].alias << " (" << peers[i].ip << ":" << peers[i].port << ")" << std::endl;
    }
    else if (cmd == "send" && argc == 3) {
        std::string filepath = argv[2];
        auto peers = Discovery::discover();
        if (peers.empty()) { std::cerr << "No receivers to send to." << std::endl; return 1; }
        auto target = peers[0];
        std::cout << "Sending '" << filepath << "' to " << target.alias << " (" << target.ip << ":" << target.port << ")" << std::endl;
        int sock = FileTransfer::createConnection(target.ip, target.port);
        if (sock < 0) return 1;
        std::vector<unsigned char> sessionKey;
        if (!doKeyExchange(sock, sessionKey)) {
            std::cerr << "Key exchange failed" << std::endl;
            CLOSE_SOCKET(sock);
            return 1;
        }
        FileTransfer::sendFile(sock, filepath, sessionKey);
        CLOSE_SOCKET(sock);
    }
    else if (cmd == "send-to" && argc == 4) {
        std::string filepath = argv[2];
        std::string target = argv[3];
        size_t pos = target.find(':');
        std::string ip = target.substr(0,pos);
        int port = (pos != std::string::npos)? std::stoi(target.substr(pos+1)) : PORT_DEFAULT;
        int sock = FileTransfer::createConnection(ip, port);
        if (sock < 0) return 1;
        std::vector<unsigned char> sessionKey;
        if (!doKeyExchange(sock, sessionKey)) {
            std::cerr << "Key exchange failed" << std::endl;
            CLOSE_SOCKET(sock);
            return 1;
        }
        FileTransfer::sendFile(sock, filepath, sessionKey);
        CLOSE_SOCKET(sock);
    }
    else {
        std::cout << "Usage:\n"
                  << "  QuickDrop listen [alias] [outFile]  # listen with alias and optional output file\n"
                  << "  QuickDrop discover                  # find receivers with aliases\n"
                  << "  QuickDrop send <file>               # discover + send to first peer\n"
                  << "  QuickDrop send-to <file> <ip:port>  # send to specified peer\n";
    }

    FileTransfer::cleanupSockets();
    return 0;
}
