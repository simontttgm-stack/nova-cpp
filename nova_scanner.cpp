#include <jni.h>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <string>
#include <thread>
#include <atomic>
#include <chrono>
#include <algorithm>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>

struct ServerNode {
    char ip;
    int port;
    int latency_ms;
    bool is_alive;
};

void secure_zero_memory(void* ptr, size_t size) {
    if (!ptr || size == 0) return;
    volatile unsigned char* p = reinterpret_cast<volatile unsigned char*>(ptr);
    while (size--) {
        *p++ = 0;
    }
}

// Проверка реального UDP/QUIC-канала для работы в мобильных сетях (4G/5G)
int probe_endpoint(const char* ip, int port, int timeout_ms) {
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) return -1;

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &addr.sin_addr) <= 0) {
        close(sock);
        return -1;
    }

    // Минимальный QUIC Initial-зонд для проверки прохождения UDP через DPI мобильного оператора
    const unsigned char probe_packet = {
        0xc0, 0x00, 0x00, 0x00, 0x01, 0x08, 0x01, 0x02,
        0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x00, 0x00
    };

    auto start = std::chrono::steady_clock::now();
    ssize_t sent = sendto(sock, probe_packet, sizeof(probe_packet), 0,
                          reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    if (sent < 0) {
        close(sock);
        return -1;
    }

    pollfd pfd{};
    pfd.fd = sock;
    pfd.events = POLLIN;

    int poll_res = poll(&pfd, 1, timeout_ms);
    if (poll_res <= 0) {
        close(sock);
        return -1;
    }

    unsigned char recv_buf;
    ssize_t recvd = recvfrom(sock, recv_buf, sizeof(recv_buf), 0, nullptr, nullptr);
    close(sock);

    if (recvd <= 0) return -1;

    auto end = std::chrono::steady_clock::now();
    return static_cast<int>(
        std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count()
    );
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_example_nova_NativeScanner_scanAndPurgeBestServer(
        JNIEnv* env,
        jclass /* clazz */,
        jobjectArray ip_list,
        jintArray port_list,
        jint timeout_ms) {

    jsize count = env->GetArrayLength(ip_list);
    if (count <= 0) return env->NewStringUTF("");

    size_t buffer_size = static_cast<size_t>(count) * sizeof(ServerNode);
    ServerNode* nodes = static_cast<ServerNode*>(std::malloc(buffer_size));
    if (!nodes) return env->NewStringUTF("");

    std::memset(nodes, 0, buffer_size);

    jint* ports = env->GetIntArrayElements(port_list, nullptr);
    for (jsize i = 0; i < count; ++i) {
        auto j_ip = static_cast<jstring>(env->GetObjectArrayElement(ip_list, i));
        const char* raw_ip = env->GetStringUTFChars(j_ip, nullptr);

        std::strncpy(nodes[i].ip, raw_ip, sizeof(nodes[i].ip) - 1);
        nodes[i].port = ports[i];
        nodes[i].latency_ms = 999999;
        nodes[i].is_alive = false;

        env->ReleaseStringUTFChars(j_ip, raw_ip);
        env->DeleteLocalRef(j_ip);
    }
    env->ReleaseIntArrayElements(port_list, ports, JNI_ABORT);

    std::atomic<int> next_index{0};
    int thread_count = std::min(static_cast<int>(count), 16);
    std::vector<std::thread> workers;
    workers.reserve(thread_count);

    for (int t = 0; t < thread_count; ++t) {
        workers.emplace_back([&]() {
            while (true) {
                int idx = next_index.fetch_add(1);
                if (idx >= count) break;

                int rtt = probe_endpoint(nodes[idx].ip, nodes[idx].port, timeout_ms);
                if (rtt >= 0) {
                    nodes[idx].latency_ms = rtt;
                    nodes[idx].is_alive = true;
                }
            }
        });
    }

    for (auto& w : workers) {
        if (w.joinable()) w.join();
    }

    int best_idx = -1;
    int min_latency = 999999;
    for (int i = 0; i < count; ++i) {
        if (nodes[i].is_alive && nodes[i].latency_ms < min_latency) {
            min_latency = nodes[i].latency_ms;
            best_idx = i;
        }
    }

    char result_buf = {0};
    if (best_idx != -1) {
        std::snprintf(result_buf, sizeof(result_buf), "%s:%d", nodes[best_idx].ip, nodes[best_idx].port);
    }

    jstring j_result = env->NewStringUTF(result_buf);

    secure_zero_memory(nodes, buffer_size);
    std::free(nodes);
    nodes = nullptr;

    secure_zero_memory(result_buf, sizeof(result_buf));

    return j_result;
}
