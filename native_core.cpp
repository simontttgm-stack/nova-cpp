#include <jni.h>
#include <vector>
#include <string>
#include <thread>
#include <atomic>
#include <unistd.h>
#include <poll.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <android/log.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define LOG_TAG "NovaCore"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

std::atomic<bool> g_is_running{false};
std::thread g_tun_thread;

// Проверяем, является ли пакет TCP и содержит ли он TLS ClientHello (рукопожатие)
bool is_tls_client_hello(const uint8_t* packet, size_t length, size_t& tls_offset) {
    if (length < sizeof(struct iphdr)) return false;
    
    struct iphdr* ip = (struct iphdr*)packet;
    if (ip->protocol != IPPROTO_TCP) return false;

    size_t ip_header_len = ip->ihl * 4;
    if (length < ip_header_len + sizeof(struct tcphdr)) return false;

    struct tcphdr* tcp = (struct tcphdr*)(packet + ip_header_len);
    size_t tcp_header_len = tcp->doff * 4;
    
    size_t payload_offset = ip_header_len + tcp_header_len;
    if (length <= payload_offset) return false;

    // Проверяем, что это TLS Handshake (тип 0x16)
    const uint8_t* payload = packet + payload_offset;
    if (payload[0] != 0x16) return false; 
    
    // Проверяем, что это ClientHello (тип 0x01)
    if (payload[5] != 0x01) return false;

    tls_offset = payload_offset;
    return true;
}

// Функция фрагментации: режем пакет на две части
void fragment_and_send(int tun_fd, const uint8_t* packet, size_t length, size_t tls_offset) {
    struct iphdr* ip = (struct iphdr*)packet;
    struct tcphdr* tcp = (struct tcphdr*)(packet + (ip->ihl * 4));

    // Размер полезной нагрузки TCP
    size_t tcp_payload_len = length - tls_offset;
    
    // Делим пополам (или можно настроить смещение, чтобы разорвать именно SNI)
    // Отступаем 5 байт от начала TLS, чтобы заголовок Handshake остался в первом пакете
    size_t split_point = tls_offset + 5; 
    
    if (split_point >= length) return; // Нечего делить

    size_t first_part_len = split_point;
    size_t second_part_len = length - split_point;

    // Отправляем ПЕРВУЮ часть
    write(tun_fd, packet, first_part_len);

    // Немного ждем, чтобы DPI гарантированно обработал пакеты по отдельности
    usleep(1000); // 1 миллисекунда

    // Готовим ВТОРУЮ часть (копируем оставшиеся байты, но меняем IP/TCP заголовки)
    std::vector<uint8_t> second_packet(second_part_len + (ip->ihl * 4) + (tcp->doff * 4));
    
    // Копируем IP заголовок
    memcpy(second_packet.data(), packet, ip->ihl * 4);
    struct iphdr* ip2 = (struct iphdr*)second_packet.data();
    
    // Копируем TCP заголовок
    memcpy(second_packet.data() + (ip->ihl * 4), packet + (ip->ihl * 4), tcp->doff * 4);
    struct tcphdr* tcp2 = (struct tcphdr*)(second_packet.data() + (ip->ihl * 4));
    
    // Копируем оставшуюся полезную нагрузку
    memcpy(second_packet.data() + tls_offset, packet + split_point, second_part_len);

    // Обновляем длины в заголовках
    ip2->tot_len = htons(second_packet.size());
    tcp2->seq = htonl(ntohl(tcp->seq) + (first_part_len - tls_offset)); // Сдвигаем seq
    
    // Отправляем ВТОРУЮ часть
    write(tun_fd, second_packet.data(), second_packet.size());
    
    LOGI("TLS ClientHello фрагментирован! Отправлено: %zu + %zu байт", first_part_len, second_packet.size());
}

void tun_loop(int tun_fd) {
    LOGI("TUN loop started. FD: %d", tun_fd);
    std::vector<uint8_t> buffer(65536);

    while (g_is_running.load(std::memory_order_relaxed)) {
        pollfd pfd{};
        pfd.fd = tun_fd;
        pfd.events = POLLIN;

        int ret = poll(&pfd, 1, 100);
        if (ret < 0) {
            LOGE("Poll error");
            break;
        }
        if (ret == 0) continue;

        ssize_t bytes_read = read(tun_fd, buffer.data(), buffer.size());
        if (bytes_read < 0) {
            LOGE("Read error from TUN");
            break;
        }
        if (bytes_read == 0) continue;

        size_t tls_offset = 0;
        if (is_tls_client_hello(buffer.data(), bytes_read, tls_offset)) {
            // Если это TLS рукопожатие — обходим DPI!
            fragment_and_send(tun_fd, buffer.data(), bytes_read, tls_offset);
        } else {
            // Весь остальной трафик (UDP для WARP/MASQUE, обычный TCP) 
            // В будущем здесь будет отправка в AmneziaWG. 
            // Пока просто пропускаем, чтобы не сломать сеть окончательно.
        }
    }
    LOGI("TUN loop stopped");
}

extern "C" JNIEXPORT void JNICALL
Java_com_example_nova_NovaVpnService_startNativeCore(JNIEnv* env, jobject, jint tun_fd) {
    if (g_is_running.exchange(true)) {
        LOGI("Core is already running");
        return;
    }
    g_tun_thread = std::thread(tun_loop, tun_fd);
}

extern "C" JNIEXPORT void JNICALL
Java_com_example_nova_NovaVpnService_stopNativeCore(JNIEnv* env, jobject) {
    g_is_running.store(false);
    if (g_tun_thread.joinable()) {
        g_tun_thread.join();
    }
}
