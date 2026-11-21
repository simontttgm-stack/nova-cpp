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

#define LOG_TAG "NovaCore"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

std::atomic<bool> g_is_running{false};
std::thread g_tun_thread;

// Заглушка для маршрутизации (потом здесь будет логика белых списков)
bool should_bypass_dpi(const uint8_t* packet, size_t length) {
    // TODO: Парсинг IP -> TCP -> TLS ClientHello
    // TODO: Проверка SNI по списку доменов
    return false; // Пока ничего не обходим
}

// Заглушка для фрагментации TLS
void apply_dpi_bypass(int tun_fd, const uint8_t* packet, size_t length) {
    // TODO: Разбить пакет на части и отправить через write(tun_fd, ...)
}

void tun_loop(int tun_fd) {
    LOGI("TUN loop started. FD: %d", tun_fd);
    std::vector<uint8_t> buffer(65536); // Максимальный размер IP-пакета

    while (g_is_running.load(std::memory_order_relaxed)) {
        pollfd pfd{};
        pfd.fd = tun_fd;
        pfd.events = POLLIN;

        int ret = poll(&pfd, 1, 100); // Таймаут 100мс для проверки флага g_is_running
        if (ret < 0) {
            LOGE("Poll error");
            break;
        }
        if (ret == 0) continue; // Таймаут, проверяем флаг дальше

        ssize_t bytes_read = read(tun_fd, buffer.data(), buffer.size());
        if (bytes_read < 0) {
            LOGE("Read error from TUN");
            break;
        }
        if (bytes_read == 0) continue;

        // Здесь мы анализируем пакет
        if (should_bypass_dpi(buffer.data(), bytes_read)) {
            apply_dpi_bypass(tun_fd, buffer.data(), bytes_read);
        } else {
            // Если не обходим, отправляем в AmneziaWG/MASQUE (пока просто игнорируем или пишем обратно)
            // В будущем здесь будет вызов функций отправки в прокси-туннель
            // write(tun_fd, buffer.data(), bytes_read); 
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
