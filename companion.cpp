#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <android/log.h>
#include <mutex>
#include <thread>
#include <chrono>
#include <sys/socket.h>
#include <sys/un.h>
#include <random>
#include <cstdlib>
#include <ctime>

#define LOG_TAG "sys_netd_daemon"
#ifdef NDEBUG
#define LOGD(...) ((void)0)
#define LOGE(...) ((void)0)
#else
#define LOGD(fmt, ...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, fmt, ##__VA_ARGS__)
#define LOGE(fmt, ...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, fmt, ##__VA_ARGS__)
#endif

constexpr const char* MODULE_ROOT = "/data/adb/modules/kirin9000s_ultimate_spoof";
constexpr const char* RUN_DIR = "/data/adb/modules/kirin9000s_ultimate_spoof/running_state";
constexpr const char* COUNT_FILE = "/data/adb/modules/kirin9000s_ultimate_spoof/running_state/instance_count";
constexpr const char* SOCK_TMP = "/data/adb/modules/kirin9000s_ultimate_spoof/running_state/sockpath.tmp";
std::string socketPath;
std::mutex fileMtx;

// 生成12位随机套接字文件名
std::string generateRandomSocketPath() {
    char randBuf[13] = {0};
    std::mt19937 rng(static_cast<unsigned int>(time(nullptr)));
    const char* charTable = "abcdefghijklmnopqrstuvwxyz0123456789";
    for (int i = 0; i < 12; i++) {
        randBuf[i] = charTable[rng() % 36];
    }
    return std::string(RUN_DIR) + "/" + std::string(randBuf) + ".sock";
}

int readInstanceCount() {
    std::lock_guard<std::mutex> lock(fileMtx);
    mkdir(RUN_DIR, 0755);
    FILE* fp = fopen(COUNT_FILE, "r");
    if (!fp) return 0;
    int count = 0;
    fscanf(fp, "%d", &count);
    fclose(fp);
    return count;
}

void writeInstanceCount(int value) {
    std::lock_guard<std::mutex> lock(fileMtx);
    mkdir(RUN_DIR, 0755);
    FILE* fp = fopen(COUNT_FILE, "w");
    if (fp) {
        fprintf(fp, "%d", value);
        fclose(fp);
    }
}

// 500ms周期看门狗巡检，处理进程崩溃残留计数
void watchdogLoop() {
    while (true) {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        int currentCnt = readInstanceCount();
        if (currentCnt <= 0) {
            unlink(socketPath.c_str());
        }
    }
}

int main() {
    // 伪装系统netd进程名
    char procNameBuf[16] = "netd";
    prctl(PR_SET_NAME, procNameBuf, 0, 0, 0);
    mkdir(RUN_DIR, 0755);
    socketPath = generateRandomSocketPath();

    // 写入套接字路径临时文件，供Zygisk模块读取
    FILE* sockFp = fopen(SOCK_TMP, "w");
    if (sockFp) {
        fputs(socketPath.c_str(), sockFp);
        fclose(sockFp);
    }

    std::thread watchdogThread(watchdogLoop);
    watchdogThread.detach();
    unlink(socketPath.c_str());

    int serverFd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un unAddr{};
    unAddr.sun_family = AF_UNIX;
    strncpy(unAddr.sun_path, socketPath.c_str(), sizeof(unAddr.sun_path) - 1);
    bind(serverFd, reinterpret_cast<struct sockaddr*>(&unAddr), sizeof(unAddr));
    chmod(socketPath.c_str(), 0700);
    listen(serverFd, 1);

    int clientFd = accept(serverFd, nullptr, nullptr);
    char cmd;
    while (read(clientFd, &cmd, 1) == 1) {
        int current = readInstanceCount();
        if (cmd == 1) current++;
        else if (cmd == 0) current--;
        if (current < 0) current = 0;
        writeInstanceCount(current);
    }
    close(serverFd);
    unlink(socketPath.c_str());
    return 0;
}
