#include <zygisk.hpp>
#include <dlfcn.h>
#include <cstring>
#include <cstdio>
#include <unistd.h>
#include <android/log.h>
#include <fstream>
#include <string>
#include <sys/socket.h>
#include <sys/un.h>
#include <atomic>
#include <mutex>
#include <random>
#include <ctime>
#include <fcntl.h>
#include <errno.h>
#include <sys/ucontext.h>

// 条件编译内嵌必需宏，彻底避免重定义冲突
#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS 38
#endif

#ifndef PR_SET_SECCOMP
#define PR_SET_SECCOMP 22
#endif

#ifndef SECCOMP_MODE_FILTER
#define SECCOMP_MODE_FILTER 2
#endif

#ifndef SECCOMP_RET_TRAP
#define SECCOMP_RET_TRAP 0x00030000
#endif

#ifndef SECCOMP_RET_ALLOW
#define SECCOMP_RET_ALLOW 0x7fff0000
#endif

#ifndef __NR_openat
#define __NR_openat 56
#endif

#ifndef __NR_read
#define __NR_read 63
#endif

#ifndef __NR_close
#define __NR_close 57
#endif

// 内嵌Linux BPF结构体，无系统依赖
struct sock_filter {
    unsigned short code;
    unsigned char jt;
    unsigned char jf;
    unsigned int k;
};

struct sock_fprog {
    unsigned short len;
    struct sock_filter *filter;
};

using namespace zygisk;

#define LOG_TAG "sys_lib_hook"
#ifdef NDEBUG
#define LOGD(...) ((void)0)
#define LOGE(...) ((void)0)
#else
#define LOGD(fmt, ...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, fmt, ##__VA_ARGS__)
#endif

// 麒麟9000S硬件参数
constexpr const char* FAKE_CPUINFO = R"(Processor       : AArch64 Processor rev 0 (aarch64)
Features        : fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp
CPU implementer : 0x48
CPU architecture: 8
CPU variant     : 0x1
CPU part        : 0xd0c
CPU revision    : 0

processor       : 0
BogoMIPS        : 26.00
CPU implementer : 0x48
CPU architecture: 8
CPU variant     : 0x1
CPU part        : 0xd0c
CPU revision    : 0

processor       : 1
BogoMIPS        : 26.00
CPU implementer : 0x48
CPU architecture: 8
CPU variant     : 0x2
CPU part        : 0xd0a
CPU revision    : 0

processor       : 2
BogoMIPS        : 26.00
CPU implementer : 0x48
CPU architecture: 8
CPU variant     : 0x2
CPU part        : 0xd0a
CPU revision    : 0

processor       : 3
BogoMIPS        : 26.00
CPU implementer : 0x48
CPU architecture: 8
CPU variant     : 0x2
CPU part        : 0xd0a
CPU revision    : 0

processor       : 4
BogoMIPS        : 26.00
CPU implementer : 0x48
CPU architecture: 8
CPU variant     : 0x3
CPU part        : 0xd0b
CPU revision    : 0

processor       : 5
BogoMIPS        : 26.00
CPU implementer : 0x48
CPU architecture: 8
CPU variant     : 0x3
CPU part        : 0xd0b
CPU revision    : 0

processor       : 6
BogoMIPS        : 26.00
CPU implementer : 0x48
CPU architecture: 8
CPU variant     : 0x3
CPU part        : 0xd0b
CPU revision    : 0

processor       : 7
BogoMIPS        : 26.00
CPU implementer : 0x48
CPU architecture: 8
CPU variant     : 0x3
CPU part        : 0xd0b
CPU revision    : 0

Hardware        : HiSilicon Kirin 9000S
)";

// 伪造auxv硬件向量数据
constexpr const char FAKE_AUXV[] = "\x10\x00\x00\x00\xef\xfe\xef\x7E\x1A\x00\x00\x00\x1F\x00\x00\x00";
constexpr unsigned long FAKE_HWCAP = 0x7efefeff;
constexpr unsigned long FAKE_HWCAP2 = 0x0000001f;

// 内存虚拟文件结构体
struct FakeFile {
    const char* data;
    size_t dataSize;
    std::atomic<size_t> offset;
    FakeFile(const char* buf, size_t len) : data(buf), dataSize(len), offset(0) {}
};

std::atomic<int> nextFd{9000};
std::mutex fileMapMtx;
std::map<int, FakeFile*> virtualFiles;

std::string targetPackage;
std::string socketPath;

// 15-80μs 原生随机时延模拟
void simulateNativeReadLatency() {
    static thread_local std::mt19937 rng(static_cast<unsigned int>(time(nullptr)));
    long usec = 15 + (rng() % 65);
    struct timespec ts = {0, usec * 1000L};
    nanosleep(&ts, nullptr);
}

// 套接字发送启停指令
void sendCommand(char cmd) {
    int sockFd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
    struct sockaddr_un unAddr{};
    unAddr.sun_family = AF_UNIX;
    strncpy(unAddr.sun_path, socketPath.c_str(), sizeof(unAddr.sun_path) - 1);
    connect(sockFd, reinterpret_cast<sockaddr*>(&unAddr), sizeof(unAddr));
    write(sockFd, &cmd, 1);
    close(sockFd);
}

// 读取目标游戏包名
std::string loadTargetPkg() {
    std::ifstream conf("/data/adb/modules/kirin9000s_ultimate_spoof/target.conf");
    std::string pkg;
    if (conf.is_open()) {
        getline(conf, pkg);
        conf.close();
    }
    // 读取失败使用默认三角洲包名兜底
    if (pkg.empty()) pkg = "com.tencent.tmgp.dfm";
    return pkg;
}

// dl_phdr模块库过滤回调
int filterPhdrCallback(struct dl_phdr_info* info, size_t size, void* data, int (*originCb)(struct dl_phdr_info*, size_t, void*)) {
    if (info->dlpi_name) {
        std::string libName(info->dlpi_name);
        if (libName.find("kirin9000s") != std::string::npos || libName.find("cpu_spoof") != std::string::npos)
            return 0;
    }
    return originCb(info, size, data);
}

// SIGSYS系统调用捕获处理函数
static void sigsysHandler(int sig, siginfo_t* info, void* ctx) {
    ucontext_t* ctxUc = reinterpret_cast<ucontext_t*>(ctx);
    unsigned long* regs = reinterpret_cast<unsigned long*>(&ctxUc->uc_mcontext);
    long syscallNr = regs[8];
    long retVal = -1;

    if (syscallNr == __NR_openat) {
        const char* path = reinterpret_cast<const char*>(regs[1]);
        if (strstr(path, "/proc/cpuinfo")) {
            int fd = nextFd.fetch_add(1);
            std::lock_guard<std::mutex> lock(fileMapMtx);
            virtualFiles[fd] = new FakeFile(FAKE_CPUINFO, sizeof(FAKE_CPUINFO) - 1);
            retVal = fd;
        } else if (strstr(path, "/proc/self/auxv")) {
            int fd = nextFd.fetch_add(1);
            std::lock_guard<std::mutex> lock(fileMapMtx);
            virtualFiles[fd] = new FakeFile(FAKE_AUXV, sizeof(FAKE_AUXV) - 1);
            retVal = fd;
        } else if (strstr(path, "/sys/devices/system/cpu")) {
            errno = ENOENT;
            retVal = -1;
        }
    } else if (syscallNr == __NR_read) {
        int fd = static_cast<int>(regs[0]);
        std::lock_guard<std::mutex> lock(fileMapMtx);
        auto iter = virtualFiles.find(fd);
        if (iter != virtualFiles.end()) {
            FakeFile* file = iter->second;
            simulateNativeReadLatency();
            size_t off = file->offset.load();
            size_t remain = file->dataSize - off;
            size_t readCount = std::min((size_t)regs[2], remain);
            memcpy(reinterpret_cast<void*>(regs[1]), file->data + off, readCount);
            file->offset.fetch_add(readCount);
            retVal = readCount;
        }
    } else if (syscallNr == __NR_close) {
        int fd = static_cast<int>(regs[0]);
        std::lock_guard<std::mutex> lock(fileMapMtx);
        auto iter = virtualFiles.find(fd);
        if (iter != virtualFiles.end()) {
            delete iter->second;
            virtualFiles.erase(iter);
        }
    }
    regs[0] = retVal;
}

class UltimateCpuSpoof : public ModuleBase {
public:
    void onLoad(Api* api, JNIEnv* env) override {
        targetPackage = loadTargetPkg();
        // 读取随机套接字路径
        std::ifstream sockFile("/data/adb/modules/kirin9000s_ultimate_spoof/running_state/sockpath.tmp");
        if (sockFile.is_open()) {
            getline(sockFile, socketPath);
            sockFile.close();
        }
        // 运行期擦除内存明文关键字
        char keyword[] = "cpu_spoof";
        memset(keyword, 0, sizeof(keyword));
    }

    void preAppSpecialize(AppSpecializeArgs* args) override {
        const char* procName = api->getProcessName();
        if (!procName || targetPackage.empty()) return;
        size_t pkgLen = targetPackage.size();
        // 前缀匹配游戏子进程
        bool isTargetProc = (strncmp(procName, targetPackage.c_str(), pkgLen) == 0);
        if (!isTargetProc) return;

        sendCommand('\x01');

        // 1. Hook getauxval 篡改硬件指令集参数
        api->pltHookRegister(".*libc\\.so$", "getauxval",
        [=](void* origFunc, void** outReal) {
            *outReal = origFunc;
            return [](unsigned long type) -> unsigned long {
                if (type == 16) return FAKE_HWCAP;
                if (type == 26) return FAKE_HWCAP2;
                using OrigFunc = unsigned long (*)(unsigned long);
                return ((OrigFunc)*outReal)(type);
            };
        }, nullptr);

        // 2. 过滤dl_iterate_phdr，隐藏模块库
        api->pltHookRegister(".*libc\\.so$", "dl_iterate_phdr",
        [=](void* origFunc, void** outReal) {
            *outReal = origFunc;
            return [](int (*cb)(struct dl_phdr_info*, size_t, void*), void* data) -> int {
                auto wrapCallback = [cb](struct dl_phdr_info* info, size_t sz, void* d) -> int {
                    return filterPhdrCallback(info, sz, d, cb);
                };
                using OrigFunc = int (*)(int(*)(struct dl_phdr_info*, size_t, void*), void*);
                return ((OrigFunc)*outReal)(wrapCallback, data);
            };
        }, nullptr);

        // 3. 注册Seccomp-BPF系统调用过滤器
        struct sock_filter bpfRules[] = {
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_read, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_close, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        };
        struct sock_fprog seccompProg = {
            .len = sizeof(bpfRules) / sizeof(bpfRules[0]),
            .filter = bpfRules
        };

        // 配置SIGSYS信号处理器
        struct sigaction sigAction{};
        sigAction.sa_sigaction = sigsysHandler;
        sigAction.sa_flags = SA_SIGINFO | SA_NODEFER;
        sigaction(SIGSYS, &sigAction, nullptr);
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &seccompProg, 0, 0);

        // 关闭进程内存转储，禁止ptrace调试
        prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);

        // 进程退出回调，下发退出指令
        args->onExit = [=]() {
            sendCommand('\x00');
        };
    }
};

REGISTER_ZYGISK_MODULE(UltimateCpuSpoof)
