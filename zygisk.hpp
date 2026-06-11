#ifndef ZYGISK_HPP
#define ZYGISK_HPP

#include <jni.h>

namespace zygisk {

struct AppSpecializeArgs {
    JNIEnv* env;
    jobject nice_name;
    jstring app_data_dir;
    const char* const* rlimits;
    void (*onExit)();
};

struct ServerSpecializeArgs {
    JNIEnv* env;
    jstring nice_name;
};

class Api {
public:
    virtual ~Api() {}
    virtual const char* getProcessName() const = 0;
    
    // 使用 void* 避免类型依赖，实际使用时会强制转换
    virtual void pltHookRegister(const char* regex, const char* symbol, void* newFunc, void** oldFunc) = 0;
    
    // 某些版本需要额外参数，这里不做要求
};

class ModuleBase {
public:
    virtual ~ModuleBase() {}
    virtual void onLoad(Api* api, JNIEnv* env) {}
    virtual void preAppSpecialize(AppSpecializeArgs* args) {}
    virtual void postAppSpecialize(const AppSpecializeArgs* args) {}
    virtual void preServerSpecialize(ServerSpecializeArgs* args) {}
    virtual void postServerSpecialize(const ServerSpecializeArgs* args) {}
};

#define REGISTER_ZYGISK_MODULE(className) \
    extern "C" __attribute__((visibility("default"))) \
    zygisk::ModuleBase* zygiskModuleOnLoad(zygisk::Api* api, JNIEnv* env) { \
        auto* mod = new className(); \
        mod->onLoad(api, env); \
        return mod; \
    }

} // namespace zygisk

#endif
