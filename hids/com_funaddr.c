#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <link.h>
#include <dlfcn.h>
#include "cjson/cJSON.h"

// add your own libc symbols to check if you wish
static const char *symbols[] = {
     "accept","ftrace", "access", "execve", "link", "__lxstat", "__lxstat64", 
   "open", "rmdir", "unlink", "unlinkat", "__xstat", "__xstat64",
   "fopen", "fopen64", "opendir", "readdir", "readdir64",
   "pam_authenticate", "pam_open_session", "pam_acct_mgmt",
   "getpwnam", "pam_sm_authenticate", "getpwnam_r", "pcap_loop",
    NULL
};

struct cJSON * dladdr_check(void)
{
    struct cJSON *dladdr_check =NULL;
    void *dls_handle;
    const char *symbol;
    int i = 0, hooked_funcs = 0;

    if(!(dls_handle = dlopen("/lib/x86_64-linux-gnu/libc.so.6", RTLD_LAZY))) {
        return dladdr_check;
    }

    dladdr_check = cJSON_CreateObject();	//创建一个对象
    struct cJSON *func_sofile = cJSON_CreateObject();

    printf("[+] beginning dlsym/dladdr check.\n");
    while((symbol = symbols[i++]))
    {

        // printf("[+] checking \033[1;32m%s\033[0m.\n", symbol);

        void *real_symbol_addr, *curr_symbol_addr;
        real_symbol_addr = dlsym(dls_handle, symbol);
        curr_symbol_addr = dlsym(RTLD_NEXT, symbol);

        if(real_symbol_addr != curr_symbol_addr)
        {
            Dl_info real_nfo, curr_nfo;
            // 获取地址的符号信息
            dladdr(real_symbol_addr, &real_nfo);
            dladdr(curr_symbol_addr, &curr_nfo);
            printf("[-] function %s possibly \033[1;31mhijacked\033[0m / location of shared object file: %s\n", symbol, curr_nfo.dli_fname);
            cJSON_AddStringToObject(func_sofile, symbol, curr_nfo.dli_fname);
            hooked_funcs++;
        }
    }
    dlclose(dls_handle);

    cJSON_AddNumberToObject(dladdr_check,"pre-load hook funcs count",hooked_funcs);
    cJSON_AddItemToObject(dladdr_check, "funcs && location of shared object file", func_sofile);

    printf("[+] dlsym/dladdr check finished.\n");

    return dladdr_check;
}

void dlinfo_check(void)
{
    struct link_map *lm;
    dlinfo(dlopen(NULL, RTLD_LAZY), 2, &lm);
    printf("[+] beginning dlinfo check.\n");


    while(lm != NULL)
    {
        // if(strlen(lm->l_name) > 0) printf("%p %s\n", (void *)lm->l_addr, lm->l_name);
        lm = lm->l_next;
    }

    printf("[+] dlinfo check finished.\n");

}

int do_so_check(void)
{
    struct cJSON * so_check= cJSON_CreateObject();	//创建一个对象;
    printf("===========================================user mod rootkit check bdginning =======================================================\n");
    if(getenv("LD_PRELOAD")) {
        cJSON_AddTrueToObject(so_check, "check env:LD_PRELOAD");
        printf("... LD_PRELOAD is visible in the local environment variables.. little warning\n");
    }else{
        cJSON_AddFalseToObject(so_check, "check env:LD_PRELOAD");
    }
    if(access("/etc/ld.so.preload", F_OK) != -1) 
    {
        cJSON_AddTrueToObject(so_check, "check /etc/ld.so.preload");
        printf("... /etc/ld.so.preload DOES definitely exist.. little warning\n");
    }else{
        cJSON_AddFalseToObject(so_check, "check /etc/ld.so.preload");
    }
    printf("[+] finished basic checks\n\n");

    dlinfo_check();

    struct cJSON *hooked_funcs = dladdr_check();
    if (hooked_funcs)
    {
        struct cJSON *parse = cJSON_Parse(cJSON_Print(hooked_funcs));
        struct cJSON *cjson_funcs_cnt = cJSON_GetObjectItem(parse, "pre-load hook funcs count");
        if(cjson_funcs_cnt->valueint > 0) printf("[!] the dladdr check revealed that there are %d possibly hooked functions. YOUR MALWARE SUUUUCKS.\n", cjson_funcs_cnt->valueint);
        if(cjson_funcs_cnt->valueint == 0) printf("[+] no modifications to any libc functions were found. no LD_PRELOAD malware loaded, or your malware is decent.\n");
        cJSON_AddItemToObject(so_check,"dladdr_check",hooked_funcs);
    }

    printf("===========================================user mod rootkit check finished =========================================================\n");

    char *json_data = cJSON_Print(so_check);	//JSON数据结构转换为JSON字符串
	printf("%s\n",json_data);//输出字符串
	cJSON_Delete(so_check);//清除结构体	

    return 0;
}