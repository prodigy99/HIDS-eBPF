# eBPF-HIDS

Intrusion Detection System based on eBPF

# 为什么是eBPF？

稳定：通过验证器，防止用户编写的程序导致内核崩溃。相比内核模块，eBPF更稳定

免安装：eBPF内置于Linux内核，无需安装额外依赖，开箱即用。

内核编程：支持开发者插入自定义的代码逻辑（包括数据采集、分析和过滤）到内核中运行

高效的信息交流机制：通过Map（本质上是一种共享内存的方式）进行数据传输，实现各个hook点、用户态与内核态的高效信息交互。

# Branches

* `main`               ------主分支，仅实现入侵检测功能
* `lsm`           -------基于KRSI内核运行时检测，基于LSM hook点实现函数级的入侵阻断
* `send_signal`          ------基于bpf_send_signal()辅助函数发送信号，实现进程级的入侵阻断

# eBPF-HIDS source code

```shell
# hids source code
./hids/config.h  
./hids/utils.h  
./hids/hids.h  
./hids/hids.bpf.c  
./hids/hids.c  
./hids/hids.h 
./hids/com_funaddr.c 
# bpftrace 跟踪各种系统调用序列的脚本
./demo/*.c #bpftrace跟踪脚本
./demo/*.txt #得到的系统调用序列
```

# Install Dependencies

本项目使用到CORE特性，若想在本地编译或者运行该项目，内核需开启CONFIG_DEBUG_INFO_BTF=y编译配置，内核相关的支持情况参见[supported-distros](https://github.com/aquasecurity/btfhub/blob/main/docs/supported-distros.md)。推荐在默认启用CONFIG_DEBUG_INFO_BTF的高版本内核运行

在低版本未开启CONFIG_DEBUG_INFO_BTF编译配置运行该项目有以下两种方式
- 配置CONFIG_DEBUG_INFO_BTF=y，重新编译内核
- 基于BTFHub或其他来源收集不同Linux内核发行版的BTF源文件，使用BTFGen生成精简版的BTF文件。具体内容参考：
    - [BTFGen: 让 eBPF 程序可移植发布更近一步](https://developer.aliyun.com/article/899354#:~:text=BTF%20%E4%BF%A1%E6%81%AF%E7%94%B1%E5%86%85%E6%A0%B8%E6%9C%AC%E8%BA%AB%E6%8F%90%E4%BE%9B%E7%9A%84%EF%BC%8C%E8%BF%99%E9%9C%80%E8%A6%81%E5%9C%A8%E5%86%85%E6%A0%B8%E7%BC%96%E8%AF%91%E6%97%B6%E8%AE%BE%E7%BD%AE%20CONFIG_DEBUG_INFO_BTF%3Dy%20%E9%80%89%E9%A1%B9%20%E3%80%82%20%E8%AF%A5%E9%80%89%E9%A1%B9%20%E5%9C%A8Linux%20%E5%86%85%E6%A0%B8,%E4%B8%AD%E5%BC%95%E5%85%A5%E7%9A%84%EF%BC%8C%E8%AE%B8%E5%A4%9A%E6%B5%81%E8%A1%8C%E7%9A%84%20Linux%20%E5%8F%91%E8%A1%8C%E7%89%88%E5%9C%A8%E5%85%B6%E5%90%8E%E7%9A%84%E9%83%A8%E5%88%86%E5%86%85%E6%A0%B8%E7%89%88%E6%9C%AC%E6%89%8D%E9%BB%98%E8%AE%A4%E5%90%AF%E7%94%A8%E3%80%82%20%E8%BF%99%E6%84%8F%E5%91%B3%E7%9D%80%E6%9C%89%E5%BE%88%E5%A4%9A%E7%94%A8%E6%88%B7%E8%BF%90%E8%A1%8C%E7%9A%84%E5%86%85%E6%A0%B8%E5%B9%B6%E6%B2%A1%E6%9C%89%E5%AF%BC%E5%87%BA%20BTF%20%E4%BF%A1%E6%81%AF%EF%BC%8C%E5%9B%A0%E6%AD%A4%E4%B8%8D%E8%83%BD%E4%BD%BF%E7%94%A8%E5%9F%BA%E4%BA%8E%20CO-RE%20%E7%9A%84%E5%B7%A5%E5%85%B7%E3%80%82)   
    - [btfhub官方仓库](https://github.com/aquasecurity/btfhub) 
    - [BTF源文件仓库](https://github.com/aquasecurity/btfhub-archive) 

On Ubuntu/Debian:

```shell
# 目前仅在Ubuntu20.04、22.04上进行测试
$ apt install -y git make gcc clang llvm libelf1 libelf-dev zlib1g-dev
# Getting the source code. Download the git repository 
$ git clone https://github.com/haozhuoD/HIDS-eBPF.git
# Enter the folder
$ cd HIDS-eBPF/hids 
$ make clean    # 清除仓库中旧编译的bpf相关内容
$ make          # 配置环境并编译
```

### Usage正常开发时使用

```shell
# Compile
$ make hids   # 或者 make all  
# 运行hids
$ sudo ./hids

# clear
$ make clear  # 或者 make clean
```


# [Some-Examples](./examples.md)

# Documents

#### [文档：判断进程是否运行在容器中](./doc/区分容器进程.md)

#### [文档：Rootkit检测原理](./doc/Rootkit检测.md)

#### [文档：简单的KRSI](./doc/lsm.md)

#### [项目中期文档](./doc/中期报告-面向云原生的内核威胁检测系统的设计与实现.pdf)

#### [项目中期slides](./doc/中期答辩PPT.pdf)

#### [项目开题slides](./doc/开题答辩PPT.pdf)

#### [内核信息提取hook点的研究](https://github.com/haozhuoD/bpftrace-hook-demo)

#### Other

[容器加固学习文档](./doc/容器加固.md)

[docker容器运行时安全早期学习文档](./doc/docker容器运行时安全.md)

[ebpf rootkit初步探索](./demo/ebpf-rootkit.c)

# Hook points

> 项目目前支持 `19` 种 Hook，足以实现本项目所需功能。这些hook点的选取主要基于本人的实践，存在优化空间

<details><summary> 项目使用的 eBPF Hook point 详情 </summary>
<p>

| Hook                                       | Status & Description                     |
| :----------------------------------------- | :------------------------------------    |
| tracepoint/module/module_load              | ON & 提取*.ko文件相关信息                                      |
| tracepoint/syscalls/sys_exit_finit_module | ON & 触发系统调用表检查                                       |
| tracepoint/syscalls/sys_enter_mount       | ON                                     |
| tracepoint/syscalls/sys_exit_mount        | ON                                       |
| tracepoint/syscalls/sys_enter_open        | ON                                       |
| tracepoint/syscalls/sys_exit_open         | ON                                    |
| tracepoint/syscalls/sys_enter_openat      | ON                                     |
| tracepoint/syscalls/sys_exit_openat       | ON                                     |
| tracepoint/syscalls/sys_enter_execve      | ON                                       |
| tracepoint/syscalls/sys_enter_execveat    | ON                                     |
| tracepoint/syscalls/sys_enter_kill        | ON & 基于信号系统实现功能分发                                   |
| tracepoint/syscalls/sys_enter_memfd_create| ON & 无文件攻击相关                                    |
| kprobe/kprobe_lookup_name                 | ON & kprobe framework相关函数                                    |
| kprobe/arm_kprobe                         | ON & kprobe framework相关函数                                   |
| kprobe/insn_init                          | ON & 篡改内存代码行为相关函数                                   |
| kprobe/insn_get_length                    | ON & 篡改内存代码行为相关函数                           |
| kprobe/security_file_permission           | ON & file_operations checks                           |
| lsm/cred_prepare                          | OFF(only ON in lsm branch) & 基于lsm阻断insmod                                    |
| lsm/kernel_read_file                      | OFF(only ON in lsm branch) & 基于lsm阻断无文件加载攻击                                  |

</p></details>

# Reference
使用的库与参考的代码实现

[libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap)

[cJSON lib](https://github.com/DaveGamble/cJSON)

# todo

#### todolist

* [ ] 检测中断向量表idt_table 0X80号软中断系统调用服务表项的修改。和系统调用表检查类似，检查idt_table[0X80]的地址值是否变化或者超出范围
* [√] 容器逃逸相关检测。示例截图、完善原理文档
* [√] Nofile attack 无文件攻击文档工作。示例截图、完善原理文档
* [√] 完善文件的fop检查，相关内容bpftrace-hook-demo仓库kern_hook_demo中的security_file_permission
* [ ] fop-check示例寻找（注意相关注释中的链接），运行结果验证

其他可选：安装libbpf,参考 [libbpf](https://github.com/libbpf/libbpf)
```shell
# For Ubuntu20.10+
sudo apt-get install -y  make clang llvm libelf-dev libbpf-dev bpfcc-tools libbpfcc-dev linux-tools-$(uname -r) linux-headers-$(uname -r)
```

Complete documentation... 
