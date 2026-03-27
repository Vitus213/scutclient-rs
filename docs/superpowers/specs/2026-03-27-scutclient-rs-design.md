---
name: scutclient-rs 设计规格
description: SCUT Dr.com客户端Rust重写版设计文档
type: project
---

# scutclient-rs 设计规格

## 1. 概述

将C语言版本的scutclient用Rust完全重写，用于华南理工大学校园网802.1X认证。目标运行环境为OpenClash/OpenWrt路由器。

## 2. 功能需求

### 2.1 核心功能
- 802.1X EAPOL认证（Identity + MD5-Challenge）
- Dr.com UDP心跳维护
- 自动重连（指数退避）
- 定时下线等待（net_time参数）

### 2.2 辅助功能
- 上线Hook命令执行
- 下线Hook命令执行
- 信号处理（SIGTERM/SIGINT优雅退出）
- 日志输出（多级别）

### 2.3 部署方式
- OpenWrt ipk包
- procd/init.d服务管理
- UCI配置文件支持
- 多架构交叉编译（x86_64, aarch64, mipsel, arm）

## 3. 架构设计

### 3.1 目录结构

```
scutclient-rs/
├── Cargo.toml
├── src/
│   ├── main.rs              # 主入口、事件循环、CLI解析
│   ├── config/
│   │   └── mod.rs           # 配置结构、常量定义
│   ├── auth/
│   │   ├── mod.rs           # 802.1X认证状态机
│   │   ├── eap.rs           # EAP协议定义
│   │   ├── eapol.rs         # EAPOL包构建
│   │   └── socket.rs        # Raw socket封装
│   ├── drcom/
│   │   ├── mod.rs           # Dr.com UDP状态机
│   │   ├── packet.rs        # Dr.com包构建
│   │   └── udp.rs           # UDP客户端
│   └── utils/
│       ├── mod.rs           # 工具函数
│       └── md5.rs           # MD5计算
└── openwrt/
    ├── Makefile             # OpenWrt包定义
    └── files/
        ├── scutclient.init  # init.d脚本
        └── scutclient.config # UCI配置模板
```

### 3.2 模块职责

| 模块 | 职责 |
|-----|------|
| main | CLI解析、信号处理、主事件循环 |
| config | 配置结构体、默认值、常量 |
| auth | 802.1X认证、EAPOL包处理 |
| drcom | Dr.com UDP协议、心跳维护 |
| utils | MD5、CRC32、加密工具 |

### 3.3 主事件循环

```
初始化
  │
  ▼
┌─────────────────────────────────────┐
│         802.1X 认证阶段             │
│  1. 发送 EAPOL Start                │
│  2. 处理 Request Identity           │
│  3. 处理 Request MD5                │
│  4. 等待 Success                    │
└─────────────────────────────────────┘
  │ Success
  ▼
┌─────────────────────────────────────┐
│         UDP 心跳循环阶段            │
│                                     │
│  loop {                             │
│    select!(8021x, udp, timeout)     │
│                                     │
│    if 8021x可读: 处理EAP包          │
│    if udp可读:   处理UDP包          │
│    if timeout:   检查心跳/定时下线  │
│  }                                  │
└─────────────────────────────────────┘
  │ 失败/掉线
  ▼
指数退避重试 (1s → 2s → 4s → ... → 256s)
```

## 4. 命令行参数

| 参数 | 简写 | 说明 | 默认值 |
|-----|------|------|-------|
| --username | -u | 用户名 | (必填) |
| --password | -p | 密码 | (必填) |
| --iface | -i | 网卡名 | eth0 |
| --dns | -n | DNS服务器 | 222.201.130.30 |
| --hostname | -H | 主机名 | 系统主机名 |
| --udp-server | -s | UDP服务器 | 202.38.210.131 |
| --cli-version | -c | 客户端版本(hex) | 默认值 |
| --hash | -h | DrAuthSvr hash | 默认值 |
| --net-time | -T | 允许上网时间 | (可选) |
| --online-hook | -E | 上线hook | (可选) |
| --offline-hook | -Q | 下线hook | (可选) |
| --debug | -D | 调试级别 | 0 |
| --logoff | -o | 退出登录模式 | false |

## 5. OpenWrt集成

### 5.1 UCI配置 (/etc/config/scutclient)

```
config scutclient 'config'
    option enabled '1'
    option username ''
    option password ''
    option iface 'eth0'
    option dns '222.201.130.30'
    option udp_server '202.38.210.131'
    option net_time ''
    option online_hook ''
    option offline_hook ''
```

### 5.2 init.d脚本

- 支持 start/stop/restart/enable/disable
- 使用 procd 管理进程
- 支持 UCI 配置读取

### 5.3 依赖

- libc (musl)
- 无其他运行时依赖

## 6. 交叉编译目标

| 架构 | 目标三元组 |
|-----|-----------|
| x86_64 | x86_64-unknown-linux-musl |
| aarch64 | aarch64-unknown-linux-musl |
| arm | armv7-unknown-linux-musleabihf |
| mipsel | mipsel-unknown-linux-musl |

## 7. 资源预算

| 指标 | 目标值 |
|-----|-------|
| 编译后大小 | < 500KB (strip后) |
| 运行内存 | < 2MB |
| CPU占用 | < 1% (空闲时) |

## 8. 实现优先级

1. **P0**: 补全 main.rs 事件循环
2. **P0**: 命令行参数解析
3. **P0**: 信号处理
4. **P1**: OpenWrt打包脚本
5. **P1**: GitHub Actions CI/CD
6. **P2**: 完善错误处理
7. **P2**: 添加单元测试
