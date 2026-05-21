# DIMY Privacy-Preserving Contact Tracing Demo

## English

This repository contains a Python implementation of a DIMY-style privacy-preserving contact tracing demo. It simulates local encounter discovery with UDP broadcasts, Shamir secret sharing, X25519 key exchange, rolling Bloom filters, and a TCP backend for exposure-risk checks.

The code is intended for controlled local testing and protocol demonstration only. It is not production-ready medical, security, or public-health infrastructure.

### Components

- `Dimy.py`: client node that generates EphIDs, broadcasts Shamir shares, reconstructs peer EphIDs, derives EncIDs, and manages Bloom filters.
- `DimyServer.py`: TCP backend that stores uploaded contact Bloom filters and checks query Bloom filters.
- `attacker.py`: local adversarial traffic generator for replay and flood testing.

### Requirements

- Python 3.10 or later
- `cryptography`
- `pyshamir`

Install dependencies:

```bash
pip install -r requirements.txt
```

### Run

Start the backend server:

```bash
python DimyServer.py
```

Start one or more client nodes in separate terminals:

```bash
python Dimy.py 15 3 5 30 127.0.0.1 55000
```

Arguments:

- `t`: EphID rotation period in seconds. Supported values: `15`, `18`, `21`, `24`, `27`, `30`.
- `k`: Shamir reconstruction threshold. Must be at least `3`.
- `n`: Number of Shamir shares. Must be at least `5` and greater than `k`.
- `drop_percent`: simulated packet drop percentage. Supported values: `30`, `40`, `50`, `60`, `70`.
- `server_ip`: optional backend server IP. Defaults to `127.0.0.1`.
- `server_port`: optional backend server port. Defaults to `55000`.

Client commands:

- `q`: manually submit a query Bloom filter.
- `i`: upload this node's contact Bloom filter.

Run the attacker simulator in a separate terminal:

```bash
python attacker.py 3 5
```

The attacker starts replay mode automatically. Enter `f` to start flood mode.

### Notes

- UDP broadcast behavior depends on the local network and operating system firewall rules.
- All protocol timing values are compressed for demonstration.
- The adversarial simulator is included only for controlled testing of replay and flood behavior.

---

## 中文

本仓库提供一个基于 Python 的 DIMY 风格隐私保护接触追踪演示实现。它使用 UDP 广播模拟本地相遇发现，结合 Shamir 秘密分享、X25519 密钥交换、滚动 Bloom Filter，以及用于风险查询的 TCP 后端服务。

该项目仅用于本地受控测试和协议演示，不适合作为真实医疗、安全或公共卫生系统直接使用。

### 组件

- `Dimy.py`：客户端节点，负责生成 EphID、广播 Shamir 分享片段、重构对端 EphID、派生 EncID，并维护 Bloom Filter。
- `DimyServer.py`：TCP 后端服务，保存上传的接触 Bloom Filter，并处理查询 Bloom Filter。
- `attacker.py`：本地对抗流量模拟器，用于测试重放和洪泛场景。

### 环境要求

- Python 3.10 或更高版本
- `cryptography`
- `pyshamir`

安装依赖：

```bash
pip install -r requirements.txt
```

### 运行方式

启动后端服务：

```bash
python DimyServer.py
```

在不同终端中启动一个或多个客户端节点：

```bash
python Dimy.py 15 3 5 30 127.0.0.1 55000
```

参数说明：

- `t`：EphID 轮换周期，单位为秒。支持 `15`、`18`、`21`、`24`、`27`、`30`。
- `k`：Shamir 重构阈值，必须不小于 `3`。
- `n`：Shamir 分享片段数量，必须不小于 `5`，且大于 `k`。
- `drop_percent`：模拟丢包百分比。支持 `30`、`40`、`50`、`60`、`70`。
- `server_ip`：可选的后端服务 IP，默认 `127.0.0.1`。
- `server_port`：可选的后端服务端口，默认 `55000`。

客户端交互命令：

- `q`：手动提交查询 Bloom Filter。
- `i`：上传当前节点的接触 Bloom Filter。

在单独终端中启动攻击模拟器：

```bash
python attacker.py 3 5
```

攻击模拟器会自动启动重放模式。输入 `f` 可以启动洪泛模式。

### 注意事项

- UDP 广播行为会受到本地网络和操作系统防火墙规则影响。
- 项目中的协议时间参数为了演示效果进行了压缩。
- 对抗流量模拟器只用于受控环境中的重放与洪泛测试。

