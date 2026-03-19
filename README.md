# SentinelClaw

> **攻防一体的网络安全研究平台** · An Offensive-Defensive Network Security Research Platform

[![Python](https://img.shields.io/badge/Python-3.11-blue?logo=python)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110-009688?logo=fastapi)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18-61dafb?logo=react)](https://react.dev)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-yellow)](LICENSE)

---

## 项目简介

SentinelClaw 是一个面向网络安全研究与教学的**攻防演示平台**。它将 ARP 协议攻击模拟、实时流量威胁检测与 AI 辅助分析整合在同一个系统中，形成完整的"攻击—感知—分析"闭环。

项目前端采用赛博风格的深色 UI，所有数据实时刷新；后端基于 Scapy 进行底层数据包操作，结合 DeepSeek 大模型实现智能威胁分析与安全报告生成。

> **适用场景**：Agent攻击、攻防原理可视化、个人安全研究。

---

## 功能特性

### 🛡️ 实时态势感知
- 每 1.5 秒轮询，统计数字变化时触发动画高亮
- 威胁评分（0–100）根据告警等级实时计算，4 级颜色指示（LOW / MEDIUM / HIGH / CRITICAL）
- 攻击源 IP 排行、告警等级分布进度条、高危告警实时流
- 趋势折线图（30 秒粒度，攻击 30 秒内即可在图表上显现）
- 威胁面覆盖雷达图、攻击类型分布、近期动态流

### ⚔️ ARP 攻击构造
- 五种 ARP 攻击：**欺骗 · 泛洪 · 扫描 · 无故 ARP · 中间人**
- 自然语言 Agent 执行：直接描述攻击意图，自动解析并调用后端
- 攻击流程可视化：SVG 网络拓扑动画，数据包沿路径实时流动，按步骤轮播
- 执行 Pipeline 展示：逐步显示攻击过程与结果

### 🔍 威胁检测
- 实时抓包（基于网卡选择），告警时间线滚动更新
- 规则引擎：ARP 泛洪 / 扫描 / 欺骗 / 中间人等检测规则
- AI 辅助攻击链重构：将离散告警串联成完整攻击路径
- 一键生成安全事件报告（Markdown 渲染，含表格/代码块）

### 🤖 AI 分析中心
- 基于 DeepSeek 大模型的安全对话助手
- 快捷指令：攻击链重构、风险评估、报告生成、高危威胁识别

---

## 技术架构

```
SentinelClaw/
├── backend/                  # Python · FastAPI
│   ├── core/                 # Scapy 抓包、ARP 构造、规则检测引擎
│   ├── agents/               # LangChain + DeepSeek Agent
│   ├── routers/              # REST API 路由
│   ├── models/               # 数据模型
│   └── main.py
├── frontend/                 # React 18 · Vite · Tailwind CSS
│   └── src/
│       ├── pages/            # Dashboard · ARPForge · ThreatDetector · AICenter
│       ├── components/       # ThreatTimeline · AttackChainGraph
│       └── contexts/         # AttackAgentContext
├── data/
│   ├── samples/              # 示例 PCAP 文件
│   └── logs/                 # 攻击记录日志
├── requirements.txt
├── .env.example
└── README.md
```

| 层级 | 技术 |
|---|---|
| 后端框架 | FastAPI + Uvicorn |
| 数据包操作 | Scapy |
| AI Agent | LangChain + DeepSeek API |
| 前端框架 | React 18 + Vite |
| UI 样式 | Tailwind CSS |
| 图表 | Recharts |
| Markdown 渲染 | react-markdown + remark-gfm |

---

## 快速开始

### 环境要求
- **操作系统**：推荐 Windows 11 + WSL2 (Ubuntu 22.04)（实时抓包需 Linux 内核）
- **Python**：3.11+
- **Node.js**：18+
- **权限**：实时抓包需以 root 运行后端

### 1. 克隆项目

```bash
git clone https://github.com/your-username/SentinelClaw.git
cd SentinelClaw
```

### 2. 后端配置（WSL 中执行）

```bash
# 安装系统依赖
sudo apt update && sudo apt install -y \
    python3.11 python3.11-venv python3-pip \
    libpcap-dev tcpdump net-tools

# 创建虚拟环境
python3.11 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 配置环境变量
cp .env.example .env
# 编辑 .env，填入你的 DEEPSEEK_API_KEY
```

### 3. 启动后端

```bash
cd backend
source ../venv/bin/activate

# 普通模式（不含实时抓包）
uvicorn main:app --reload --host 0.0.0.0 --port 8000

# 实时抓包模式（需 root）
sudo $(which uvicorn) main:app --host 0.0.0.0 --port 8000
```

### 4. 启动前端

```bash
cd frontend
npm install
npm run dev
# 访问 http://localhost:5173
```

### 5. API 文档

启动后端后访问：[http://localhost:8000/docs](http://localhost:8000/docs)

---

## 注意事项

- `.env` 中 `DEEPSEEK_API_KEY` 为必填项，否则 AI 分析功能不可用。
- 实时抓包功能需在 WSL/Linux 环境内以 root 权限运行后端。
- 前端默认代理到 `http://localhost:8000`，如修改端口请同步更新 `vite.config.js`。
- 部分 ARP 攻击操作在 `real_send=false` 模式下仅作模拟，不真正发包。

---

## 免责声明

**本项目仅供授权网络环境下的安全研究、教育实验和技术演示使用。**

严禁将本项目中的任何攻击工具或代码用于未经授权的网络中。使用者须自行承担因违规使用产生的一切法律责任，项目作者不承担任何连带责任。

---

---

## Overview

SentinelClaw is an **offensive-defensive network security research platform** designed for education and authorized lab environments. It integrates ARP protocol attack simulation, real-time traffic threat detection, and AI-assisted analysis into a single cohesive system.

The platform demonstrates a complete "attack → sense → analyze" loop: you can launch ARP attacks, watch the threat dashboard react in near real-time, reconstruct attack chains with AI, and generate structured security reports — all from a single interface.

> **Intended for**: agent attack ,attack-defense principle visualization, and personal security research.

---

## Features

### 🛡️ Real-Time Threat Dashboard
- Polls every 1.5 seconds; stat numbers animate on change
- Live threat score (0–100) with 4-level color indicator (LOW / MEDIUM / HIGH / CRITICAL)
- Top attacker IP ranking, severity breakdown bars, live critical alert feed
- 30-second trend chart granularity — new attacks appear within ~30 seconds
- Threat coverage radar chart, attack type distribution, activity log

### ⚔️ ARP Attack Forge
- Five ARP attack types: **Spoof · Flood · Scan · Gratuitous ARP · MITM**
- Natural language Agent: describe the attack in plain text, let the Agent parse and execute
- Animated attack flow diagram: SVG network topology with packet-traveling animations, auto-cycling through attack steps
- Execution pipeline display: step-by-step progress with status indicators

### 🔍 Threat Detector
- Live packet capture with selectable network interface
- Rule-based detection: ARP flooding, scanning, spoofing, MITM, etc.
- AI-powered attack chain reconstruction from discrete alerts
- One-click security report generation (full Markdown rendering with tables)

### 🤖 AI Analysis Center
- DeepSeek-powered security chat assistant
- Quick commands: attack chain rebuild, risk assessment, report generation, high-risk threat identification

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend framework | FastAPI + Uvicorn |
| Packet engine | Scapy |
| AI Agent | LangChain + DeepSeek API |
| Frontend | React 18 + Vite |
| Styling | Tailwind CSS |
| Charts | Recharts |
| Markdown | react-markdown + remark-gfm |

---

## Quick Start

### Requirements
- **OS**: Windows 11 + WSL2 (Ubuntu 22.04) recommended for live packet capture
- **Python**: 3.11+
- **Node.js**: 18+
- **Permissions**: root required for live capture

### Clone

```bash
git clone https://github.com/your-username/SentinelClaw.git
cd SentinelClaw
```

### Backend (run inside WSL)

```bash
sudo apt update && sudo apt install -y \
    python3.11 python3.11-venv libpcap-dev tcpdump net-tools

python3.11 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# Fill in DEEPSEEK_API_KEY in .env
```

```bash
cd backend
source ../venv/bin/activate
uvicorn main:app --reload --host 0.0.0.0 --port 8000
# For live capture: sudo $(which uvicorn) main:app --host 0.0.0.0 --port 8000
```

### Frontend

```bash
cd frontend
npm install
npm run dev
# Open http://localhost:5173
```

---

## Disclaimer

**This project is intended solely for security research, education, and demonstration in authorized environments.**

Do not use any attack tools or code in this project against systems you do not own or have explicit written permission to test. The author assumes no liability for any misuse or illegal activity.

---

## License

[GPL-3.0](LICENSE) © 2025 SentinelClaw Contributors
