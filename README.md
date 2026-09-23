# U盘ISO更新程序

一个用于将 ISO 镜像写入 USB 虚拟光驱（CD-ROM 模式）的 Windows 小工具。基于 LuaJIT + IUP 构建，直接调用 Windows SCSI Pass-Through Direct (SPTI) 接口操作设备。

> 基于慧荣的SM3281开发。只测试过这一种主控，不保证其他主控可用。

> ⚠️ **风险提示**：本程序直接操作磁盘设备，不当使用可能导致数据丢失甚至设备损坏。使用前请备份重要数据，并确认你完全理解每个操作的含义。作者不对因使用本程序造成的任何损失承担责任。

---

## 功能特点
<div align="center"><img width="619" height="232" alt="image" src="https://github.com/user-attachments/assets/d3654b2a-4646-4ba7-8b86-017a2bc9087c" /></div>

- **直接 SCSI 直通**：通过 SPTI 向 CD-ROM 设备发送 INQUIRY / READ CAPACITY / READ(10) / WRITE(10) / WRITE(12) 等 SCSI 命令，绕过文件系统层。
- **自动枚举设备**：扫描 `\\.\CDROM0` ~ `\\.\CDROM15`，并额外探测 `PhysicalDrive0~7` 中 PDT 为 0x05（CD/DVD）的设备。
- **自动探测最大传输块**：从 256 块（512KB）往下试到 4 块，找到设备支持的最大单次传输大小并缓存，避免 `Error 87`。
- **写入后校验**：可选读回整个 ISO 与源文件逐块比对（默认开启）。
- **图形界面 + 命令行双模式**：`luajit_iup.exe` 提供 GUI，`luajit.exe` 配合 `spti.lua` 提供命令行操作。
- **实时进度与速度**：基于 `QueryPerformanceCounter` 的高精度计时，显示写入/校验进度和 MB/s。

---

## 仓库内容

| 文件 | 说明 |
|------|------|
| `U盘ISO更新程序1.4.exe` | 图形界面单文件可执行程序 |
| `main.lua` | GUI 主程序（IUP 界面），由 `luajit_iup.exe` 自动加载 |
| `spti.lua` | 命令行版 SCSI 工具，配合 `luajit.exe` 使用 |
| `luajit.exe` | LuaJIT 解释器，用于运行 `spti.lua` |
| `luajit_iup.exe` | 带 IUP 支持的 LuaJIT，启动时自动加载 `main.lua` |

> **只需要下载[U盘ISO更新程序1.4.exe](https://github.com/marskid/usb-cdrom-tool/releases)即可运行，无其他依赖文件。**
> 其他文件用于开发调试。

> 注：`luajit.exe` 和 `luajit_iup.exe` 已上传到仓库，方便直接运行脚本，无需自行配置 LuaJIT 环境。

---

## 快速开始

### 环境要求

- Windows（32/64 位均可，需与 exe 架构匹配）
- **管理员权限**（访问物理设备必需）

### 图形界面

运行U盘ISO更新程序1.4.exe或者双击 `luajit_iup.exe`，程序会自动加载 `main.lua` 并显示界面。
luajit_iup.exe主要用于调试。

操作流程：

1. 点击 **扫描U盘**，等待枚举 CD-ROM 设备。
2. 在顶部下拉框中选择目标设备。
3. 点击 **选择ISO**，选中要写入的 ISO 文件。
4. （可选）勾选 **写入后校验**。
5. 点击 **更新U盘** 开始写入。写入过程中按钮变为 **中止**，可随时中断。
6. 出错时日志面板会自动展开；也可手动点击 **显示日志**。

### 命令行

```bash
luajit.exe spti.lua <命令> [参数...]
```

#### 命令列表

| 命令 | 说明 |
|------|------|
| `list` | 列出所有 CD-ROM 设备及详细信息 |
| `info <设备>` | 显示指定设备的详细信息 |
| `writeiso <设备> <ISO文件>` | 从 LBA 0 开始写入整个 ISO |
| `writezero <设备> <LBA> <块数\|all>` | 从指定 LBA 开始写零，`all` 表示清到设备末尾 |

#### 设备参数

支持短名字，脚本会自动补全为 Windows 设备路径：

| 输入 | 实际路径 |
|------|----------|
| `0` | `\\.\CDROM0` |
| `CDROM0` | `\\.\CDROM0` |
| `E` | `\\.\E:` |
| `\\.\CDROM0` | 原样使用 |

#### 选项

| 选项 | 说明 |
|------|------|
| `--verify` | 写入后读回验证 |
| `--write12` | 使用 WRITE(12) 命令（默认 WRITE(10)） |
| `--chunk=N` | 每次 SCSI 传输的块数，不指定则自动探测 |

#### 示例

```bash
# 列出设备
luajit.exe spti.lua list

# 查看 0 号设备信息
luajit.exe spti.lua info 0

# 写入 ISO 并校验
luajit.exe spti.lua writeiso 0 image.iso --verify

# 指定 chunk 为 32 块（64KB），写入并校验
luajit.exe spti.lua writeiso 0 image.iso --chunk=32 --verify

# 清空整个设备（从 LBA 0 到末尾）
luajit.exe spti.lua writezero 0 0 all

# 清空并验证
luajit.exe spti.lua writezero 0 0 all --verify
```

---

## 关于 chunk（传输块大小）

SCSI 直通单次传输的数据量有上限，超过会返回 `Error 87 (ERROR_INVALID_PARAMETER)`。本程序的处理策略：

- **不指定 `--chunk` 时自动探测**：从 256 块（512KB）往下试到 4 块，找到设备能接受的最大值并缓存。
- **探测失败回退**：默认 32 块（64KB）。
- **经验值**：
  - USB 2.0 虚拟光驱常见上限约 **64KB**（chunk=32）
  - USB 3.0 虚拟光驱常见上限约 **512KB**（chunk=256）

---

## 编译说明

最终产物为单文件可执行程序 `U盘ISO更新程序1.4.exe`。

编译依赖：

- **LuaJIT**（含头文件和静态库）
- **IUP**（含 Lua 绑定）
- **MinGW**（gcc / windres）
- **luastatic**

编译流程大致为：用 `luastatic` 将 `main.lua` 与 LuaJIT、IUP 静态库打包为单个 exe，再用 `windres` 链接图标资源。

> 编译所需的中间文件和详细步骤从略。如需自行编译，请参考上述工具链的官方文档。
---

## 开发说明与致谢

本项目的开发过程大量借助了 AI 辅助工具，特此说明并致谢。

### 开发方式

- **协议分析与抓包**：通过对 USB 虚拟光驱设备的实际通信进行抓包分析，梳理出可用的 SCSI 命令序列与设备行为特征。
- **代码生成**：主要代码由 **DeepSeek** 与 **Trace** 辅助生成，包括 SCSI 直通封装、CDB 构造、设备枚举、写入/校验状态机以及 IUP 界面逻辑。
- **人工工作**：作者负责需求定义、抓包数据整理、关键逻辑判断、代码整合、调试与功能测试。

AI 工具显著降低了底层协议实验和样板代码的编写成本，让开发者能把精力集中在设备行为验证和实际测试上。在此对 DeepSeek、Trace 以及相关开源工具链表示感谢。

### 免责声明

尽管作者已对程序进行了实际测试，但请注意：

- 本程序由 AI 辅助生成，**不保证代码完全正确、完整或适用于所有设备**。
- AI 生成的代码可能存在未被发现的逻辑缺陷、边界问题或对特定硬件的兼容性问题。
- 不同品牌、不同固件的 USB 虚拟光驱行为可能存在差异，抓包分析结论不一定具有普适性。
- 作者仅对自身测试过的有限场景负责，**不对其他环境下的使用结果作出任何承诺**。

使用本程序即表示你理解并自愿承担上述风险。因使用本程序造成的任何数据丢失、设备损坏或其他损失，作者不承担责任。

详见下方 [许可证](#许可证) 中的免责条款。
---

## 许可证

本项目采用 **GNU General Public License v3.0 or later** 发布。

```
Copyright (C) 2026 marskid

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
```

第三方组件：

- **LuaJIT** — MIT License — <https://luajit.org>
- **IUP** — Tecgraf Library License (MIT 风格) — <https://www.tecgraf.puc-rio.br/iup/>

---

## 项目地址

<https://github.com/marskid/usb-cdrom-tool>
