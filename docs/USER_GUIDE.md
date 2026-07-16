# Private Network 使用指南

本指南面向三类使用者：

- **网络所有者**：运行 Control 和 Control Service，创建节点与朋友账号。
- **节点所有者**：安装 Node Host，让自己的 Mac 成为一个互联网出口。
- **普通成员**：安装 Connect，用一个账号连接网络所有者分配的节点。

当前版本适合少量、互相信任的亲友测试。它不是商业 VPN 服务，也没有可用性 SLA。

## 目录

1. [先理解三个组件](#1-先理解三个组件)
2. [选择公网方案](#2-选择公网方案)
3. [发布 Control Service](#3-发布-control-service)
4. [添加节点](#4-添加节点)
5. [添加朋友账号](#5-添加朋友账号)
6. [使用 Connect](#6-使用-connect)
7. [日常管理](#7-日常管理)
8. [状态与故障排查](#8-状态与故障排查)
9. [备份与恢复](#9-备份与恢复)
10. [卸载与重新配对](#10-卸载与重新配对)
11. [安全与隐私](#11-安全与隐私)

## 1. 先理解三个组件

### Control

Control 是网络所有者的管理应用。它负责：

- 创建和管理节点；
- 创建朋友账号；
- 把一个账号分配到一个或多个节点；
- 生成 Node Host 和 Connect 的一次性 setup code；
- 查看节点在线状态、配置版本和账号下发状态。

Control 窗口可以关闭，真正持久运行的是独立的 Control Service。

### Node Host

Node Host 安装在提供出口的 Mac 上。它作为 `_privnetnode` 系统账号的 LaunchDaemon 运行，
负责 Xray、REALITY 密钥、配置切换、流量限制、节点同步和本地暂停。

关闭 Node Host 窗口不会停止节点；系统进入睡眠会停止提供网络服务。锁屏不会。

### Connect

Connect 是朋友使用的客户端。一次登录后，它会自动获取账号被分配的全部节点，并在节点列表
变化后同步。

当前 Connect 使用：

- 本地 SOCKS5：`127.0.0.1:10808`
- 本地 HTTP：`127.0.0.1:10809`
- 默认连接模式：设置 macOS/Windows 系统代理

它目前不是 TUN/Network Extension 全设备 VPN。遵循系统代理的应用会通过节点；忽略系统代理
的应用和 UDP 流量不会被强制接管。

## 2. 选择公网方案

真正的远程使用需要两个不同的公网入口：

1. **控制面 HTTPS**：Node Host 和 Connect 用它登录、同步和上报状态。
2. **数据面 TCP**：Connect 用它承载 VLESS + REALITY 流量。

不要把两者混为一谈。

### 方案比较

| 方案 | 控制面 | REALITY 数据面 | 最终出口 IP | 适用场景 |
| --- | --- | --- | --- | --- |
| Cloudflare Tunnel | 可以 | 不作为普通 TCP 客户端入口 | 不适用 | 发布 Control API |
| Tailscale | tailnet 内可以 | 仅适合加入同一 tailnet 的设备 | 节点 IP | 私有管理，不适合傻瓜客户端 |
| 家宽端口转发 | 可以另配 HTTPS | 可以 | 家宽 IP | 有公网 IPv4 和路由器控制权 |
| VPS + 原始 TCP relay/FRP | 可以 | 可以 | **节点家宽 IP** | 公寓网络、CGNAT、动态 IP |
| 在 VPS 直接运行 Xray | 可以 | 可以 | VPS IP | 不需要家宽出口时 |

### 推荐的小规模方案

对于公寓网络、WhiteSky、CGNAT 或没有路由器端口控制权的场景，推荐：

```text
朋友 Connect
  -> Vultr TCP 443
  -> FRP 出站隧道
  -> Mac 127.0.0.1:10443
  -> Xray
  -> Internet（最终出口为 Mac 所在网络）
```

同一条 FRP 连接还可以把本机 Control Service 的 `127.0.0.1:8787` 转发到 VPS 内部端口，
再由 Caddy 提供 HTTPS。完整模板位于 [Vultr TCP Relay](../deploy/vultr-relay/README.md)。

这种方案不要求家宽静态 IP，因为 Mac 主动连接 VPS；VPS IP 必须稳定。

## 3. 发布 Control Service

### 3.1 本机安装

从仓库根目录执行：

```bash
brew install xray

python3 scripts/product/control-service.py install \
  --network-name "Friends Network" \
  --xray-path /opt/homebrew/bin/xray
```

它会完成：

- release 构建；
- owner-only 配置和 SQLite 初始化；
- LaunchAgent 注册；
- 服务启动和 health check；
- 管理 token 生成。

重复运行 `install` 会更新二进制和配置，不会自动轮换管理 token 或删除数据库。

检查状态：

```bash
python3 scripts/product/control-service.py status
```

正常输出应包含：

```json
{
  "installed": true,
  "launchdLoaded": true,
  "healthy": true
}
```

### 3.2 配置公开 HTTPS origin

默认 `http://127.0.0.1:8787` 只允许同一台 Mac 测试。其他电脑无法使用包含该地址的邀请码。

先准备一个满足以下条件的入口：

- 使用有效 HTTPS 证书；
- origin 只有 scheme、host 和可选 port，不带 path、query、账号密码或 fragment；
- 只反向代理到 `http://127.0.0.1:8787`；
- 不把本机 `8787` 直接开放到公网；
- 不修改或记录 `Authorization` header 和 setup code。

然后保留现有数据重新安装配置：

```bash
python3 scripts/product/control-service.py install \
  --network-name "Friends Network" \
  --xray-path /opt/homebrew/bin/xray \
  --public-origin https://control.example.com
```

如果使用仓库里的 Vultr/Caddy 模板，默认入口包含 `8443`：

```bash
python3 scripts/product/control-service.py install \
  --network-name "Friends Network" \
  --xray-path /opt/homebrew/bin/xray \
  --public-origin https://control.example.com:8443
```

更新 origin 后应重新生成尚未使用的 setup code。旧 code 内嵌旧 origin，不会自动变化。

### 3.3 外部探测

Control 必须从节点局域网之外验证公网端点。Control 和 Node Host 在同一家庭网络时，
`local-tcp` 只测试 NAT hairpin，不能作为互联网可达证明。

可部署可选的 Cloudflare Worker：

```bash
cd probe-worker
npm ci
npx wrangler secret put PROBE_TOKEN
npm run deploy
```

把同一个专用 token 放入 owner-only 文件，不要写进命令参数或 Git：

```bash
umask 077
openssl rand -hex 32 > ~/.private-network-probe-token
chmod 600 ~/.private-network-probe-token

python3 scripts/product/control-service.py install \
  --network-name "Friends Network" \
  --xray-path /opt/homebrew/bin/xray \
  --public-origin https://control.example.com \
  --probe-mode remote-http \
  --tcp-probe-url https://probe.example.workers.dev/v1/tcp-probe \
  --tcp-probe-token-file ~/.private-network-probe-token
```

Worker 的 TCP 成功只是预检。Control 还会执行 VLESS + REALITY 协议 canary，只有精确配置通过
后才会把端点加入 Connect bundle。

### 3.4 启动 Control 应用

打开已安装的 Control 应用，或开发时运行：

```bash
npm run tauri -- dev
```

Control 会读取本机 owner-only Control Service 配置。主要页面：

- **网络**：服务、节点、朋友和公网入口总览。
- **节点**：生成节点邀请码、查看版本、禁用或撤销节点。
- **朋友**：创建账号、修改节点分配、生成 Connect code。
- **这台 Mac**：兼容的本机 Xray 状态和服务操作。
- **设置**：显示 Control、数据面和中继边界。

## 4. 添加节点

### 4.1 在 Control 创建节点邀请码

Control 中进入 **节点 -> 添加节点**，输入可识别的设备名称，例如“湾区 Mac mini”。生成后
复制 setup code，只发给这台节点的所有者。

CLI 等价命令：

```bash
python3 scripts/product/control-service.py create-node \
  --display-name "Bay Area Mac mini" \
  --listen-port 10443 \
  --public-port 443
```

setup code 短期有效并且只能使用一次。不要发送底层 JSON、UUID、REALITY 私钥或管理员 token。

### 4.2 安装 Node Host

在节点 Mac 上安装提供的系统 `.pkg`，管理员密码只用于安装以下固定资产：

- `/Applications/Private Network Node.app`
- `/Library/Application Support/Private Network Node/`
- `/Library/LaunchDaemons/com.sky.realitynode.agent.plist`
- `_privnetnode` 专用系统账号

打开 **Private Network Node**。未配对时应显示 `Ready to pair`，而不是
`Install required`。如果提示后台服务不完整，请不要改 PATH 或手工启动 Xray，先按
[Node Host 排障](#node-host-提示后台服务不完整) 检查安装包和 LaunchDaemon。

### 4.3 粘贴 code 并确认授权

1. 粘贴 `pn-node-v1...` setup code。
2. 点击 **Review setup**。
3. 核对网络名称、Control host 和过期时间。
4. 确认“我拥有或控制此 Mac”。
5. 确认“朋友流量会从此网络出口”。
6. 根据网络环境选择 relay 和自动路由器映射。
7. 设置流量、带宽和并发限制。
8. 点击 **Pair and start**。

授权含义：

- **Use managed relay**：允许节点使用 Control 分配的内置 relay，推荐无法端口转发时启用。
- **Try automatic router mapping**：允许尝试 PCP、NAT-PMP 和 UPnP；失败会安全回退。
- **Monthly transfer**：本月观察到的 Xray 流量达到上限后暂停可用性。
- **Bandwidth limit**：节点共享入口的带宽限制。
- **Concurrent sessions**：同时连接数量上限。

Vultr + FRP 是单独配置的 provider-owned manual endpoint，不是内置 managed relay assignment。
是否勾选 managed relay 不会自动安装、启动或配置 FRP。

节点正常时应显示：

- `Online`
- Runtime `Serving`
- Revision 为数字且与 Control desired revision 一致
- Public path 为 `Direct verified` 或 `Relay verified`

### 4.4 配置 Vultr + FRP 入口

在 VPS 按 [deploy/vultr-relay](../deploy/vultr-relay/README.md) 安装 `frps`，然后在 Mac 安装
`frpc`：

```bash
brew install frpc
sudo install -d -m 0750 /opt/homebrew/etc/frp
sudo install -m 0600 /path/to/token /opt/homebrew/etc/frp/token
sudo install -m 0644 deploy/vultr-relay/frpc.example.toml /opt/homebrew/etc/frp/frpc.toml
brew services start frpc
```

先把 `frpc.toml` 中的 `VPS_PUBLIC_IPV4` 替换为实际地址。默认数据路径为：

```text
VPS:443 -> Mac 127.0.0.1:10443
```

然后在 Node Host 的 **Advanced endpoint -> Configure endpoint** 中填写：

- Address：VPS 公网 IPv4 或稳定域名
- Public port：`443`

这是有限期的 provider-owned endpoint。过期前需要重新确认；配置版本保持同一转发端口时，
Node Host 可以携带现有批准进入新 revision，但不会延长原过期时间。

### 4.5 直接公网入口

如果节点有公网 IPv4 和路由器控制权，优先在配对时允许自动 mapping。手工映射必须指向
Node Host 当前 revision 管理的 admission port，而不是随意把 Xray 私有 backend 暴露到 LAN。

直接入口还需要：

- 路由器和 macOS 防火墙允许对应 TCP；
- 动态公网 IP 变化后有 DDNS 或重新发布 endpoint；
- Control 的外部 protocol canary 验证通过；
- 不使用 `ping` 作为判断标准，ICMP 失败不代表 TCP 443 不可用。

## 5. 添加朋友账号

### 5.1 每位朋友一个账号

在 Control 中进入 **朋友 -> 添加朋友**：

1. 输入朋友名称。
2. 选择这个账号可以使用的全部节点。
3. 创建账号。
4. 点击账号的登录/Setup 操作，生成一次性 Connect code。
5. 只把 code 发给对应朋友。

不要让 3 到 5 个人共用一个账号。独立账号才能单独禁用、删除、统计和轮换节点凭据。

CLI 等价流程：

```bash
python3 scripts/product/control-service.py create-account \
  --display-name "Friend 1"

python3 scripts/product/control-service.py assign-account \
  --user-id USER_ID \
  --node-id NODE_ID_1 \
  --node-id NODE_ID_2

python3 scripts/product/control-service.py create-connect-code \
  --user-id USER_ID
```

`assign-account` 中重复使用 `--node-id` 表示完整目标列表，不是增量追加。完全不传
`--node-id` 会从所有节点移除该账号。

### 5.2 修改账号节点

在朋友账号上选择 **编辑节点**，勾选新的完整节点列表并保存。Control 会创建新 revision，
各 Node Host 验证并应用后，Connect 下一次同步会收到新 bundle。

不要因为短暂的 `pending` 连续重复点击。依次确认：

```text
desired -> received -> validated -> applied -> bundle available
```

### 5.3 账号状态

| 操作 | 可恢复 | 结果 |
| --- | --- | --- |
| Active | 是 | 账号正常使用 |
| Disabled | 是 | 暂停全部节点访问，保留账号 |
| Deleted | 否 | 终止账号并从所有节点删除凭据 |

怀疑设备丢失时先 `Disabled`，确认后再 `Deleted`。删除后应创建新账号，不应尝试复用旧 code。

## 6. 使用 Connect

### 6.1 首次登录

1. 安装并打开 **Private Network Connect**。
2. 粘贴网络所有者提供的 `pn-member...` code。
3. 点击 **Continue**。
4. 核对网络名称和 Control host。
5. 为当前设备填写名称，例如 `Alice MacBook`。
6. 点击 **Join network**。

setup code 消费后不能在第二台设备重复使用。朋友新增设备时，网络所有者应为同一账号生成新
Connect code。

Connect 会自动保存登录状态，不需要朋友手工创建或管理 Keychain 项。macOS/Linux 默认写入
当前用户独占的应用凭据文件（目录 `0700`、文件 `0600`）；Windows 使用 Credential Manager。
macOS 旧版本留下的 Keychain 项不会被新版读取或自动删除。升级后如果账号或兼容连接未出现，
为该设备重新生成一次 Connect code，或重新导入原始 `vless://` 链接。

### 6.2 连接和断开

- 点击中央电源按钮连接。
- 默认 `Automatic` 会从健康节点中选择最佳可用路径。
- 点击具体节点可固定为 `Manual`；该节点失败时不会自动换到其他节点。
- 点击 **Sync now** 强制刷新账号 bundle 和探测节点。
- 再次点击电源按钮断开并恢复之前的系统代理设置。

系统代理模式会在异常退出后根据本地恢复记录进行清理。不要在 Connect 正在连接时手工改同一
网络服务的 HTTP、HTTPS 或 SOCKS 代理，否则恢复结果可能与预期不同。

### 6.3 手动代理

高级应用可以直接使用：

```text
SOCKS5  127.0.0.1:10808
HTTP    127.0.0.1:10809
```

只有 Connect 显示 `Connected` 时这些端口才有有效数据路径。SOCKS 应使用远程 DNS 模式
（通常称为 `socks5h`），避免域名在本机提前解析。

### 6.4 移除此设备账号

Connect 的 **Settings -> Remove account from this device** 会：

- 先断开；
- 删除本机 refresh credential、设备密钥和缓存节点；
- 不删除 Control 中的朋友账号；
- 不影响同一账号的其他设备。

如果设备丢失，仅在本机点 Remove 不够；网络所有者应禁用该账号或通过管理 API 撤销对应
device，并让剩余设备重新同步。

## 7. 日常管理

### 7.1 服务启动和停止

Control Service：

```bash
python3 scripts/product/control-service.py status
python3 scripts/product/control-service.py stop
python3 scripts/product/control-service.py start
```

Node Host 服务由系统 LaunchDaemon 启动。查看状态：

```bash
launchctl print system/com.sky.realitynode.agent

'/Library/Application Support/Private Network Node/current/node-host' \
  system-control status
```

不需要保持 Control 或 Node Host 窗口打开。

重启行为：

| 进程 | 默认启动级别 | 重启后何时启动 |
| --- | --- | --- |
| Node Host | 系统 LaunchDaemon | 开机后，无需图形用户登录 |
| Control Service | 当前用户 LaunchAgent | 网络所有者登录后 |
| `brew services` 安装的 `frpc` | 当前用户 LaunchAgent | 对应用户登录后 |
| Control / Node Host UI | 普通桌面应用 | 手工打开，不影响已运行服务 |

Control Service 离线时，已应用的 Node Host 和仍在 `offlineExpiresAt` 期限内的 Connect 缓存可
继续工作；新设备登录、bundle 更新、管理操作和遥测同步会等待 Control 恢复。要求无人登录也能
恢复控制面和 FRP 时，应将它们部署为经过测试的系统服务，或把 Control/relay 移到 VPS；不要
依赖自动登录。

### 7.2 本地暂停节点

Node Host 点击 **Pause** 会立即停止该节点的数据路径和公网发布，不需要等待 Control 在线。
本地 owner pause 的优先级高于 Control 的 active 状态。恢复时点击 **Resume**。

### 7.3 禁用和撤销节点

| 操作 | 可恢复 | 使用时机 |
| --- | --- | --- |
| Approve | 是 | 批准 pending 节点 |
| Disable | 是 | 临时停止新配置和客户端使用 |
| Revoke | 否 | 节点丢失、转让或身份不再可信 |

CLI：

```bash
python3 scripts/product/control-service.py set-node-status \
  --node-id NODE_ID \
  --status disable
```

`revoke` 后该安装必须重新配对为新 node identity，不能通过 `approve` 恢复。

### 7.4 更新共享限制

Node Host 的 Monthly transfer、Bandwidth limit 和 Concurrent sessions 是节点所有者的本地
权力。Control 不能绕过本地 pause 或提高节点所有者拒绝的限制。

流量数字是 Xray 已观察到的下限，不应当作运营商账单或精确计费依据。

### 7.5 睡眠、合盖和锁屏

- **锁屏**：后台服务继续运行。
- **显示器关闭**：通常不影响后台服务。
- **系统睡眠**：Control Service、Node Host、FRP 和 Xray 都会暂停。
- **MacBook 合盖**：没有满足 macOS closed-display 条件时通常会睡眠。
- **Mac mini**：接电、关闭自动睡眠并保持网络连接后更适合长期节点。

如果使用防睡眠工具，应选择“允许锁屏、只阻止系统睡眠”的模式。不要关闭屏幕锁定来换取
后台运行。更改后务必用手机蜂窝网络做真实外网测试。

### 7.6 更新软件

Node Host `.pkg` 升级会：

1. 保留旧服务运行直到 payload 到位；
2. 快照 state、identity、SQLite WAL/SHM 和权限；
3. 停止旧 daemon；
4. 验证新 App、Node Host、Xray 和 sidecar manifest；
5. 迁移并启动新 daemon；
6. 失败时恢复上一 release 和状态。

不要用拖拽 App 覆盖系统 Node Host 安装。始终使用匹配版本的 `.pkg`。

## 8. 状态与故障排查

### 8.1 快速检查顺序

遇到“朋友连不上”时按控制链路顺序检查：

1. Control Service 是否 healthy。
2. Node 是否 active、online、not paused。
3. desired revision 是否等于 applied revision。
4. endpoint 是否通过 protocol verification。
5. 朋友账号是否 active 且分配到该节点。
6. assignment provisioning 是否 applied。
7. Connect 是否同步到最新 bundle。
8. Connect 本地 Xray 是否 connected。
9. 最后再测试真实 HTTP/SOCKS 流量。

不要只看 `ping` 或“TCP 端口能打开”。REALITY endpoint 必须通过完整协议 canary。

### Control Service 不健康

```bash
python3 scripts/product/control-service.py status

tail -n 100 \
  "$HOME/Library/Application Support/Private Network/Control Service/logs/control-service.error.log"

curl --fail http://127.0.0.1:8787/healthz
```

常见原因：

- Mac 睡眠或用户未登录，LaunchAgent 没有运行；
- `control-service.json` 被修改为非 loopback bind；
- Xray 路径不存在或文件 digest 已变化；
- 数据库或 controller identity 权限被破坏；
- 公开 tunnel 正常，但本机 `8787` 服务已停止。

不要删除数据库来“重试”。先保留整个 Control Service 数据目录并检查日志。

### 邀请码在其他电脑上不可用

检查 Control 网络页是否提示“目前只有本机地址”。setup code 内的 origin 必须是远程设备可达的
HTTPS 地址，而不是：

```text
http://127.0.0.1:8787
http://localhost:8787
局域网 http://192.168.x.x:8787
```

其他常见原因：code 已过期、已使用、复制不完整，或创建 code 后又更改了 public origin。

### Node Host 提示后台服务不完整

先确认运行的是正式安装版，不是 `target/.../bundle` 中的开发 App：

```bash
pgrep -alf private-network-node-host-app
```

正式进程路径应位于：

```text
/Applications/Private Network Node.app/Contents/MacOS/
```

检查 daemon 和 package receipt：

```bash
launchctl print system/com.sky.realitynode.agent
pkgutil --pkg-info com.sky.realitynode.pkg
```

检查安全状态接口：

```bash
'/Library/Application Support/Private Network Node/current/node-host' \
  system-control status
```

如果 daemon 不存在或 package 资产缺失，重新运行匹配版本的 Node Host `.pkg`。不要把
`node-host` 手工放进 PATH，也不要把 `_privnetnode` 状态目录改成当前用户所有。

### Node Online 但 endpoint 未验证

`Serving` 只说明本机 Xray 正常，不代表公网可达。继续检查：

```bash
nc -vz 127.0.0.1 10443
nc -vz VPS_PUBLIC_IPV4 443
```

第二条只证明 TCP 建连。还需要：

- FRP route 指向正确本机端口；
- Control 外部 probe 可以访问；
- Node revision、REALITY public key、short ID、server name 和 canary credential 完全匹配；
- endpoint 没有过期；
- VPS firewall 允许 `443/tcp`。

### FRP 中继不可用

Mac：

```bash
brew services list | grep frpc
pgrep -alf frpc
/opt/homebrew/opt/frpc/bin/frpc verify -c /opt/homebrew/etc/frp/frpc.toml
```

VPS：

```bash
sudo systemctl status frps
sudo journalctl -u frps -n 100 --no-pager
sudo ss -lntp | grep -E ':(443|7000)\b'
sudo ufw status
```

检查两端 token 完全一致、VPS IP 未变化、`7000/tcp` 可达、remote port 没有被其他服务占用。

### Connect 显示 No nodes assigned

在 Control 中检查：

- 账号不是 disabled/deleted；
- 账号至少分配一个 active 节点；
- 节点 applied 最新 revision；
- endpoint 已 verified；
- assignment provisioning 为 applied。

然后在 Connect 点击 **Sync now**。单纯重新生成 Connect code 不会修复未下发的节点配置。

### Connect 连接后没有流量

检查本机端口是否被其他进程占用：

```bash
lsof -nP -iTCP:10808 -sTCP:LISTEN
lsof -nP -iTCP:10809 -sTCP:LISTEN
```

连接期间测试：

```bash
curl --proxy http://127.0.0.1:10809 https://api.ipify.org
curl --socks5-hostname 127.0.0.1:10808 https://api.ipify.org
```

两个结果应为节点出口 IP。若浏览器可用但某个应用不可用，该应用可能忽略系统代理、使用 UDP，
或执行自己的 DNS/QUIC 路径；这不是当前 Connect 能强制接管的范围。

### 刷新或 UI 看起来卡顿

Control、Node Host 和 Connect 的网络操作在 native backend 执行。不要连续点击 Refresh。先等待
当前请求完成，再检查后台服务状态。UI 卡顿不等于后台节点停止；用上述 CLI 状态接口区分 UI
问题和服务问题。

## 9. 备份与恢复

Control 数据库同时绑定 controller signing identity。只复制 SQLite 主文件可能漏掉一致性信息，
必须使用内置 backup 命令。

默认安装的二进制和数据库：

```bash
CONTROL_BIN="$HOME/Library/Application Support/Private Network/Control Service/bin/control-server"
CONTROL_DB="$HOME/Library/Application Support/Private Network/Control Service/state/control-service.sqlite3"
```

备份目标必须位于由你管理的加密存储，例如加密 APFS volume 或已加密备份仓库：

```bash
"$CONTROL_BIN" backup create \
  --database "$CONTROL_DB" \
  --destination /Volumes/EncryptedBackups/control-2026-07-13 \
  --external-encryption-contract encrypted-apfs-v1

"$CONTROL_BIN" backup verify \
  --backup /Volumes/EncryptedBackups/control-2026-07-13
```

应用不会替你加密备份。`--external-encryption-contract` 是操作员确认，不是加密实现。

恢复前：

1. 停止 Control Service。
2. 验证 backup。
3. 先执行 `--dry-run`。
4. 恢复到一个不存在的新 generation 目录。
5. 验证后再修改服务配置指向新数据库。

完整恢复命令和 rollback 防护见 [Control Backup And Recovery](../control-server/OPERATIONS.md)。

## 10. 卸载与重新配对

### 10.1 Connect

1. 在 Settings 选择 **Remove account from this device**。
2. 确认已经断开且系统代理恢复。
3. 退出 Connect。
4. 删除应用。

删除 App 前不移除账号会留下本地凭据和恢复状态；重新安装可能继续识别旧设备。macOS/Linux
的 Connect 数据位于 `~/Library/Application Support/com.sky.realityclient/`，不要在账号仍需
使用时手工删除。

### 10.2 Node Host 仅解除配对

在 Node Host 底部输入完整 Node ID，点击 **Unpair this Mac**。它会：

- 停止 Xray、admission、mapping 和 relay；
- 删除节点 state 和 installation identity；
- 保留 App、系统服务和空的安全目录；
- 回到 `Ready to pair`。

Control 中对应旧节点不会自动变成可复用身份。需要时在 Control 中 revoke 旧节点，再创建新 code。

### 10.3 卸载 Node Host package

保留数据和日志，便于稍后恢复或取证：

```bash
sudo '/Library/Application Support/Private Network Node/bin/private-network-node-uninstall' \
  --preserve-data
```

已经先完成 Unpair，且确认永久清理本机状态：

```bash
sudo '/Library/Application Support/Private Network Node/bin/private-network-node-uninstall' \
  --purge-data --confirm-unpaired
```

仍处于 paired 状态时，purge 要求精确 Node ID：

```bash
sudo '/Library/Application Support/Private Network Node/bin/private-network-node-uninstall' \
  --purge-data --confirm-node-id NODE_ID
```

`--purge-data` 不可恢复。优先在 UI 中 Unpair，再使用 `--confirm-unpaired`。

### 10.4 Control Service

当前产品脚本提供 stop/start/update，没有一键 destructive uninstall。保留数据时只停止服务：

```bash
python3 scripts/product/control-service.py stop
```

需要迁移时，先创建并验证加密 backup，然后保留整个目录：

```text
~/Library/Application Support/Private Network/Control Service/
```

不要只删除 LaunchAgent 后遗忘数据库，也不要在没有可验证 backup 时手工清空该目录。

## 11. 安全与隐私

- setup code 是 bearer secret。收到它的人在过期前可能消费邀请。
- setup link 把 secret 放在 HTTPS fragment 中，浏览器正常不会把 fragment 发送给服务器；仍不要
  转发到公开群聊或截图。
- 管理 token 只在确实配置管理客户端时通过 `admin-token` 命令查看。
- 每个朋友使用独立账号，每台 Connect 设备使用独立 device identity。
- macOS/Linux 的 Connect 凭据文件虽然仅当前用户可读，但不具备 Keychain 的额外访问控制；
  同一用户权限下运行的恶意软件仍可能读取它。不要在不可信或多人共用的系统账号中使用。
- Relay 看不到 REALITY 明文，但可以观察元数据；VPS 管理员仍是信任边界的一部分。
- Control 默认只保留最小化流量聚合；详细连接目的地记录默认关闭。
- Node Host 流量最终从节点网络出口。节点所有者应明确同意，并理解朋友行为可能影响其公网 IP
  信誉、运营商配额和法律责任。
- 不要将 Node Host、Control Service、FRP token、backup 或 credential-store 导出到公开仓库。
- 非商业或亲友用途不自动豁免当地法律、服务商条款或网络内容规则。

对于实现级安全保证、威胁模型和凭据生命周期，以 [SECURITY.md](./SECURITY.md) 为准。
