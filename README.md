# DSH LAN Access

把原生 DeepSeek Harness Web UI 转发到局域网或外部端口映射，并用“设备申请 + owner 审批”替代一次性登录 token。

它只做两件事：**认证**和**转发**。不启动第二套界面、不做 VPN/隧道/端口映射。

## 特性

- 监听一个可配置端口（默认 `0.0.0.0:8097`），反代到本机 DSH Web；
- 新设备第一次访问显示等待页，owner 在管理页允许后才放行；
- 已批准设备获得持久 HttpOnly 设备 Cookie，DSH/容器重启后不需要重新配对；
- 移除设备立即撤销；
- 支持 HTTP / WebSocket；
- 设备 IP **不参与鉴权**，只作为申请来源显示；动态 IP、换网络不会导致设备失效；
- Web profile 的管理页嵌入 DSH **设置 → 局域网访问**；
- Desktop 使用本机回环管理页 `http://127.0.0.1:8097/__manage`；
- 本机 `127.0.0.1` 访问 8097 直接放行，不进入设备配对；
- 管理 API 接受桌面端显式的 `x-dsh-lan-admin` 请求头，避免被 CSRF 保护误伤。

## 安全模型

设备真正的凭据是审批后签发的设备 Cookie（随机设备 ID + HMAC + 注册表），
不是 IP，也不是浏览器指纹。指纹（UA/系统/屏幕/语言/时区哈希）只用于识别和展示。

P1 仅支持 HTTP。通过公网端口映射使用时，链路不加密；`tls.certFile` / `tls.keyFile`
配置入口已预留，但尚未验收。不要把 DSH 管理入口（通常是 8096）映射到公网，只映射
本插件的 8097。

## 安装

### 作为 DSH bundle

把本目录放到本机任意位置，然后在 DSH 的 **插件 → 添加插件** 中选择这个目录；
或在对应 profile 中执行：

```sh
dsh plugin --profile desktop add /path/to/dsh-lan-access
dsh plugin --profile web add /path/to/dsh-lan-access
```

安装后重启 DSH（web profile 可重启容器）。

### NAS / Docker

```sh
# 把本目录放到 DSH_HOME 下，例如 /data/plugins/dsh-lan-access
docker exec dsh dsh plugin --profile web add /data/plugins/dsh-lan-access
docker restart dsh
```

owner 登录地址在容器日志：

```sh
docker logs dsh 2>&1 | grep 'dsh web:' | tail -1
```

## 使用

- 设备访问 `http://<主机>:8097`；
- 在管理页点 **允许**：
  - Web profile：DSH 设置 → 局域网访问；
  - Desktop：`http://127.0.0.1:8097/__manage`（只有本机可打开）；
- 设备自动进入原生 DSH Web；
- 需要撤销时，在管理页对已批准设备点 **移除**。

## 配置

在 bundle 的 `cordis.patch.yml` 中：

```yaml
config:
  bind: 0.0.0.0
  port: 8097
  # 可选，未验收：
  # tls:
  #   certFile: /path/to/cert.pem
  #   keyFile: /path/to/key.pem
```

## 开发

```sh
node --check index.js
node --check client.js
```

Host 代码在 `index.js`，浏览器端管理页在 `client.js`；无需构建，直接作为 bundle 安装。

## License

MIT
