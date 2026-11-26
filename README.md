# C盘智清 (SmartCCleaner v2.0)

一款基于原生 Windows WPF (.NET Framework 4.8) 构建的 **零依赖、高速并行、安全透明的 C 盘智能清理桌面软件**，附带专属无残留卸载向导 `Uninstall.exe`。

## v2.0 核心特性与工程优化

1. **Win32 原生高速扫描引擎**
   - 使用 `FindFirstFileExW`（单次系统调用获取大小、时间与符号链接属性）+ `\\?\` 超长路径支持（彻底解决 `npm`、`Gradle`、`JetBrains` 超过 260 字符缓存漏扫）；
   - 4 线程受控并发扫描，多分类同时体检更迅速；
   - 预编译白名单正则快照，热点扫描路径零额外内存分配。

2. **全面智能清理与安全保护**
   - **系统垃圾 & 浏览器缓存**（默认安全勾选）：用户/系统 Temp（自动保护 5 分钟内新文件）、C 盘回收站、Windows 更新缓存（管理员模式下自动协同暂停/恢复 `wuauserv` 服务）、传递优化、缩略图、错误报告/Dump、显卡着色器缓存、Edge/Chrome/Brave/Firefox/WebView2 网页缓存。
   - **常用软件 & 开发工具缓存**（默认不勾选，按需确认）：微信/xwechat、QQ/NTQQ、钉钉/飞书/企业微信、VS Code/Cursor、网易云音乐/Bilibili、npm/Yarn/pnpm、pip/uv、NuGet、Gradle/Maven、Go/Cargo、JetBrains、Docker 日志与虚拟磁盘检测。
   - **运行中进程感知**：自动检测正在运行的关联软件（如 `chrome`、`msedge`、`WeChat`、`Code`）并标注提示。
   - **可撤销保护**：支持勾选「常用/开发缓存优先移入回收站（可撤销）」。
   - **单实例防冲突 & 配置持久化**：重复双击自动唤醒已有窗口；自动记忆演练模式、回收站偏好与窗口大小；支持一键创建桌面快捷方式。
   - **流式完整审计日志**：使用 `StreamWriter` 边清理边写入完整无截断日志。

3. **专属卸载程序 (`Uninstall.exe`)**
   - 自动检测并关闭运行中的 `SmartCCleaner.exe`；
   - 一键移除主程序、桌面/开始菜单快捷方式、可选清空 `%LocalAppData%\SmartCCleaner`（白名单、配置与日志）；
   - 内置路径安全校验（绝不误删桌面、文档或磁盘根目录），卸载完成后自动执行无残留自删除。

## 发布文件位置 (`dist\`)
- `dist\SmartCCleaner.exe` — 主程序（约 119 KB，双击即用）
- `dist\Uninstall.exe` — 专属卸载程序（约 41 KB）
- `dist\C盘智清_v2.0_绿色分享版.zip` — 包含主程序、卸载程序与使用说明的分享压缩包，可直接发给朋友

## 重新编译与运行测试
```powershell
powershell -ExecutionPolicy Bypass -File .\build.ps1
```
测试程序会独立输出至 `build\tests\SmartCCleaner.Tests.exe`，保持 `dist\` 目录整洁。
