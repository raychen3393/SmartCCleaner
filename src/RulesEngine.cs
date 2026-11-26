using System;
using System.Collections.Generic;
using System.IO;
using Microsoft.Win32;

namespace SmartCCleaner
{
    public static class RulesEngine
    {
        public static List<CleanRule> BuildDefaultRules()
        {
            string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            string docs = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            string userTemp = Path.GetTempPath();

            var rules = new List<CleanRule>();

            // =========================================================================
            // 1. 系统垃圾 (System Junk)
            // =========================================================================

            rules.Add(new CleanRule
            {
                Id = "sys_user_temp",
                Name = "用户临时文件 (User Temp)",
                Description = "应用程序安装、解压缩和运行过程中残留的临时文件（自动跳过 5 分钟内新创建文件）。",
                SafetyNote = "安全可清理；正在占用的临时文件会自动跳过。",
                Category = CleanCategory.SystemJunk,
                Risk = RiskLevel.Safe,
                DefaultSelected = true,
                RequiresAdmin = false,
                Targets = new List<CleanTargetSpec>
                {
                    new CleanTargetSpec { PathPattern = userTemp, Recursive = true, MinAgeMinutes = 5 },
                    new CleanTargetSpec { PathPattern = Path.Combine(localAppData, "Temp"), Recursive = true, MinAgeMinutes = 5 }
                }
            });

            rules.Add(new CleanRule
            {
                Id = "sys_win_temp",
                Name = "Windows 系统临时文件",
                Description = "C:\\Windows\\Temp 中的系统级临时文件与安装日志残留。",
                SafetyNote = "安全可清理；部分文件需要管理员权限。",
                Category = CleanCategory.SystemJunk,
                Risk = RiskLevel.Safe,
                DefaultSelected = true,
                RequiresAdmin = true,
                Targets = new List<CleanTargetSpec>
                {
                    new CleanTargetSpec { PathPattern = @"C:\Windows\Temp", Recursive = true, MinAgeMinutes = 5 }
                }
            });

            rules.Add(new CleanRule
            {
                Id = "sys_recycle_bin",
                Name = "C盘回收站",
                Description = "清空 C 盘回收站中已删除但仍占用空间的文件。",
                SafetyNote = "清空后无法直接从回收站还原，请确认无误删文件。",
                Category = CleanCategory.SystemJunk,
                Risk = RiskLevel.Safe,
                DefaultSelected = true,
                RequiresAdmin = false,
                Targets = new List<CleanTargetSpec>
                {
                    new CleanTargetSpec { PathPattern = @"C:\$Recycle.Bin", Kind = TargetKind.RecycleBin }
                }
            });

            rules.Add(new CleanRule
            {
                Id = "sys_win_update",
                Name = "Windows 更新下载缓存",
                Description = "系统已下载的更新补丁安装包（SoftwareDistribution\\Download），管理员模式下自动协同暂停/恢复更新服务。",
                SafetyNote = "清理后不影响已安装更新，未完成的更新会在下次检查时重新下载。",
                Category = CleanCategory.SystemJunk,
                Risk = RiskLevel.Safe,
                DefaultSelected = true,
                RequiresAdmin = true,
                Targets = new List<CleanTargetSpec>
                {
                    new CleanTargetSpec { PathPattern = @"C:\Windows\SoftwareDistribution\Download", Recursive = true }
                }
            });

            rules.Add(new CleanRule
            {
                Id = "sys_delivery_opt",
                Name = "Windows 传递优化缓存",
                Description = "用于局域网/P2P 分发系统更新的缓存文件。",
                SafetyNote = "安全可清理，系统按需重建。",
                Category = CleanCategory.SystemJunk,
                Risk = RiskLevel.Safe,
                DefaultSelected = true,
                RequiresAdmin = true,
                Targets = new List<CleanTargetSpec>
                {
                    new CleanTargetSpec { PathPattern = @"C:\Windows\SoftwareDistribution\DeliveryOptimization\Cache", Recursive = true },
                    new CleanTargetSpec { PathPattern = @"C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache", Recursive = true }
                }
            });

            rules.Add(new CleanRule
            {
                Id = "sys_thumb_cache",
                Name = "缩略图与图标缓存",
                Description = "资源管理器生成的图片/视频缩略图缓存数据库（thumbcache_*.db）。",
                SafetyNote = "安全可清理；正在被资源管理器锁定的文件会自动跳过，清理后自动重建。",
                Category = CleanCategory.SystemJunk,
                Risk = RiskLevel.Safe,
                DefaultSelected = true,
                RequiresAdmin = false,
                Targets = new List<CleanTargetSpec>
                {
                    new CleanTargetSpec
                    {
                        PathPattern = Path.Combine(localAppData, @"Microsoft\Windows\Explorer"),
                        SearchPattern = "thumbcache_*.db",
                        Recursive = false,
                        Kind = TargetKind.FilePattern
                    },
                    new CleanTargetSpec
                    {
                        PathPattern = Path.Combine(localAppData, @"Microsoft\Windows\Explorer"),
                        SearchPattern = "iconcache_*.db",
                        Recursive = false,
                        Kind = TargetKind.FilePattern
                    }
                }
            });

            rules.Add(new CleanRule
            {
                Id = "sys_wer_dumps",
                Name = "错误报告与崩溃转储日志",
                Description = "Windows 错误报告 (WER)、程序崩溃 Dump 及内核转储日志。",
                SafetyNote = "除非需要排查近期蓝屏/崩溃问题，否则可安全清理。",
                Category = CleanCategory.SystemJunk,
                Risk = RiskLevel.Safe,
                DefaultSelected = true,
                RequiresAdmin = false,
                Targets = new List<CleanTargetSpec>
                {
                    new CleanTargetSpec { PathPattern = Path.Combine(localAppData, @"Microsoft\Windows\WER"), Recursive = true },
                    new CleanTargetSpec { PathPattern = Path.Combine(localAppData, "CrashDumps"), Recursive = true },
                    new CleanTargetSpec { PathPattern = @"C:\ProgramData\Microsoft\Windows\WER", Recursive = true },
                    new CleanTargetSpec { PathPattern = @"C:\Windows\Minidump", Recursive = true },
                    new CleanTargetSpec { PathPattern = @"C:\Windows\LiveKernelReports", Recursive = true }
                }
            });

            rules.Add(new CleanRule
            {
                Id = "sys_gpu_shader_cache",
                Name = "DirectX / 显卡着色器缓存",
                Description = "DirectX、NVIDIA、AMD、Intel 显卡编译留下的旧着色器缓存。",
                SafetyNote = "安全可清理；游戏或 3D 应用首次启动时会自动重新生成。",
                Category = CleanCategory.SystemJunk,
                Risk = RiskLevel.Safe,
                DefaultSelected = true,
                RequiresAdmin = false,
                Targets = new List<CleanTargetSpec>
                {
                    new CleanTargetSpec { PathPattern = Path.Combine(localAppData, "D3DSCache"), Recursive = true },
                    new CleanTargetSpec { PathPattern = Path.Combine(localAppData, @"NVIDIA\DXCache"), Recursive = true },
                    new CleanTargetSpec { PathPattern = Path.Combine(localAppData, @"NVIDIA\GLCache"), Recursive = true },
                    new CleanTargetSpec { PathPattern = Path.Combine(localAppData, @"AMD\DxCache"), Recursive = true },
                    new CleanTargetSpec { PathPattern = Path.Combine(localAppData, @"Intel\ShaderCache"), Recursive = true }
                }
            });

            rules.Add(new CleanRule
            {
                Id = "sys_win_logs",
                Name = "Windows 系统诊断与安装日志",
                Description = "CBS 归档日志、DISM 日志及系统更新日志备份。",
                SafetyNote = "仅清理日志和归档文件，不影响系统组件。",
                Category = CleanCategory.SystemJunk,
                Risk = RiskLevel.Safe,
                DefaultSelected = true,
                RequiresAdmin = true,
                Targets = new List<CleanTargetSpec>
                {
                    new CleanTargetSpec { PathPattern = @"C:\Windows\Logs\CBS", SearchPattern = "*.cab", Recursive = false, Kind = TargetKind.FilePattern },
                    new CleanTargetSpec { PathPattern = @"C:\Windows\Logs\CBS", SearchPattern = "*.log", Recursive = false, Kind = TargetKind.FilePattern },
                    new CleanTargetSpec { PathPattern = @"C:\Windows\Logs\DISM", SearchPattern = "*.log", Recursive = false, Kind = TargetKind.FilePattern },
                    new CleanTargetSpec { PathPattern = @"C:\Windows\Logs\WindowsUpdate", SearchPattern = "*.etl", Recursive = false, Kind = TargetKind.FilePattern }
                }
            });

            // =========================================================================
            // 2. 浏览器缓存 (Browser Caches)
            // =========================================================================

            rules.Add(BuildChromiumBrowserRule(
                "browser_edge",
                "Microsoft Edge 网页缓存",
                Path.Combine(localAppData, @"Microsoft\Edge\User Data"),
                new[] { "msedge" }));

            rules.Add(BuildChromiumBrowserRule(
                "browser_chrome",
                "Google Chrome 网页缓存",
                Path.Combine(localAppData, @"Google\Chrome\User Data"),
                new[] { "chrome" }));

            rules.Add(BuildChromiumBrowserRule(
                "browser_brave",
                "Brave 浏览器缓存",
                Path.Combine(localAppData, @"BraveSoftware\Brave-Browser\User Data"),
                new[] { "brave" }));

            rules.Add(new CleanRule
            {
                Id = "browser_firefox",
                Name = "Mozilla Firefox 网页缓存",
                Description = "Firefox 网页静态资源缓存（cache2），绝不删除书签、密码与登录态。",
                SafetyNote = "纯缓存清理，安全无副作用；默认不勾选，按需手动选择。",
                Category = CleanCategory.BrowserCache,
                Risk = RiskLevel.Safe,
                DefaultSelected = false,
                RequiresAdmin = false,
                AssociatedProcesses = new[] { "firefox" },
                Targets = new List<CleanTargetSpec>
                {
                    new CleanTargetSpec { PathPattern = Path.Combine(localAppData, @"Mozilla\Firefox\Profiles\*\cache2"), Recursive = true },
                    new CleanTargetSpec { PathPattern = Path.Combine(localAppData, @"Mozilla\Firefox\Profiles\*\startupCache"), Recursive = true }
                }
            });

            rules.Add(new CleanRule
            {
                Id = "browser_webview2",
                Name = "Edge WebView2 应用内嵌缓存",
                Description = "Windows 应用内嵌浏览器组件产生的临时网页缓存。",
                SafetyNote = "安全可清理；正在运行的应用占用文件会自动跳过。",
                Category = CleanCategory.BrowserCache,
                Risk = RiskLevel.Safe,
                DefaultSelected = false,
                RequiresAdmin = false,
                Targets = new List<CleanTargetSpec>
                {
                    new CleanTargetSpec { PathPattern = Path.Combine(localAppData, @"Microsoft\EdgeWebView\User Data\*\Cache\Cache_Data"), Recursive = true },
                    new CleanTargetSpec { PathPattern = Path.Combine(localAppData, @"Microsoft\EdgeWebView\User Data\*\GPUCache"), Recursive = true }
                }
            });

            // =========================================================================
            // 3. 常用软件缓存 (Common Apps Cache)
            // =========================================================================

            var wechatTargets = new List<CleanTargetSpec>();
            string wechatRoot = DetectWeChatFilesRoot(docs);
            if (!string.IsNullOrEmpty(wechatRoot))
            {
                wechatTargets.Add(new CleanTargetSpec { PathPattern = Path.Combine(wechatRoot, @"*\FileStorage\Cache"), Recursive = true });
                wechatTargets.Add(new CleanTargetSpec { PathPattern = Path.Combine(wechatRoot, @"*\FileStorage\Temp"), Recursive = true });
                wechatTargets.Add(new CleanTargetSpec { PathPattern = Path.Combine(wechatRoot, @"*\FileStorage\Sns\Cache"), Recursive = true });
            }
            wechatTargets.Add(new CleanTargetSpec { PathPattern = Path.Combine(docs, @"xwechat_files\*\temp"), Recursive = true });
            wechatTargets.Add(new CleanTargetSpec { PathPattern = Path.Combine(appData, @"Tencent\WeChat\All Users\CefResources"), Recursive = true });
            wechatTargets.Add(new CleanTargetSpec { PathPattern = Path.Combine(appData, @"Tencent\xwechat\radium\cache"), Recursive = true });

            rules.Add(new CleanRule
            {
                Id = "app_wechat",
                Name = "微信 (WeChat) 临时与预览缓存",
                Description = "仅清理微信的临时/朋友圈预览/网页缓存，严格保护聊天记录、图片、视频与收发文件。",
                SafetyNote = "绝不触碰 Msg/File/Image/Video 目录，但仍建议按需勾选。",
                Category = CleanCategory.CommonApps,
                Risk = RiskLevel.Medium,
                DefaultSelected = false,
                RequiresAdmin = false,
                AssociatedProcesses = new[] { "WeChat", "Weixin" },
                Targets = wechatTargets
            });

            rules.Add(new CleanRule
            {
                Id = "app_qq",
                Name = "QQ / NTQQ 客户端缓存",
                Description = "仅清理 QQ 临时目录与图片/网页缓存，严格保护聊天记录与已接收文件。",
                SafetyNote = "不删除聊天数据库；按需勾选清理。",
                Category = CleanCategory.CommonApps,
                Risk = RiskLevel.Medium,
                DefaultSelected = false,
                RequiresAdmin = false,
                AssociatedProcesses = new[] { "QQ" },
                Targets = new List<CleanTargetSpec>
                {
                    new CleanTargetSpec { PathPattern = Path.Combine(appData, @"Tencent\QQ\Temp"), Recursive = true },
                    new CleanTargetSpec { PathPattern = Path.Combine(localAppData, @"Tencent\QQNT\Cache"), Recursive = true },
                    new CleanTargetSpec { PathPattern = Path.Combine(docs, @"Tencent Files\*\nt_qq\nt_data\Cache"), Recursive = true }
                }
            });

            rules.Add(new CleanRule
            {
                Id = "app_office_im",
                Name = "钉钉 / 飞书 / 企业微信 缓存",
                Description = "办公沟通软件内置浏览器的静态缓存和 GPU 缓存。",
                SafetyNote = "仅清理缓存，不影响登录信息与本地文档。",
                Category = CleanCategory.CommonApps,
                Risk = RiskLevel.Medium,
                DefaultSelected = false,
                RequiresAdmin = false,
                AssociatedProcesses = new[] { "DingTalk", "Feishu", "Lark", "WXWork" },
                Targets = new List<CleanTargetSpec>
                {
                    new CleanTargetSpec { PathPattern = Path.Combine(appData, @"DingTalk\*\Cache"), Recursive = true },
                    new CleanTargetSpec { PathPattern = Path.Combine(localAppData, @"LarkShell\sdk_storage\cache"), Recursive = true },
                    new CleanTargetSpec { PathPattern = Path.Combine(appData, @"LarkShell\Cache"), Recursive = true },
                    new CleanTargetSpec { PathPattern = Path.Combine(appData, @"Tencent\WXWork\Cache"), Recursive = true }
                }
            });

            rules.Add(new CleanRule
            {
                Id = "app_vscode_editors",
                Name = "VS Code / Cursor 编辑器缓存",
                Description = "Electron 内核缓存、旧版本缓存数据（CachedData / GPUCache / Code Cache）。",
                SafetyNote = "不影响扩展、设置和代码项目；建议关闭编辑器后清理。",
                Category = CleanCategory.CommonApps,
                Risk = RiskLevel.Medium,
                DefaultSelected = false,
                RequiresAdmin = false,
                AssociatedProcesses = new[] { "Code", "Cursor" },
                Targets = new List<CleanTargetSpec>
                {
                    new CleanTargetSpec { PathPattern = Path.Combine(appData, @"Code\Cache\Cache_Data"), Recursive = true },
                    new CleanTargetSpec { PathPattern = Path.Combine(appData, @"Code\CachedData"), Recursive = true },
                    new CleanTargetSpec { PathPattern = Path.Combine(appData, @"Code\GPUCache"), Recursive = true },
                    new CleanTargetSpec { PathPattern = Path.Combine(appData, @"Code\Code Cache"), Recursive = true },
                    new CleanTargetSpec { PathPattern = Path.Combine(appData, @"Cursor\Cache\Cache_Data"), Recursive = true },
                    new CleanTargetSpec { PathPattern = Path.Combine(appData, @"Cursor\CachedData"), Recursive = true },
                    new CleanTargetSpec { PathPattern = Path.Combine(appData, @"Cursor\GPUCache"), Recursive = true }
                }
            });

            rules.Add(new CleanRule
            {
                Id = "app_media_cache",
                Name = "网易云音乐 / Bilibili 客户端缓存",
                Description = "音视频客户端的在线试听/网页缓存。",
                SafetyNote = "不影响已下载的本地歌曲或视频。",
                Category = CleanCategory.CommonApps,
                Risk = RiskLevel.Medium,
                DefaultSelected = false,
                RequiresAdmin = false,
                AssociatedProcesses = new[] { "cloudmusic", "bilibili" },
                Targets = new List<CleanTargetSpec>
                {
                    new CleanTargetSpec { PathPattern = Path.Combine(localAppData, @"Netease\CloudMusic\Cache"), Recursive = true },
                    new CleanTargetSpec { PathPattern = Path.Combine(localAppData, @"Netease\CloudMusic\webdata\Cache"), Recursive = true },
                    new CleanTargetSpec { PathPattern = Path.Combine(appData, @"bilibili\Cache"), Recursive = true },
                    new CleanTargetSpec { PathPattern = Path.Combine(appData, @"bilibili\GPUCache"), Recursive = true }
                }
            });

            // =========================================================================
            // 4. 开发工具缓存 (Developer Caches)
            // =========================================================================

            rules.Add(new CleanRule
            {
                Id = "dev_npm_yarn_pnpm",
                Name = "Node.js 包缓存 (npm / Yarn / pnpm)",
                Description = "前端包管理器下载的 tarball 与元数据缓存（已支持超长路径扫描与清理）。",
                SafetyNote = "清理后不影响现有项目 node_modules，下次安装新依赖时按需重新下载。",
                Category = CleanCategory.DevTools,
                Risk = RiskLevel.Medium,
                DefaultSelected = false,
                RequiresAdmin = false,
                Targets = new List<CleanTargetSpec>
                {
                    new CleanTargetSpec { PathPattern = Path.Combine(localAppData, "npm-cache"), Recursive = true },
                    new CleanTargetSpec { PathPattern = Path.Combine(appData, "npm-cache"), Recursive = true },
                    new CleanTargetSpec { PathPattern = Path.Combine(localAppData, @"Yarn\Cache"), Recursive = true },
                    new CleanTargetSpec { PathPattern = Path.Combine(localAppData, "pnpm-cache"), Recursive = true }
                }
            });

            rules.Add(new CleanRule
            {
                Id = "dev_python_pip_uv",
                Name = "Python 包缓存 (pip / uv)",
                Description = "pip 与 uv 下载的 wheel / sdist 安装包缓存。",
                SafetyNote = "不影响已安装的 Python 虚拟环境和包。",
                Category = CleanCategory.DevTools,
                Risk = RiskLevel.Medium,
                DefaultSelected = false,
                RequiresAdmin = false,
                Targets = new List<CleanTargetSpec>
                {
                    new CleanTargetSpec { PathPattern = Path.Combine(localAppData, @"pip\cache"), Recursive = true },
                    new CleanTargetSpec { PathPattern = Path.Combine(localAppData, @"uv\cache"), Recursive = true }
                }
            });

            rules.Add(new CleanRule
            {
                Id = "dev_nuget",
                Name = ".NET NuGet 包缓存",
                Description = "C# / .NET 项目本地缓存的 NuGet 包与 v3 索引缓存。",
                SafetyNote = "清理后再次编译 .NET 项目时会自动重新还原所需包。",
                Category = CleanCategory.DevTools,
                Risk = RiskLevel.Medium,
                DefaultSelected = false,
                RequiresAdmin = false,
                Targets = new List<CleanTargetSpec>
                {
                    new CleanTargetSpec { PathPattern = Path.Combine(localAppData, @"NuGet\v3-cache"), Recursive = true },
                    new CleanTargetSpec { PathPattern = Path.Combine(userProfile, @".nuget\packages"), Recursive = true }
                }
            });

            rules.Add(new CleanRule
            {
                Id = "dev_java_maven_gradle",
                Name = "Java 依赖缓存 (Gradle / Maven)",
                Description = "Gradle 构建缓存与 Maven 本地仓库缓存（支持超长路径）。",
                SafetyNote = "体积通常很大；清理后下次构建项目会重新拉取依赖，请按需勾选。",
                Category = CleanCategory.DevTools,
                Risk = RiskLevel.Caution,
                DefaultSelected = false,
                RequiresAdmin = false,
                Targets = new List<CleanTargetSpec>
                {
                    new CleanTargetSpec { PathPattern = Path.Combine(userProfile, @".gradle\caches"), Recursive = true },
                    new CleanTargetSpec { PathPattern = Path.Combine(userProfile, @".m2\repository"), Recursive = true }
                }
            });

            rules.Add(new CleanRule
            {
                Id = "dev_go_cargo",
                Name = "Go / Rust 构建与包缓存",
                Description = "Go 编译缓存（go-build）与 Cargo 注册表压缩包缓存。",
                SafetyNote = "不影响已编译产物，下次构建时按需重建。",
                Category = CleanCategory.DevTools,
                Risk = RiskLevel.Medium,
                DefaultSelected = false,
                RequiresAdmin = false,
                Targets = new List<CleanTargetSpec>
                {
                    new CleanTargetSpec { PathPattern = Path.Combine(localAppData, "go-build"), Recursive = true },
                    new CleanTargetSpec { PathPattern = Path.Combine(userProfile, @".cargo\registry\cache"), Recursive = true }
                }
            });

            rules.Add(new CleanRule
            {
                Id = "dev_jetbrains",
                Name = "JetBrains IDE 索引与日志缓存",
                Description = "IntelliJ IDEA / PyCharm / Rider / WebStorm 的旧索引缓存与日志。",
                SafetyNote = "关闭对应 IDE 后清理，下次打开项目会自动重建索引。",
                Category = CleanCategory.DevTools,
                Risk = RiskLevel.Medium,
                DefaultSelected = false,
                RequiresAdmin = false,
                AssociatedProcesses = new[] { "idea64", "pycharm64", "rider64", "webstorm64" },
                Targets = new List<CleanTargetSpec>
                {
                    new CleanTargetSpec { PathPattern = Path.Combine(localAppData, @"JetBrains\*\caches"), Recursive = true },
                    new CleanTargetSpec { PathPattern = Path.Combine(localAppData, @"JetBrains\*\log"), Recursive = true }
                }
            });

            rules.Add(new CleanRule
            {
                Id = "dev_docker_logs",
                Name = "Docker Desktop 日志与虚拟磁盘检测",
                Description = "可安全清理 Docker 运行日志；若检测到超大 WSL/Docker 虚拟磁盘 (vhdx)，仅提示建议命令绝不直接删除。",
                SafetyNote = "日志可直接清理；vhdx 镜像需通过 docker system prune 释放，避免破坏容器数据。",
                Category = CleanCategory.DevTools,
                Risk = RiskLevel.Medium,
                DefaultSelected = false,
                RequiresAdmin = false,
                AssociatedProcesses = new[] { "Docker Desktop" },
                Targets = new List<CleanTargetSpec>
                {
                    new CleanTargetSpec { PathPattern = Path.Combine(localAppData, @"Docker\log"), Recursive = true },
                    new CleanTargetSpec { PathPattern = Path.Combine(localAppData, @"Docker\wsl\data\ext4.vhdx"), Kind = TargetKind.AdvisoryOnly },
                    new CleanTargetSpec { PathPattern = Path.Combine(localAppData, @"Docker\wsl\disk\docker_data.vhdx"), Kind = TargetKind.AdvisoryOnly }
                }
            });

            return rules;
        }

        private static CleanRule BuildChromiumBrowserRule(string id, string name, string userDataRoot, string[] procs)
        {
            return new CleanRule
            {
                Id = id,
                Name = name,
                Description = "仅清理网页资源缓存、代码缓存与 GPU 缓存，严格保留书签、密码、Cookie 与扩展。",
                SafetyNote = "纯缓存清理，安全无副作用；默认不勾选，按需手动选择。",
                Category = CleanCategory.BrowserCache,
                Risk = RiskLevel.Safe,
                DefaultSelected = false,
                RequiresAdmin = false,
                AssociatedProcesses = procs,
                Targets = new List<CleanTargetSpec>
                {
                    new CleanTargetSpec { PathPattern = Path.Combine(userDataRoot, @"*\Cache\Cache_Data"), Recursive = true },
                    new CleanTargetSpec { PathPattern = Path.Combine(userDataRoot, @"*\Code Cache"), Recursive = true },
                    new CleanTargetSpec { PathPattern = Path.Combine(userDataRoot, @"*\GPUCache"), Recursive = true },
                    new CleanTargetSpec { PathPattern = Path.Combine(userDataRoot, @"ShaderCache"), Recursive = true },
                    new CleanTargetSpec { PathPattern = Path.Combine(userDataRoot, @"GrShaderCache"), Recursive = true }
                }
            };
        }

        private static string DetectWeChatFilesRoot(string docsFolder)
        {
            try
            {
                using (RegistryKey key = Registry.CurrentUser.OpenSubKey(@"Software\Tencent\WeChat"))
                {
                    if (key != null)
                    {
                        string val = key.GetValue("FileSavePath") as string;
                        if (!string.IsNullOrWhiteSpace(val) && !string.Equals(val, "MyDocument:", StringComparison.OrdinalIgnoreCase))
                        {
                            string customPath = Path.Combine(val, "WeChat Files");
                            if (Directory.Exists(customPath)) return customPath;
                            if (Directory.Exists(val)) return val;
                        }
                    }
                }
            }
            catch
            {
            }

            if (!string.IsNullOrEmpty(docsFolder))
            {
                string defaultPath = Path.Combine(docsFolder, "WeChat Files");
                if (Directory.Exists(defaultPath)) return defaultPath;
            }
            return string.Empty;
        }
    }
}
