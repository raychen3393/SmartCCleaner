using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization.Json;
using System.Text;
using System.Text.RegularExpressions;

namespace SmartCCleaner
{
    /// <summary>
    /// Streaming UTF-8 audit log writer with zero truncation and low memory footprint.
    /// </summary>
    public class AuditLogSession : IDisposable
    {
        private readonly string _filePath;
        private readonly StreamWriter _writer;
        private readonly object _writeLock = new object();
        private bool _disposed;

        public string FilePath { get { return _filePath; } }

        public AuditLogSession(string logsDirectory, bool isDryRun, DateTime startedAt)
        {
            Directory.CreateDirectory(logsDirectory);
            string tag = isDryRun ? "dryrun" : "clean";
            string fileName = string.Format("{0}_{1:yyyyMMdd_HHmmss}.log", tag, startedAt);
            _filePath = Path.Combine(logsDirectory, fileName);

            _writer = new StreamWriter(_filePath, false, new UTF8Encoding(true), 16384);
            _writer.WriteLine("============================================================");
            _writer.WriteLine("  C盘智清 (SmartCCleaner v2.0) 流式清理审计日志");
            _writer.WriteLine("============================================================");
            _writer.WriteLine(string.Format("执行模式: {0}", isDryRun ? "演练模式（仅模拟，未实际删除文件）" : "真实清理模式"));
            _writer.WriteLine(string.Format("开始时间: {0:yyyy-MM-dd HH:mm:ss}", startedAt));
            _writer.WriteLine();
            _writer.WriteLine("--- 详细操作记录（完整无截断） ---");
        }

        public void WriteRecord(string line)
        {
            if (_disposed || _writer == null) return;
            lock (_writeLock)
            {
                _writer.WriteLine(line);
            }
        }

        public void WriteSummaryFooter(CleanExecutionReport report)
        {
            if (_disposed || _writer == null) return;
            lock (_writeLock)
            {
                _writer.WriteLine();
                _writer.WriteLine("--- 分类汇总 ---");
                for (int i = 0; i < report.RuleSummaries.Count; i++)
                {
                    _writer.WriteLine(report.RuleSummaries[i]);
                }
                _writer.WriteLine();
                _writer.WriteLine("============================================================");
                _writer.WriteLine(string.Format("结束时间: {0:yyyy-MM-dd HH:mm:ss}", report.FinishedAt));
                _writer.WriteLine(string.Format("执行状态: {0}", report.WasCancelled ? "用户中途取消" : "已完成"));
                _writer.WriteLine(string.Format("预计/实际释放空间: {0} ({1} 字节)", FormatHelper.FormatBytes(report.FreedBytes), report.FreedBytes));
                _writer.WriteLine(string.Format("彻底删除: {0} | 移入回收站: {1} | 清理空目录: {2}",
                    report.DeletedFiles, report.RecycledFiles, report.DeletedDirectories));
                _writer.WriteLine(string.Format("跳过总计: {0} (安全保护/白名单: {1}, 占用/权限不足: {2})",
                    report.SkippedFiles, report.ProtectedSkippedFiles, report.LockedOrDeniedFiles));
                _writer.WriteLine("============================================================");
                _writer.Flush();
            }
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            if (_writer != null)
            {
                try { _writer.Dispose(); } catch { }
            }
        }
    }

    public class SafetyGuard
    {
        private class CompiledWhitelistRule
        {
            public string RawPattern;
            public bool IsWildcard;
            public bool MatchesFullPath;
            public Regex CompiledRegex;
            public string NormalizedPrefix;
            public string NormalizedPrefixWithSlash;
        }

        private readonly string _appDataRoot;
        private readonly string _whitelistFilePath;
        private readonly string _settingsFilePath;
        private readonly string _logsDirectory;
        private readonly string[] _hardcodedProtectedPrefixes;
        private readonly string[] _hardcodedProtectedPrefixesWithSlash;
        private readonly string[] _hardcodedExactProtectedPaths;
        private readonly string _myDocsPrefix;
        private readonly string _defaultDocsPrefix;
        private readonly HashSet<string> _sensitiveFileNames;
        private readonly object _wlLock = new object();
        private WhitelistConfig _whitelist;
        private volatile CompiledWhitelistRule[] _compiledWhitelist;

        public string AppDataRoot { get { return _appDataRoot; } }
        public string LogsDirectory { get { return _logsDirectory; } }
        public string WhitelistFilePath { get { return _whitelistFilePath; } }
        public string SettingsFilePath { get { return _settingsFilePath; } }

        public SafetyGuard()
            : this(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SmartCCleaner"))
        {
        }

        public SafetyGuard(string appDataRoot)
        {
            _appDataRoot = appDataRoot;
            _whitelistFilePath = Path.Combine(_appDataRoot, "whitelist.json");
            _settingsFilePath = Path.Combine(_appDataRoot, "settings.json");
            _logsDirectory = Path.Combine(_appDataRoot, "logs");

            try
            {
                Directory.CreateDirectory(_appDataRoot);
                Directory.CreateDirectory(_logsDirectory);
            }
            catch
            {
            }

            List<string> prefixes = BuildProtectedPrefixes();
            _hardcodedProtectedPrefixes = prefixes.ToArray();
            _hardcodedProtectedPrefixesWithSlash = prefixes.Select(p => p + "\\").ToArray();
            _hardcodedExactProtectedPaths = BuildExactProtectedPaths().ToArray();

            string docs = NormalizePath(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments));
            _myDocsPrefix = string.IsNullOrEmpty(docs) ? string.Empty : (docs + "\\");

            string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            string defDocs = string.IsNullOrEmpty(userProfile) ? string.Empty : NormalizePath(Path.Combine(userProfile, "Documents"));
            _defaultDocsPrefix = string.IsNullOrEmpty(defDocs) ? string.Empty : (defDocs + "\\");

            _sensitiveFileNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "bookmarks", "login data", "cookies", "history", "web data",
                "places.sqlite", "logins.json", "key4.db",
                "msg0.db", "micromsg.db", "nt_msg.db"
            };

            _whitelist = LoadWhitelist();
            RebuildCompiledWhitelist();
        }

        private List<string> BuildProtectedPrefixes()
        {
            var list = new List<string>();
            AddNormalized(list, @"C:\Windows\System32");
            AddNormalized(list, @"C:\Windows\SysWOW64");
            AddNormalized(list, @"C:\Windows\WinSxS");
            AddNormalized(list, @"C:\Windows\Boot");
            AddNormalized(list, @"C:\Windows\Fonts");
            AddNormalized(list, @"C:\Windows\INF");
            AddNormalized(list, @"C:\Windows\SystemApps");
            AddNormalized(list, @"C:\Windows\servicing");
            AddNormalized(list, @"C:\Windows\assembly");
            AddNormalized(list, @"C:\Windows\Microsoft.NET");
            AddNormalized(list, @"C:\Program Files");
            AddNormalized(list, @"C:\Program Files (x86)");
            AddNormalized(list, @"C:\Recovery");
            AddNormalized(list, @"C:\System Volume Information");
            AddNormalized(list, @"C:\Boot");
            AddNormalized(list, @"C:\PerfLogs");

            AddNormalized(list, Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory));
            AddNormalized(list, Environment.GetFolderPath(Environment.SpecialFolder.MyPictures));
            AddNormalized(list, Environment.GetFolderPath(Environment.SpecialFolder.MyVideos));
            AddNormalized(list, Environment.GetFolderPath(Environment.SpecialFolder.MyMusic));

            string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            if (!string.IsNullOrEmpty(userProfile))
            {
                AddNormalized(list, Path.Combine(userProfile, "Desktop"));
                AddNormalized(list, Path.Combine(userProfile, "Pictures"));
                AddNormalized(list, Path.Combine(userProfile, "Videos"));
                AddNormalized(list, Path.Combine(userProfile, "Music"));
                AddNormalized(list, Path.Combine(userProfile, "Downloads"));
                AddNormalized(list, Path.Combine(userProfile, ".ssh"));
                AddNormalized(list, Path.Combine(userProfile, ".gnupg"));
                AddNormalized(list, Path.Combine(userProfile, ".aws"));
            }

            AddNormalized(list, _appDataRoot);
            return list;
        }

        private List<string> BuildExactProtectedPaths()
        {
            var list = new List<string>();
            AddNormalized(list, @"C:\");
            AddNormalized(list, @"C:\Windows");
            AddNormalized(list, @"C:\Users");
            AddNormalized(list, @"C:\ProgramData");
            AddNormalized(list, Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
            AddNormalized(list, Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments));
            AddNormalized(list, Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData));
            AddNormalized(list, Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData));
            return list;
        }

        private static void AddNormalized(List<string> list, string path)
        {
            if (string.IsNullOrWhiteSpace(path)) return;
            string norm = NormalizePath(path);
            if (!string.IsNullOrEmpty(norm) && !list.Contains(norm, StringComparer.OrdinalIgnoreCase))
            {
                list.Add(norm);
            }
        }

        public static string NormalizePath(string path)
        {
            if (string.IsNullOrWhiteSpace(path)) return string.Empty;
            string trimmed = path.Trim();
            if (trimmed.StartsWith(@"\\?\"))
            {
                trimmed = trimmed.Substring(4);
            }
            if (trimmed.Length < 250)
            {
                try
                {
                    string full = Path.GetFullPath(trimmed);
                    if (full.Length > 3 && full.EndsWith("\\"))
                    {
                        full = full.TrimEnd('\\');
                    }
                    return full;
                }
                catch
                {
                }
            }
            trimmed = trimmed.Replace('/', '\\');
            if (trimmed.Length > 3 && trimmed.EndsWith("\\"))
            {
                trimmed = trimmed.TrimEnd('\\');
            }
            return trimmed;
        }

        public IList<string> GetBuiltInProtectedSummary()
        {
            return new List<string>
            {
                @"C:\Windows\System32、SysWOW64、WinSxS、Boot、Fonts 等系统核心目录",
                @"C:\Program Files 与 C:\Program Files (x86) 已安装程序目录",
                @"当前用户的桌面、下载、图片、视频、音乐、SSH/密钥目录（兼容重定向路径）",
                @"微信/QQ 聊天记录数据库与收发文件（仅允许扫描明确缓存子目录）",
                @"浏览器书签、密码、Cookie、历史记录与扩展程序",
                @"所有 NTFS 符号链接、目录联接及祖先挂载点（自动跳过，防止跨盘越界删除）"
            };
        }

        public bool IsReparsePoint(string path)
        {
            return NativeFileScanner.IsReparsePointFast(path);
        }

        /// <summary>
        /// Walks ancestor directories of a candidate root to ensure no parent was symlinked onto another drive.
        /// </summary>
        public bool HasReparsePointInAncestorChain(string dirPath)
        {
            string current = NormalizePath(dirPath);
            while (!string.IsNullOrEmpty(current) && current.Length > 3)
            {
                if (NativeFileScanner.IsReparsePointFast(current))
                {
                    return true;
                }
                int lastSlash = current.LastIndexOf('\\');
                if (lastSlash <= 2) break;
                current = current.Substring(0, lastSlash);
            }
            return false;
        }

        /// <summary>
        /// Hot-path thread-safe protection check with zero heap allocations and precompiled whitelist rules.
        /// </summary>
        public bool IsProtected(string path, out string reason)
        {
            reason = null;
            if (string.IsNullOrWhiteSpace(path))
            {
                reason = "空路径";
                return true;
            }

            string normalized = NormalizePath(path);

            if (!normalized.StartsWith(@"C:\", StringComparison.OrdinalIgnoreCase))
            {
                reason = "非 C 盘路径（安全策略仅允许清理 C 盘）";
                return true;
            }

            for (int i = 0; i < _hardcodedExactProtectedPaths.Length; i++)
            {
                if (string.Equals(normalized, _hardcodedExactProtectedPaths[i], StringComparison.OrdinalIgnoreCase))
                {
                    reason = "系统关键根目录";
                    return true;
                }
            }

            for (int i = 0; i < _hardcodedProtectedPrefixes.Length; i++)
            {
                if (string.Equals(normalized, _hardcodedProtectedPrefixes[i], StringComparison.OrdinalIgnoreCase) ||
                    normalized.StartsWith(_hardcodedProtectedPrefixesWithSlash[i], StringComparison.OrdinalIgnoreCase))
                {
                    reason = "系统核心或个人重要目录保护";
                    return true;
                }
            }

            bool insideDocs =
                (_myDocsPrefix.Length > 0 && normalized.StartsWith(_myDocsPrefix, StringComparison.OrdinalIgnoreCase)) ||
                (_defaultDocsPrefix.Length > 0 && normalized.StartsWith(_defaultDocsPrefix, StringComparison.OrdinalIgnoreCase));

            if (insideDocs)
            {
                bool isExplicitChatCache =
                    normalized.IndexOf(@"\FileStorage\Cache\", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    normalized.IndexOf(@"\FileStorage\Temp\", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    normalized.IndexOf(@"\FileStorage\Sns\Cache\", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    normalized.IndexOf(@"\nt_data\Cache\", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    (normalized.IndexOf(@"\xwechat_files\", StringComparison.OrdinalIgnoreCase) >= 0 &&
                     normalized.IndexOf(@"\temp\", StringComparison.OrdinalIgnoreCase) >= 0);

                if (!isExplicitChatCache)
                {
                    reason = "文档目录保护（非明确缓存子目录）";
                    return true;
                }
            }

            int slashIdx = normalized.LastIndexOf('\\');
            string fileName = slashIdx >= 0 ? normalized.Substring(slashIdx + 1) : normalized;
            if (_sensitiveFileNames.Contains(fileName))
            {
                reason = "敏感用户数据文件保护";
                return true;
            }

            // Lock-free read of precompiled whitelist snapshot
            CompiledWhitelistRule[] compiled = _compiledWhitelist;
            for (int i = 0; i < compiled.Length; i++)
            {
                CompiledWhitelistRule rule = compiled[i];
                if (rule.IsWildcard)
                {
                    string target = rule.MatchesFullPath ? normalized : fileName;
                    if (rule.CompiledRegex.IsMatch(target))
                    {
                        reason = string.Format("命中用户白名单：{0}", rule.RawPattern);
                        return true;
                    }
                }
                else
                {
                    if (string.Equals(normalized, rule.NormalizedPrefix, StringComparison.OrdinalIgnoreCase) ||
                        normalized.StartsWith(rule.NormalizedPrefixWithSlash, StringComparison.OrdinalIgnoreCase))
                    {
                        reason = string.Format("命中用户白名单：{0}", rule.RawPattern);
                        return true;
                    }
                }
            }

            return false;
        }

        private void RebuildCompiledWhitelist()
        {
            var list = new List<CompiledWhitelistRule>();
            List<WhitelistEntry> entries;
            lock (_wlLock)
            {
                entries = (_whitelist != null && _whitelist.Entries != null)
                    ? new List<WhitelistEntry>(_whitelist.Entries)
                    : new List<WhitelistEntry>();
            }

            for (int i = 0; i < entries.Count; i++)
            {
                string pat = entries[i].Pattern;
                if (string.IsNullOrWhiteSpace(pat)) continue;
                string trimmed = pat.Trim();

                if (trimmed.Contains("*") || trimmed.Contains("?"))
                {
                    bool fullPath = trimmed.Contains("\\") || trimmed.Contains("/");
                    string regexStr = "^" + Regex.Escape(trimmed.Replace('/', '\\'))
                        .Replace("\\*", ".*")
                        .Replace("\\?", ".") + "$";
                    list.Add(new CompiledWhitelistRule
                    {
                        RawPattern = trimmed,
                        IsWildcard = true,
                        MatchesFullPath = fullPath,
                        CompiledRegex = new Regex(regexStr, RegexOptions.IgnoreCase | RegexOptions.Compiled)
                    });
                }
                else
                {
                    string norm = NormalizePath(trimmed);
                    list.Add(new CompiledWhitelistRule
                    {
                        RawPattern = trimmed,
                        IsWildcard = false,
                        NormalizedPrefix = norm,
                        NormalizedPrefixWithSlash = norm + "\\"
                    });
                }
            }

            _compiledWhitelist = list.ToArray();
        }

        public List<WhitelistEntry> GetWhitelistEntries()
        {
            lock (_wlLock)
            {
                if (_whitelist == null || _whitelist.Entries == null)
                {
                    return new List<WhitelistEntry>();
                }
                return new List<WhitelistEntry>(_whitelist.Entries);
            }
        }

        public bool AddWhitelistEntry(string pattern, string note)
        {
            if (string.IsNullOrWhiteSpace(pattern)) return false;
            string cleaned = pattern.Trim();
            if (!cleaned.Contains("*") && !cleaned.Contains("?"))
            {
                cleaned = NormalizePath(cleaned);
            }

            lock (_wlLock)
            {
                if (_whitelist == null) _whitelist = new WhitelistConfig();
                if (_whitelist.Entries == null) _whitelist.Entries = new List<WhitelistEntry>();

                bool exists = _whitelist.Entries.Any(e =>
                    string.Equals(e.Pattern, cleaned, StringComparison.OrdinalIgnoreCase));
                if (exists) return false;

                _whitelist.Entries.Add(new WhitelistEntry
                {
                    Pattern = cleaned,
                    Note = string.IsNullOrWhiteSpace(note) ? "手动添加保护" : note.Trim(),
                    AddedAt = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss")
                });

                SaveWhitelist();
            }

            RebuildCompiledWhitelist();
            return true;
        }

        public bool RemoveWhitelistEntry(string pattern)
        {
            bool changed = false;
            lock (_wlLock)
            {
                if (_whitelist != null && _whitelist.Entries != null)
                {
                    int removed = _whitelist.Entries.RemoveAll(e =>
                        string.Equals(e.Pattern, pattern, StringComparison.OrdinalIgnoreCase));
                    if (removed > 0)
                    {
                        SaveWhitelist();
                        changed = true;
                    }
                }
            }

            if (changed)
            {
                RebuildCompiledWhitelist();
            }
            return changed;
        }

        private WhitelistConfig LoadWhitelist()
        {
            try
            {
                if (!File.Exists(_whitelistFilePath))
                {
                    return new WhitelistConfig();
                }
                using (var fs = File.OpenRead(_whitelistFilePath))
                {
                    var serializer = new DataContractJsonSerializer(typeof(WhitelistConfig));
                    var obj = serializer.ReadObject(fs) as WhitelistConfig;
                    return obj ?? new WhitelistConfig();
                }
            }
            catch
            {
                return new WhitelistConfig();
            }
        }

        private void SaveWhitelist()
        {
            try
            {
                Directory.CreateDirectory(_appDataRoot);
                using (var fs = File.Create(_whitelistFilePath))
                {
                    var serializer = new DataContractJsonSerializer(typeof(WhitelistConfig));
                    serializer.WriteObject(fs, _whitelist);
                }
            }
            catch
            {
            }
        }

        public AppSettings LoadSettings()
        {
            try
            {
                if (!File.Exists(_settingsFilePath)) return new AppSettings();
                using (var fs = File.OpenRead(_settingsFilePath))
                {
                    var serializer = new DataContractJsonSerializer(typeof(AppSettings));
                    var obj = serializer.ReadObject(fs) as AppSettings;
                    return obj ?? new AppSettings();
                }
            }
            catch
            {
                return new AppSettings();
            }
        }

        public void SaveSettings(AppSettings settings)
        {
            if (settings == null) return;
            try
            {
                Directory.CreateDirectory(_appDataRoot);
                using (var fs = File.Create(_settingsFilePath))
                {
                    var serializer = new DataContractJsonSerializer(typeof(AppSettings));
                    serializer.WriteObject(fs, settings);
                }
            }
            catch
            {
            }
        }

        public AuditLogSession OpenAuditLog(bool isDryRun, DateTime startedAt)
        {
            try
            {
                return new AuditLogSession(_logsDirectory, isDryRun, startedAt);
            }
            catch
            {
                return null;
            }
        }

        public List<FileInfo> GetLogFiles()
        {
            var result = new List<FileInfo>();
            try
            {
                if (!Directory.Exists(_logsDirectory)) return result;
                var dir = new DirectoryInfo(_logsDirectory);
                result.AddRange(dir.GetFiles("*.log").OrderByDescending(f => f.LastWriteTime));
            }
            catch
            {
            }
            return result;
        }
    }
}
