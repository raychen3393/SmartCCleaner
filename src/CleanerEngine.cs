using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.ServiceProcess;
using System.Threading;
using System.Threading.Tasks;

namespace SmartCCleaner
{
    public class CleanerEngine
    {
        private readonly SafetyGuard _guard;

        public SafetyGuard Guard { get { return _guard; } }

        public CleanerEngine(SafetyGuard guard)
        {
            _guard = guard;
        }

        public static bool IsRunningAsAdministrator()
        {
            try
            {
                using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
                {
                    var principal = new WindowsPrincipal(identity);
                    return principal.IsInRole(WindowsBuiltInRole.Administrator);
                }
            }
            catch
            {
                return false;
            }
        }

        public static DriveUsageInfo GetCDriveUsage()
        {
            try
            {
                var drive = new DriveInfo("C");
                return new DriveUsageInfo
                {
                    DriveLetter = "C:",
                    TotalBytes = drive.TotalSize,
                    FreeBytes = drive.AvailableFreeSpace
                };
            }
            catch
            {
                return new DriveUsageInfo { DriveLetter = "C:", TotalBytes = 1, FreeBytes = 0 };
            }
        }

        public static HashSet<string> SnapshotRunningProcessNames()
        {
            var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                Process[] procs = Process.GetProcesses();
                for (int i = 0; i < procs.Length; i++)
                {
                    try
                    {
                        set.Add(procs[i].ProcessName);
                    }
                    catch
                    {
                    }
                    finally
                    {
                        try { procs[i].Dispose(); } catch { }
                    }
                }
            }
            catch
            {
            }
            return set;
        }

        #region Win32 Recycle Bin Interop

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct SHQUERYRBINFO
        {
            public int cbSize;
            public long i64Size;
            public long i64NumItems;
        }

        [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
        private static extern int SHQueryRecycleBinW(string pszRootPath, ref SHQUERYRBINFO pSHQueryRBInfo);

        [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
        private static extern int SHEmptyRecycleBinW(IntPtr hwnd, string pszRootPath, uint dwFlags);

        private const uint SHERB_NOCONFIRMATION = 0x00000001;
        private const uint SHERB_NOPROGRESSUI = 0x00000002;
        private const uint SHERB_NOSOUND = 0x00000004;

        private static bool TryQueryRecycleBin(string rootPath, out long sizeBytes, out long itemCount)
        {
            sizeBytes = 0;
            itemCount = 0;
            try
            {
                var info = new SHQUERYRBINFO();
                info.cbSize = Marshal.SizeOf(typeof(SHQUERYRBINFO));
                int hr = SHQueryRecycleBinW(rootPath, ref info);
                if (hr == 0)
                {
                    sizeBytes = info.i64Size;
                    itemCount = info.i64NumItems;
                    return true;
                }
            }
            catch
            {
            }
            return false;
        }

        #endregion

        /// <summary>
        /// Controlled parallel scan across independent rules (MaxDegreeOfParallelism = 4).
        /// </summary>
        public Task<List<RuleScanResult>> ScanAsync(
            List<CleanRule> rules,
            IProgress<ScanProgressInfo> progress,
            CancellationToken cancellationToken)
        {
            return Task.Run(() =>
            {
                HashSet<string> runningProcs = SnapshotRunningProcessNames();
                var resultsArray = new RuleScanResult[rules.Count];
                int completedCount = 0;
                long totalFoundBytes = 0;
                int totalFoundFiles = 0;
                object progressLock = new object();

                var parallelOpts = new ParallelOptions
                {
                    MaxDegreeOfParallelism = Math.Min(4, Math.Max(2, Environment.ProcessorCount)),
                    CancellationToken = cancellationToken
                };

                Parallel.For(0, rules.Count, parallelOpts, idx =>
                {
                    CleanRule rule = rules[idx];
                    RuleScanResult scanResult = ScanSingleRule(rule, runningProcs, cancellationToken);
                    resultsArray[idx] = scanResult;

                    int done = Interlocked.Increment(ref completedCount);
                    long bytesNow = Interlocked.Add(ref totalFoundBytes, scanResult.TotalBytes);
                    int filesNow = Interlocked.Add(ref totalFoundFiles, scanResult.FileCount);

                    if (progress != null)
                    {
                        lock (progressLock)
                        {
                            progress.Report(new ScanProgressInfo
                            {
                                CompletedRules = done,
                                TotalRules = rules.Count,
                                CurrentRuleName = rule.Name,
                                CurrentPath = "",
                                FoundBytesSoFar = bytesNow,
                                FoundFilesSoFar = filesNow
                            });
                        }
                    }
                });

                if (progress != null)
                {
                    progress.Report(new ScanProgressInfo
                    {
                        CompletedRules = rules.Count,
                        TotalRules = rules.Count,
                        CurrentRuleName = "扫描完成",
                        CurrentPath = "",
                        FoundBytesSoFar = totalFoundBytes,
                        FoundFilesSoFar = totalFoundFiles
                    });
                }

                return resultsArray.Where(r => r != null).ToList();
            }, cancellationToken);
        }

        public RuleScanResult ScanSingleRule(CleanRule rule, CancellationToken cancellationToken)
        {
            return ScanSingleRule(rule, null, cancellationToken);
        }

        public RuleScanResult ScanSingleRule(CleanRule rule, HashSet<string> runningProcs, CancellationToken cancellationToken)
        {
            var result = new RuleScanResult
            {
                Rule = rule,
                IsSelected = rule.DefaultSelected
            };

            if (runningProcs != null && rule.AssociatedProcesses != null && rule.AssociatedProcesses.Length > 0)
            {
                for (int i = 0; i < rule.AssociatedProcesses.Length; i++)
                {
                    string proc = rule.AssociatedProcesses[i];
                    if (runningProcs.Contains(proc))
                    {
                        result.RunningProcesses.Add(proc);
                    }
                }
            }

            var seenFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            for (int t = 0; t < rule.Targets.Count; t++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                CleanTargetSpec spec = rule.Targets[t];

                if (spec.Kind == TargetKind.RecycleBin)
                {
                    long rbSize, rbItems;
                    if (TryQueryRecycleBin(@"C:\", out rbSize, out rbItems))
                    {
                        result.IsDetected = true;
                        if (rbSize > 0 || rbItems > 0)
                        {
                            result.TotalBytes += rbSize;
                            result.FileCount += (int)Math.Min(rbItems, int.MaxValue);
                            result.Items.Add(new ScannedFileItem
                            {
                                FullPath = @"C:\$Recycle.Bin",
                                DisplayName = string.Format("C 盘回收站（共 {0} 个已删除项目）", rbItems),
                                SizeBytes = rbSize,
                                LastWriteTime = DateTime.Now,
                                IsRecycleBinEntry = true
                            });
                        }
                    }
                    continue;
                }

                if (spec.Kind == TargetKind.AdvisoryOnly)
                {
                    if (File.Exists(spec.PathPattern))
                    {
                        try
                        {
                            var fi = new FileInfo(spec.PathPattern);
                            result.IsDetected = true;
                            result.Items.Add(new ScannedFileItem
                            {
                                FullPath = fi.FullName,
                                DisplayName = string.Format("[仅建议] {0}（不直接删除，请运行 docker system prune）", fi.Name),
                                SizeBytes = fi.Length,
                                LastWriteTime = fi.LastWriteTime,
                                IsAdvisory = true,
                                AdvisoryText = "虚拟磁盘镜像需在 Docker 内部执行 docker system prune 压缩释放"
                            });
                            result.StatusHint = string.Format("检测到 Docker 虚拟磁盘 {0}（仅提示不直接删除）", FormatHelper.FormatBytes(fi.Length));
                        }
                        catch
                        {
                        }
                    }
                    continue;
                }

                List<string> expandedDirs = ExpandDirectoryWildcards(spec.PathPattern);
                for (int d = 0; d < expandedDirs.Count; d++)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    string dir = SafetyGuard.NormalizePath(expandedDirs[d]);
                    if (!Directory.Exists(dir)) continue;

                    // Protect against symlinked roots or symlinked ancestors crossing drives
                    if (_guard.HasReparsePointInAncestorChain(dir))
                    {
                        result.SkippedProtectedCount++;
                        continue;
                    }

                    result.IsDetected = true;
                    if (!result.ResolvedRoots.Contains(dir, StringComparer.OrdinalIgnoreCase))
                    {
                        result.ResolvedRoots.Add(dir);
                    }

                    DateTime cutoff = spec.MinAgeMinutes > 0
                        ? DateTime.Now.AddMinutes(-spec.MinAgeMinutes)
                        : DateTime.MaxValue;

                    int firstNewItem = result.Items.Count;
                    ScanDirectoryFast(dir, spec.SearchPattern, spec.Recursive, cutoff, seenFiles, result, cancellationToken);
                    if (spec.MinAgeMinutes > 0)
                    {
                        for (int n = firstNewItem; n < result.Items.Count; n++)
                        {
                            result.Items[n].MinAgeMinutes = spec.MinAgeMinutes;
                        }
                    }
                    if (spec.AtomicUnitDepth >= 0)
                    {
                        AssignUnitRoots(result.Items, firstNewItem, dir, spec.AtomicUnitDepth);
                    }
                }
            }

            result.Items.Sort((a, b) => b.SizeBytes.CompareTo(a.SizeBytes));

            if (result.AccessDeniedCount > 0 && !IsRunningAsAdministrator())
            {
                result.NeedsElevationForFullAccess = true;
            }

            if (result.TotalBytes == 0 && !result.Items.Any(x => x.IsAdvisory))
            {
                result.IsSelected = false;
            }

            return result;
        }

        private void ScanDirectoryFast(
            string rootDir,
            string searchPattern,
            bool recursive,
            DateTime cutoffTime,
            HashSet<string> seenFiles,
            RuleScanResult result,
            CancellationToken cancellationToken)
        {
            bool hasCustomPattern = !string.IsNullOrEmpty(searchPattern) && searchPattern != "*";
            var stack = new Stack<string>();
            stack.Push(rootDir);
            var children = new List<NativeFileEntry>(128);

            while (stack.Count > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                string currentDir = stack.Pop();

                if (NativeFileScanner.IsReparsePointFast(currentDir))
                {
                    result.SkippedProtectedCount++;
                    continue;
                }

                // 1. Enumerate matching files (if custom pattern, query files with pattern; otherwise single pass for both files & subdirs!)
                children.Clear();
                bool denied;
                NativeFileScanner.TryEnumerateChildren(currentDir, hasCustomPattern ? searchPattern : "*", children, out denied);
                if (denied)
                {
                    result.AccessDeniedCount++;
                    continue;
                }

                for (int i = 0; i < children.Count; i++)
                {
                    NativeFileEntry entry = children[i];

                    if (entry.IsDirectory)
                    {
                        if (!hasCustomPattern && recursive)
                        {
                            string dirReason;
                            if (entry.IsReparsePoint || _guard.IsProtected(entry.FullPath, out dirReason))
                            {
                                result.SkippedProtectedCount++;
                            }
                            else
                            {
                                stack.Push(entry.FullPath);
                            }
                        }
                        continue;
                    }

                    if (seenFiles.Contains(entry.FullPath)) continue;

                    if (entry.IsReparsePoint)
                    {
                        result.SkippedProtectedCount++;
                        continue;
                    }

                    string reason;
                    if (_guard.IsProtected(entry.FullPath, out reason))
                    {
                        result.SkippedProtectedCount++;
                        continue;
                    }

                    if (cutoffTime < DateTime.MaxValue && entry.LastWriteTime > cutoffTime)
                    {
                        continue;
                    }

                    seenFiles.Add(entry.FullPath);
                    result.TotalBytes += entry.SizeBytes;
                    result.FileCount++;
                    result.Items.Add(new ScannedFileItem
                    {
                        FullPath = entry.FullPath,
                        DisplayName = entry.Name,
                        SizeBytes = entry.SizeBytes,
                        LastWriteTime = entry.LastWriteTime
                    });
                }

                // If custom file pattern + recursive, also enumerate subdirectories
                if (hasCustomPattern && recursive)
                {
                    children.Clear();
                    NativeFileScanner.TryEnumerateChildren(currentDir, "*", children, out denied);
                    for (int i = 0; i < children.Count; i++)
                    {
                        NativeFileEntry entry = children[i];
                        if (!entry.IsDirectory) continue;
                        string dirReason;
                        if (entry.IsReparsePoint || _guard.IsProtected(entry.FullPath, out dirReason))
                        {
                            result.SkippedProtectedCount++;
                        }
                        else
                        {
                            stack.Push(entry.FullPath);
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Tags each newly scanned item with the package directory it belongs to.
        /// depth 0 = the scan root itself; depth N = the N-th level directory under the root.
        /// Files shallower than N stay file-level (UnitRoot = null).
        /// </summary>
        private static void AssignUnitRoots(List<ScannedFileItem> items, int startIndex, string rootDir, int depth)
        {
            string prefix = rootDir.TrimEnd('\\') + "\\";
            for (int i = startIndex; i < items.Count; i++)
            {
                string full = items[i].FullPath;
                if (!full.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) continue;

                if (depth == 0)
                {
                    items[i].UnitRoot = rootDir;
                    continue;
                }

                string rel = full.Substring(prefix.Length);
                int pos = -1;
                bool deepEnough = true;
                for (int d = 0; d < depth; d++)
                {
                    pos = rel.IndexOf('\\', pos + 1);
                    if (pos < 0)
                    {
                        deepEnough = false;
                        break;
                    }
                }

                if (deepEnough)
                {
                    items[i].UnitRoot = prefix + rel.Substring(0, pos);
                }
            }
        }

        public static List<string> ExpandDirectoryWildcards(string pattern)
        {
            var results = new List<string>();
            if (string.IsNullOrWhiteSpace(pattern)) return results;

            string normalized = pattern.Trim().Replace('/', '\\');
            if (!normalized.Contains("*") && !normalized.Contains("?"))
            {
                if (Directory.Exists(normalized))
                {
                    results.Add(normalized);
                }
                return results;
            }

            string[] parts = normalized.Split(new[] { '\\' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length == 0) return results;

            var current = new List<string>();
            int startIdx = 0;
            if (parts[0].EndsWith(":"))
            {
                current.Add(parts[0] + "\\");
                startIdx = 1;
            }
            else
            {
                return results;
            }

            for (int i = startIdx; i < parts.Length; i++)
            {
                string segment = parts[i];
                var next = new List<string>();

                for (int c = 0; c < current.Count; c++)
                {
                    string baseDir = current[c];
                    if (segment.Contains("*") || segment.Contains("?"))
                    {
                        try
                        {
                            string[] matches = Directory.GetDirectories(baseDir, segment);
                            next.AddRange(matches);
                        }
                        catch
                        {
                        }
                    }
                    else
                    {
                        string combined = Path.Combine(baseDir, segment);
                        if (Directory.Exists(combined))
                        {
                            next.Add(combined);
                        }
                    }
                }

                current = next;
                if (current.Count == 0) break;
            }

            return current;
        }

        public Task<CleanExecutionReport> CleanAsync(
            List<RuleScanResult> selectedRules,
            CleanOptions options,
            IProgress<CleanProgressInfo> progress,
            CancellationToken cancellationToken)
        {
            if (options == null) options = new CleanOptions();

            return Task.Run(() =>
            {
                var report = new CleanExecutionReport
                {
                    StartedAt = DateTime.Now,
                    IsDryRun = options.IsDryRun
                };

                int totalActionable = 0;
                for (int i = 0; i < selectedRules.Count; i++)
                {
                    totalActionable += selectedRules[i].Items.Count(x => !x.IsAdvisory);
                }

                int processed = 0;
                bool stoppedWuauserv = false;
                bool hasWinUpdateRule = selectedRules.Any(r => r.Rule.Id == "sys_win_update");

                using (AuditLogSession log = _guard.OpenAuditLog(options.IsDryRun, report.StartedAt))
                {
                    if (log != null)
                    {
                        report.LogFilePath = log.FilePath;
                    }

                    // Coordinate Windows Update service when elevated & cleaning update cache
                    if (!options.IsDryRun && options.CoordinateWindowsUpdateService && hasWinUpdateRule && IsRunningAsAdministrator())
                    {
                        stoppedWuauserv = TryTemporarilyStopService("wuauserv");
                        if (stoppedWuauserv && log != null)
                        {
                            log.WriteRecord("[服务协同] 已临时暂停 Windows Update (wuauserv) 服务以释放更新缓存占用");
                        }
                    }

                    try
                    {
                        for (int r = 0; r < selectedRules.Count; r++)
                        {
                            if (cancellationToken.IsCancellationRequested)
                            {
                                report.WasCancelled = true;
                                break;
                            }

                            RuleScanResult ruleResult = selectedRules[r];
                            bool preferRecycleBin = options.MoveNonSafeToRecycleBin && ruleResult.Rule.Risk != RiskLevel.Safe;

                            long ruleFreed = 0;
                            long ruleRecycledBytes = 0;
                            int ruleDeleted = 0;
                            int ruleRecycled = 0;
                            int ruleSkipped = 0;

                            // 包缓存按整包处理：同一包目录下的文件要么一起删除，要么一起保留。
                            var unitMembers = new Dictionary<string, List<ScannedFileItem>>(StringComparer.OrdinalIgnoreCase);
                            for (int u = 0; u < ruleResult.Items.Count; u++)
                            {
                                ScannedFileItem candidate = ruleResult.Items[u];
                                if (candidate.IsAdvisory || string.IsNullOrEmpty(candidate.UnitRoot)) continue;
                                List<ScannedFileItem> bucket;
                                if (!unitMembers.TryGetValue(candidate.UnitRoot, out bucket))
                                {
                                    bucket = new List<ScannedFileItem>();
                                    unitMembers.Add(candidate.UnitRoot, bucket);
                                }
                                bucket.Add(candidate);
                            }
                            var handledUnits = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                            for (int idx = 0; idx < ruleResult.Items.Count; idx++)
                            {
                                if (cancellationToken.IsCancellationRequested)
                                {
                                    report.WasCancelled = true;
                                    break;
                                }

                                ScannedFileItem item = ruleResult.Items[idx];
                                if (item.IsAdvisory) continue;

                                if (!string.IsNullOrEmpty(item.UnitRoot))
                                {
                                    if (!handledUnits.Add(item.UnitRoot)) continue;

                                    List<ScannedFileItem> members = unitMembers[item.UnitRoot];
                                    processed += members.Count;
                                    ReportCleanProgress(progress, processed, totalActionable, ruleResult.Rule.Name, item.UnitRoot, report);

                                    UnitCleanResult unit = ProcessUnit(item.UnitRoot, members, options.IsDryRun, preferRecycleBin, log);
                                    ruleFreed += unit.FreedBytes;
                                    ruleRecycledBytes += unit.RecycledBytes;
                                    ruleDeleted += unit.DeletedFiles;
                                    ruleRecycled += unit.RecycledFiles;
                                    ruleSkipped += unit.SkippedFiles;
                                    report.FreedBytes += unit.FreedBytes;
                                    report.RecycledBytes += unit.RecycledBytes;
                                    report.DeletedFiles += unit.DeletedFiles;
                                    report.RecycledFiles += unit.RecycledFiles;
                                    report.SkippedFiles += unit.SkippedFiles;
                                    report.ProtectedSkippedFiles += unit.ProtectedSkippedFiles;
                                    report.LockedOrDeniedFiles += unit.LockedFiles;
                                    continue;
                                }

                                processed++;
                                if (processed == 1 || processed % 15 == 0 || processed == totalActionable)
                                {
                                    ReportCleanProgress(progress, processed, totalActionable, ruleResult.Rule.Name, item.FullPath, report);
                                }

                                if (item.IsRecycleBinEntry)
                                {
                                    if (options.IsDryRun)
                                    {
                                        ruleFreed += item.SizeBytes;
                                        ruleDeleted += Math.Max(1, ruleResult.FileCount);
                                        report.FreedBytes += item.SizeBytes;
                                        report.DeletedFiles += Math.Max(1, ruleResult.FileCount);
                                        if (log != null) log.WriteRecord(string.Format("[演练-清空回收站] {0} ({1})", item.DisplayName, FormatHelper.FormatBytes(item.SizeBytes)));
                                    }
                                    else
                                    {
                                        try
                                        {
                                            int hr = SHEmptyRecycleBinW(IntPtr.Zero, @"C:\", SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND);
                                            if (hr == 0 || hr == unchecked((int)0x8000FFFF))
                                            {
                                                ruleFreed += item.SizeBytes;
                                                ruleDeleted += Math.Max(1, ruleResult.FileCount);
                                                report.FreedBytes += item.SizeBytes;
                                                report.DeletedFiles += Math.Max(1, ruleResult.FileCount);
                                                if (log != null) log.WriteRecord(string.Format("[已清空回收站] {0} ({1})", item.DisplayName, FormatHelper.FormatBytes(item.SizeBytes)));
                                            }
                                            else
                                            {
                                                ruleSkipped++;
                                                report.SkippedFiles++;
                                                report.LockedOrDeniedFiles++;
                                                if (log != null) log.WriteRecord(string.Format("[跳过-回收站异常 0x{0:X}] {1}", hr, item.DisplayName));
                                            }
                                        }
                                        catch (Exception ex)
                                        {
                                            ruleSkipped++;
                                            report.SkippedFiles++;
                                            report.LockedOrDeniedFiles++;
                                            if (log != null) log.WriteRecord(string.Format("[跳过-回收站失败] {0}: {1}", item.DisplayName, ex.Message));
                                        }
                                    }
                                    continue;
                                }

                                // Re-verify SafetyGuard RIGHT BEFORE deletion
                                string protectReason;
                                if (_guard.IsProtected(item.FullPath, out protectReason))
                                {
                                    ruleSkipped++;
                                    report.SkippedFiles++;
                                    report.ProtectedSkippedFiles++;
                                    if (log != null) log.WriteRecord(string.Format("[安全拦截] {0} -> {1}", item.FullPath, protectReason));
                                    continue;
                                }

                                if (NativeFileScanner.IsReparsePointFast(item.FullPath))
                                {
                                    ruleSkipped++;
                                    report.SkippedFiles++;
                                    report.ProtectedSkippedFiles++;
                                    if (log != null) log.WriteRecord(string.Format("[安全拦截-软链接] {0}", item.FullPath));
                                    continue;
                                }

                                if (options.IsDryRun)
                                {
                                    if (preferRecycleBin)
                                    {
                                        // 移入回收站不释放 C 盘空间（回收站也在 C 盘），单独统计。
                                        ruleRecycledBytes += item.SizeBytes;
                                        ruleRecycled++;
                                        report.RecycledBytes += item.SizeBytes;
                                        report.RecycledFiles++;
                                        if (log != null) log.WriteRecord(string.Format("[演练-移入回收站] {0} ({1})", item.FullPath, FormatHelper.FormatBytes(item.SizeBytes)));
                                    }
                                    else
                                    {
                                        ruleFreed += item.SizeBytes;
                                        ruleDeleted++;
                                        report.FreedBytes += item.SizeBytes;
                                        report.DeletedFiles++;
                                        if (log != null) log.WriteRecord(string.Format("[演练-删除] {0} ({1})", item.FullPath, FormatHelper.FormatBytes(item.SizeBytes)));
                                    }
                                }
                                else
                                {
                                    string errMsg = null;
                                    bool recycled = false;

                                    // 「最近 N 分钟内修改的文件不清理」按删除这一刻重新计算，而不是沿用扫描时的结果：
                                    // 扫描完成后窗口可能放了很久，期间被重新写入的文件已经是活动文件了。
                                    DateTime modifiedNotAfterUtc = item.MinAgeMinutes > 0
                                        ? DateTime.UtcNow.AddMinutes(-item.MinAgeMinutes)
                                        : DateTime.MaxValue;

                                    if (preferRecycleBin)
                                    {
                                        // 回收站移动由 Shell 按路径执行，无法走句柄删除：先用句柄校验真实路径以缩小竞态窗口。
                                        // 该选项只作用于非「安全推荐」规则，这些目录都在当前用户自己的配置目录内，
                                        // 其他低权限账户无法在其中布置目录联接。
                                        SafeOpOutcome verify = NativeFileScanner.VerifyPath(item.FullPath, false, _guard, modifiedNotAfterUtc, out errMsg);
                                        if (verify == SafeOpOutcome.AlreadyGone) continue;
                                        if (verify == SafeOpOutcome.TooRecent)
                                        {
                                            ruleSkipped++;
                                            report.SkippedFiles++;
                                            report.ProtectedSkippedFiles++;
                                            if (log != null) log.WriteRecord(string.Format("[跳过-近期修改] {0} ({1})", item.FullPath, errMsg));
                                            continue;
                                        }
                                        if (verify == SafeOpOutcome.Redirected || verify == SafeOpOutcome.Protected)
                                        {
                                            ruleSkipped++;
                                            report.SkippedFiles++;
                                            report.ProtectedSkippedFiles++;
                                            if (log != null) log.WriteRecord(string.Format("[安全拦截-路径校验] {0} -> {1}", item.FullPath, errMsg));
                                            continue;
                                        }
                                        recycled = verify == SafeOpOutcome.Done && NativeFileScanner.TryMoveToRecycleBin(item.FullPath, out errMsg);
                                    }

                                    if (recycled)
                                    {
                                        ruleRecycledBytes += item.SizeBytes;
                                        ruleRecycled++;
                                        report.RecycledBytes += item.SizeBytes;
                                        report.RecycledFiles++;
                                        if (log != null) log.WriteRecord(string.Format("[已移入回收站] {0} ({1})", item.FullPath, FormatHelper.FormatBytes(item.SizeBytes)));
                                    }
                                    else
                                    {
                                        SafeOpOutcome deleted = NativeFileScanner.TrySafeDelete(item.FullPath, false, _guard, modifiedNotAfterUtc, out errMsg);
                                        if (deleted == SafeOpOutcome.Done)
                                        {
                                            ruleFreed += item.SizeBytes;
                                            ruleDeleted++;
                                            report.FreedBytes += item.SizeBytes;
                                            report.DeletedFiles++;
                                            if (log != null) log.WriteRecord(string.Format("[已删除] {0} ({1})", item.FullPath, FormatHelper.FormatBytes(item.SizeBytes)));
                                        }
                                        else if (deleted == SafeOpOutcome.Redirected || deleted == SafeOpOutcome.Protected)
                                        {
                                            ruleSkipped++;
                                            report.SkippedFiles++;
                                            report.ProtectedSkippedFiles++;
                                            if (log != null) log.WriteRecord(string.Format("[安全拦截-路径校验] {0} -> {1}", item.FullPath, errMsg));
                                        }
                                        else if (deleted == SafeOpOutcome.TooRecent)
                                        {
                                            ruleSkipped++;
                                            report.SkippedFiles++;
                                            report.ProtectedSkippedFiles++;
                                            if (log != null) log.WriteRecord(string.Format("[跳过-近期修改] {0} ({1})", item.FullPath, errMsg));
                                        }
                                        else if (deleted == SafeOpOutcome.Failed)
                                        {
                                            ruleSkipped++;
                                            report.SkippedFiles++;
                                            report.LockedOrDeniedFiles++;
                                            if (log != null) log.WriteRecord(string.Format("[跳过-占用或无权限] {0} ({1})", item.FullPath, errMsg));
                                        }
                                    }
                                }
                            }

                            if (!options.IsDryRun && !report.WasCancelled)
                            {
                                for (int rootIdx = 0; rootIdx < ruleResult.ResolvedRoots.Count; rootIdx++)
                                {
                                    report.DeletedDirectories += RemoveEmptySubdirectoriesFast(ruleResult.ResolvedRoots[rootIdx]);
                                }
                            }

                            report.RuleSummaries.Add(string.Format("- {0}: 释放 {1}，删除 {2}，移入回收站 {3} 个（{4}，未释放空间），跳过 {5}",
                                ruleResult.Rule.Name, FormatHelper.FormatBytes(ruleFreed), ruleDeleted, ruleRecycled,
                                FormatHelper.FormatBytes(ruleRecycledBytes), ruleSkipped));
                        }
                    }
                    finally
                    {
                        if (stoppedWuauserv)
                        {
                            bool resumed = TryResumeService("wuauserv");
                            if (log != null)
                            {
                                log.WriteRecord(resumed
                                    ? "[服务协同] 已恢复 Windows Update (wuauserv) 服务运行"
                                    : "[服务协同] 尝试恢复 Windows Update 服务超时，系统将在后台按需拉起");
                            }
                        }
                    }

                    report.FinishedAt = DateTime.Now;
                    if (log != null)
                    {
                        log.WriteSummaryFooter(report);
                    }
                }

                if (progress != null)
                {
                    progress.Report(new CleanProgressInfo
                    {
                        ProcessedItems = Math.Max(totalActionable, 1),
                        TotalItems = Math.Max(totalActionable, 1),
                        CurrentRuleName = report.WasCancelled ? "已取消" : "清理完成",
                        CurrentFilePath = "",
                        FreedBytesSoFar = report.FreedBytes,
                        DeletedCount = report.DeletedFiles + report.RecycledFiles,
                        SkippedCount = report.SkippedFiles
                    });
                }

                return report;
            });
        }

        private static void ReportCleanProgress(
            IProgress<CleanProgressInfo> progress,
            int processed,
            int totalActionable,
            string ruleName,
            string currentPath,
            CleanExecutionReport report)
        {
            if (progress == null) return;
            progress.Report(new CleanProgressInfo
            {
                ProcessedItems = Math.Min(processed, Math.Max(totalActionable, 1)),
                TotalItems = Math.Max(totalActionable, 1),
                CurrentRuleName = ruleName,
                CurrentFilePath = currentPath,
                FreedBytesSoFar = report.FreedBytes,
                DeletedCount = report.DeletedFiles + report.RecycledFiles,
                SkippedCount = report.SkippedFiles
            });
        }

        private class UnitCleanResult
        {
            public long FreedBytes;
            public long RecycledBytes;
            public int DeletedFiles;
            public int RecycledFiles;
            public int SkippedFiles;
            public int ProtectedSkippedFiles;
            public int LockedFiles;
        }

        /// <summary>
        /// Returns the first entry inside the unit that must not be deleted (protected / whitelisted / reparse point),
        /// or null when the whole unit can go. Walks the live tree so changes since the scan are honoured.
        /// </summary>
        private string FindUnitBlocker(string unitRoot, int minAgeMinutes)
        {
            DateTime freshCutoff = minAgeMinutes > 0 ? DateTime.Now.AddMinutes(-minAgeMinutes) : DateTime.MaxValue;
            var stack = new Stack<string>();
            stack.Push(unitRoot);
            var children = new List<NativeFileEntry>(128);

            while (stack.Count > 0)
            {
                string dir = stack.Pop();
                children.Clear();
                bool denied;
                NativeFileScanner.TryEnumerateChildren(dir, "*", children, out denied);
                if (denied) return dir + "（无权限枚举）";

                for (int i = 0; i < children.Count; i++)
                {
                    NativeFileEntry entry = children[i];
                    if (entry.IsReparsePoint) return entry.FullPath + "（符号链接/目录联接）";

                    string reason;
                    if (_guard.IsProtected(entry.FullPath, out reason)) return entry.FullPath + "（" + reason + "）";

                    if (!entry.IsDirectory && entry.LastWriteTime > freshCutoff)
                    {
                        return entry.FullPath + "（最近修改过，仍在保护期内）";
                    }

                    if (entry.IsDirectory) stack.Push(entry.FullPath);
                }
            }
            return null;
        }

        /// <summary>
        /// Cleans one package directory as a single unit:
        ///   1. skips the whole unit if anything inside is protected or a link;
        ///   2. (recycle preference) moves the whole directory to the Recycle Bin in one shell call;
        ///   3. otherwise atomically renames it to a hidden tombstone sibling — this fails as a whole when any file
        ///      inside is in use, so a package is never left half-deleted — and then deletes the tombstone.
        /// Once renamed, the package manager simply sees the package as missing and re-downloads it.
        /// </summary>
        private UnitCleanResult ProcessUnit(
            string unitRoot,
            List<ScannedFileItem> members,
            bool isDryRun,
            bool preferRecycleBin,
            AuditLogSession log)
        {
            var result = new UnitCleanResult();
            long scannedBytes = 0;
            int unitMinAge = 0;
            for (int i = 0; i < members.Count; i++)
            {
                scannedBytes += members[i].SizeBytes;
                unitMinAge = Math.Max(unitMinAge, members[i].MinAgeMinutes);
            }
            int count = members.Count;

            string reason;
            if (_guard.IsProtected(unitRoot, out reason) || _guard.HasReparsePointInAncestorChain(unitRoot))
            {
                result.SkippedFiles = count;
                result.ProtectedSkippedFiles = count;
                if (log != null) log.WriteRecord(string.Format("[安全拦截-整包] {0} -> {1}", unitRoot, reason ?? "祖先目录含符号链接/目录联接"));
                return result;
            }

            if (!Directory.Exists(unitRoot))
            {
                return result;
            }

            string blocker = FindUnitBlocker(unitRoot, unitMinAge);
            if (blocker != null)
            {
                result.SkippedFiles = count;
                result.ProtectedSkippedFiles = count;
                if (log != null) log.WriteRecord(string.Format("[安全拦截-整包] {0}：包内含受保护项 {1}，整包保留以免只删一半", unitRoot, blocker));
                return result;
            }

            if (isDryRun)
            {
                if (preferRecycleBin)
                {
                    result.RecycledFiles = count;
                    result.RecycledBytes = scannedBytes;
                    if (log != null) log.WriteRecord(string.Format("[演练-整包移入回收站] {0} ({1} 个文件, {2})", unitRoot, count, FormatHelper.FormatBytes(scannedBytes)));
                }
                else
                {
                    result.DeletedFiles = count;
                    result.FreedBytes = scannedBytes;
                    if (log != null) log.WriteRecord(string.Format("[演练-整包删除] {0} ({1} 个文件, {2})", unitRoot, count, FormatHelper.FormatBytes(scannedBytes)));
                }
                return result;
            }

            string detail;
            if (preferRecycleBin)
            {
                // Same-volume Recycle Bin moves are a single directory rename: the whole package moves, or nothing does.
                SafeOpOutcome verify = NativeFileScanner.VerifyPath(unitRoot, true, _guard, out detail);
                if (verify == SafeOpOutcome.AlreadyGone) return result;
                if (verify == SafeOpOutcome.Done && NativeFileScanner.TryMoveToRecycleBin(unitRoot, out detail))
                {
                    result.RecycledFiles = count;
                    result.RecycledBytes = scannedBytes;
                    if (log != null) log.WriteRecord(string.Format("[已整包移入回收站] {0} ({1} 个文件, {2})", unitRoot, count, FormatHelper.FormatBytes(scannedBytes)));
                    return result;
                }
                if (verify == SafeOpOutcome.Redirected || verify == SafeOpOutcome.Protected)
                {
                    result.SkippedFiles = count;
                    result.ProtectedSkippedFiles = count;
                    if (log != null) log.WriteRecord(string.Format("[安全拦截-路径校验] {0} -> {1}", unitRoot, detail));
                    return result;
                }
                if (log != null) log.WriteRecord(string.Format("[回收站不可用，改为整包删除] {0} ({1})", unitRoot, detail));
            }

            string leafName = Path.GetFileName(unitRoot);
            string tombstoneLeaf = "." + leafName + ".sccdel-" + Guid.NewGuid().ToString("N").Substring(0, 8);
            string tombstone;
            SafeOpOutcome renamed = NativeFileScanner.TryRenameDirectorySafe(unitRoot, tombstoneLeaf, _guard, out tombstone, out detail);

            if (renamed == SafeOpOutcome.AlreadyGone) return result;
            if (renamed != SafeOpOutcome.Done)
            {
                result.SkippedFiles = count;
                if (renamed == SafeOpOutcome.Failed)
                {
                    result.LockedFiles = count;
                    if (log != null) log.WriteRecord(string.Format("[跳过-整包占用] {0}：{1}，整包保留以免只删一半", unitRoot, detail));
                }
                else
                {
                    result.ProtectedSkippedFiles = count;
                    if (log != null) log.WriteRecord(string.Format("[安全拦截-整包] {0} -> {1}", unitRoot, detail));
                }
                return result;
            }

            var stats = new TreeDeleteStats();
            NativeFileScanner.DeleteTreeSafe(tombstone, _guard, stats);
            result.DeletedFiles = stats.DeletedFiles;
            result.FreedBytes = stats.DeletedBytes;
            if (log != null) log.WriteRecord(string.Format("[已整包删除] {0} ({1} 个文件, {2})", unitRoot, stats.DeletedFiles, FormatHelper.FormatBytes(stats.DeletedBytes)));

            if (stats.Failures > 0 && log != null)
            {
                log.WriteRecord(string.Format("[整包残留] {0}：{1} 项未能删除（包已整体移出原位置，包管理器会按需重新下载）", tombstone, stats.Failures));
                for (int i = 0; i < stats.Notes.Count; i++)
                {
                    log.WriteRecord("    - " + stats.Notes[i]);
                }
            }

            return result;
        }

        private static bool TryTemporarilyStopService(string serviceName)
        {
            try
            {
                using (var sc = new ServiceController(serviceName))
                {
                    if (sc.Status == ServiceControllerStatus.Running && sc.CanStop)
                    {
                        sc.Stop();
                        sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(8));
                        return sc.Status == ServiceControllerStatus.Stopped;
                    }
                }
            }
            catch
            {
            }
            return false;
        }

        private static bool TryResumeService(string serviceName)
        {
            try
            {
                using (var sc = new ServiceController(serviceName))
                {
                    if (sc.Status == ServiceControllerStatus.Stopped)
                    {
                        sc.Start();
                        sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(8));
                        return sc.Status == ServiceControllerStatus.Running;
                    }
                }
            }
            catch
            {
            }
            return false;
        }

        private int RemoveEmptySubdirectoriesFast(string rootDir)
        {
            int deleted = 0;
            if (NativeFileScanner.IsReparsePointFast(rootDir)) return 0;

            var children = new List<NativeFileEntry>();
            bool denied;
            if (!NativeFileScanner.TryEnumerateChildren(rootDir, "*", children, out denied)) return 0;

            for (int i = 0; i < children.Count; i++)
            {
                NativeFileEntry entry = children[i];
                if (!entry.IsDirectory || entry.IsReparsePoint) continue;

                string reason;
                if (_guard.IsProtected(entry.FullPath, out reason)) continue;

                deleted += RemoveEmptySubdirectoriesFast(entry.FullPath);

                // Handle-validated delete (only succeeds if truly empty; refuses redirected paths,
                // since even an arbitrary EMPTY-folder delete as admin is an escalation primitive).
                string detail;
                if (NativeFileScanner.TrySafeDelete(entry.FullPath, true, _guard, out detail) == SafeOpOutcome.Done)
                {
                    deleted++;
                }
            }

            return deleted;
        }
    }
}
