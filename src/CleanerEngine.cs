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

                    ScanDirectoryFast(dir, spec.SearchPattern, spec.Recursive, cutoff, seenFiles, result, cancellationToken);
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
                            int ruleDeleted = 0;
                            int ruleRecycled = 0;
                            int ruleSkipped = 0;

                            for (int idx = 0; idx < ruleResult.Items.Count; idx++)
                            {
                                if (cancellationToken.IsCancellationRequested)
                                {
                                    report.WasCancelled = true;
                                    break;
                                }

                                ScannedFileItem item = ruleResult.Items[idx];
                                if (item.IsAdvisory) continue;

                                processed++;
                                if (progress != null && (processed == 1 || processed % 15 == 0 || processed == totalActionable))
                                {
                                    progress.Report(new CleanProgressInfo
                                    {
                                        ProcessedItems = processed,
                                        TotalItems = Math.Max(totalActionable, 1),
                                        CurrentRuleName = ruleResult.Rule.Name,
                                        CurrentFilePath = item.FullPath,
                                        FreedBytesSoFar = report.FreedBytes,
                                        DeletedCount = report.DeletedFiles + report.RecycledFiles,
                                        SkippedCount = report.SkippedFiles
                                    });
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
                                    ruleFreed += item.SizeBytes;
                                    if (preferRecycleBin)
                                    {
                                        ruleRecycled++;
                                        report.RecycledFiles++;
                                        if (log != null) log.WriteRecord(string.Format("[演练-移入回收站] {0} ({1})", item.FullPath, FormatHelper.FormatBytes(item.SizeBytes)));
                                    }
                                    else
                                    {
                                        ruleDeleted++;
                                        report.DeletedFiles++;
                                        if (log != null) log.WriteRecord(string.Format("[演练-删除] {0} ({1})", item.FullPath, FormatHelper.FormatBytes(item.SizeBytes)));
                                    }
                                    report.FreedBytes += item.SizeBytes;
                                }
                                else
                                {
                                    if (!NativeFileScanner.FileExistsFast(item.FullPath)) continue;

                                    string errMsg;
                                    if (preferRecycleBin && NativeFileScanner.TryMoveToRecycleBin(item.FullPath, out errMsg))
                                    {
                                        ruleFreed += item.SizeBytes;
                                        ruleRecycled++;
                                        report.FreedBytes += item.SizeBytes;
                                        report.RecycledFiles++;
                                        if (log != null) log.WriteRecord(string.Format("[已移入回收站] {0} ({1})", item.FullPath, FormatHelper.FormatBytes(item.SizeBytes)));
                                    }
                                    else if (NativeFileScanner.TryDeleteFileLongPath(item.FullPath, out errMsg))
                                    {
                                        ruleFreed += item.SizeBytes;
                                        ruleDeleted++;
                                        report.FreedBytes += item.SizeBytes;
                                        report.DeletedFiles++;
                                        if (log != null) log.WriteRecord(string.Format("[已删除] {0} ({1})", item.FullPath, FormatHelper.FormatBytes(item.SizeBytes)));
                                    }
                                    else
                                    {
                                        ruleSkipped++;
                                        report.SkippedFiles++;
                                        report.LockedOrDeniedFiles++;
                                        if (log != null) log.WriteRecord(string.Format("[跳过-占用或无权限] {0} ({1})", item.FullPath, errMsg));
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

                            report.RuleSummaries.Add(string.Format("- {0}: 释放 {1}，删除 {2}，回收站 {3}，跳过 {4}",
                                ruleResult.Rule.Name, FormatHelper.FormatBytes(ruleFreed), ruleDeleted, ruleRecycled, ruleSkipped));
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

                // Attempt Win32 RemoveDirectoryW (only succeeds if truly empty)
                if (NativeFileScanner.TryRemoveEmptyDirectoryLongPath(entry.FullPath))
                {
                    deleted++;
                }
            }

            return deleted;
        }
    }
}
