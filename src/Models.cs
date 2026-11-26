using System;
using System.Collections.Generic;
using System.Runtime.Serialization;

namespace SmartCCleaner
{
    public enum CleanCategory
    {
        SystemJunk,
        BrowserCache,
        CommonApps,
        DevTools
    }

    public enum RiskLevel
    {
        Safe,
        Medium,
        Caution
    }

    public enum TargetKind
    {
        DirectoryContents,
        FilePattern,
        RecycleBin,
        AdvisoryOnly
    }

    public class CleanTargetSpec
    {
        public string PathPattern { get; set; }
        public string SearchPattern { get; set; }
        public bool Recursive { get; set; }
        public TargetKind Kind { get; set; }
        public int MinAgeMinutes { get; set; }

        public CleanTargetSpec()
        {
            SearchPattern = "*";
            Recursive = true;
            Kind = TargetKind.DirectoryContents;
            MinAgeMinutes = 0;
        }
    }

    public class CleanRule
    {
        public string Id { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }
        public string SafetyNote { get; set; }
        public CleanCategory Category { get; set; }
        public RiskLevel Risk { get; set; }
        public bool DefaultSelected { get; set; }
        public bool RequiresAdmin { get; set; }
        public string[] AssociatedProcesses { get; set; }
        public List<CleanTargetSpec> Targets { get; set; }

        public CleanRule()
        {
            Targets = new List<CleanTargetSpec>();
            AssociatedProcesses = new string[0];
        }
    }

    public class ScannedFileItem
    {
        public string FullPath { get; set; }
        public string DisplayName { get; set; }
        public long SizeBytes { get; set; }
        public DateTime LastWriteTime { get; set; }
        public bool IsRecycleBinEntry { get; set; }
        public bool IsAdvisory { get; set; }
        public string AdvisoryText { get; set; }
    }

    public class RuleScanResult
    {
        public CleanRule Rule { get; set; }
        public bool IsSelected { get; set; }
        public bool IsDetected { get; set; }
        public bool NeedsElevationForFullAccess { get; set; }
        public long TotalBytes { get; set; }
        public int FileCount { get; set; }
        public int SkippedProtectedCount { get; set; }
        public int AccessDeniedCount { get; set; }
        public List<ScannedFileItem> Items { get; set; }
        public List<string> ResolvedRoots { get; set; }
        public List<string> RunningProcesses { get; set; }
        public string StatusHint { get; set; }

        public RuleScanResult()
        {
            Items = new List<ScannedFileItem>();
            ResolvedRoots = new List<string>();
            RunningProcesses = new List<string>();
        }
    }

    public class ScanProgressInfo
    {
        public int CompletedRules { get; set; }
        public int TotalRules { get; set; }
        public string CurrentRuleName { get; set; }
        public string CurrentPath { get; set; }
        public long FoundBytesSoFar { get; set; }
        public int FoundFilesSoFar { get; set; }
    }

    public class CleanProgressInfo
    {
        public int ProcessedItems { get; set; }
        public int TotalItems { get; set; }
        public string CurrentRuleName { get; set; }
        public string CurrentFilePath { get; set; }
        public long FreedBytesSoFar { get; set; }
        public int DeletedCount { get; set; }
        public int SkippedCount { get; set; }
    }

    public class CleanOptions
    {
        public bool IsDryRun { get; set; }
        public bool MoveNonSafeToRecycleBin { get; set; }
        public bool CoordinateWindowsUpdateService { get; set; }

        public CleanOptions()
        {
            CoordinateWindowsUpdateService = true;
        }
    }

    public class CleanExecutionReport
    {
        public DateTime StartedAt { get; set; }
        public DateTime FinishedAt { get; set; }
        public bool IsDryRun { get; set; }
        public long FreedBytes { get; set; }
        public int DeletedFiles { get; set; }
        public int RecycledFiles { get; set; }
        public int DeletedDirectories { get; set; }
        public int SkippedFiles { get; set; }
        public int ProtectedSkippedFiles { get; set; }
        public int LockedOrDeniedFiles { get; set; }
        public bool WasCancelled { get; set; }
        public string LogFilePath { get; set; }
        public List<string> RuleSummaries { get; set; }

        public CleanExecutionReport()
        {
            RuleSummaries = new List<string>();
        }
    }

    [DataContract]
    public class WhitelistEntry
    {
        [DataMember]
        public string Pattern { get; set; }

        [DataMember]
        public string Note { get; set; }

        [DataMember]
        public string AddedAt { get; set; }
    }

    [DataContract]
    public class WhitelistConfig
    {
        [DataMember]
        public List<WhitelistEntry> Entries { get; set; }

        public WhitelistConfig()
        {
            Entries = new List<WhitelistEntry>();
        }
    }

    [DataContract]
    public class AppSettings
    {
        [DataMember]
        public bool DryRunMode { get; set; }

        [DataMember]
        public bool OnlyShowDetected { get; set; }

        [DataMember]
        public bool MoveNonSafeToRecycleBin { get; set; }

        [DataMember]
        public double WindowWidth { get; set; }

        [DataMember]
        public double WindowHeight { get; set; }

        public AppSettings()
        {
            DryRunMode = false;
            OnlyShowDetected = true;
            MoveNonSafeToRecycleBin = true;
            WindowWidth = 1140;
            WindowHeight = 760;
        }
    }

    public class DriveUsageInfo
    {
        public string DriveLetter { get; set; }
        public long TotalBytes { get; set; }
        public long FreeBytes { get; set; }
        public long UsedBytes { get { return TotalBytes - FreeBytes; } }
        public double UsedPercent
        {
            get
            {
                if (TotalBytes <= 0) return 0;
                return (double)UsedBytes * 100.0 / (double)TotalBytes;
            }
        }
    }

    public static class FormatHelper
    {
        public static string FormatBytes(long bytes)
        {
            if (bytes < 0) bytes = 0;
            string[] units = { "B", "KB", "MB", "GB", "TB" };
            double value = bytes;
            int idx = 0;
            while (value >= 1024.0 && idx < units.Length - 1)
            {
                value /= 1024.0;
                idx++;
            }
            if (idx == 0)
            {
                return string.Format("{0} B", bytes);
            }
            if (value >= 100)
            {
                return string.Format("{0:F1} {1}", value, units[idx]);
            }
            return string.Format("{0:F2} {1}", value, units[idx]);
        }

        public static string CategoryName(CleanCategory category)
        {
            switch (category)
            {
                case CleanCategory.SystemJunk: return "系统垃圾";
                case CleanCategory.BrowserCache: return "浏览器缓存";
                case CleanCategory.CommonApps: return "常用软件缓存";
                case CleanCategory.DevTools: return "开发工具缓存";
                default: return "其他";
            }
        }

        public static string RiskName(RiskLevel risk)
        {
            switch (risk)
            {
                case RiskLevel.Safe: return "安全推荐";
                case RiskLevel.Medium: return "按需勾选";
                case RiskLevel.Caution: return "谨慎检查";
                default: return "未知";
            }
        }
    }
}
