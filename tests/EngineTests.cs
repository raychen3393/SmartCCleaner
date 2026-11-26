using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;

namespace SmartCCleaner.Tests
{
    public static class EngineTests
    {
        private static int _passed = 0;
        private static int _failed = 0;

        public static int Main(string[] args)
        {
            Console.WriteLine("=== SmartCCleaner v2.0 Core Engine, SafetyGuard & Uninstaller Self-Tests ===");

            string sandboxRoot = Path.Combine(
                Path.GetTempPath(),
                "SmartCCleaner_Test_" + Guid.NewGuid().ToString("N"));
            string appDataDir = Path.Combine(sandboxRoot, "AppData");
            string junkDir = Path.Combine(sandboxRoot, "JunkTarget");

            Directory.CreateDirectory(appDataDir);
            Directory.CreateDirectory(junkDir);

            try
            {
                var guard = new SafetyGuard(appDataDir);
                var engine = new CleanerEngine(guard);
                string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

                // 1. Built-in hardcoded protection tests
                TestProtected(guard, @"C:\Windows\System32\kernel32.dll", true, "System32 must be protected");
                TestProtected(guard, @"C:\Windows\WinSxS\test.dll", true, "WinSxS must be protected");
                TestProtected(guard, @"C:\Program Files\App\app.exe", true, "Program Files must be protected");
                TestProtected(guard, @"C:\", true, "C drive root must be protected");
                TestProtected(guard, @"D:\SomeTemp\a.tmp", true, "Non-C drive path must be protected");
                TestProtected(guard, Path.Combine(userProfile, @"Desktop\report.docx"), true, "User Desktop must be protected");
                TestProtected(guard, Path.Combine(userProfile, @"Documents\contract.pdf"), true, "User Documents general files must be protected");
                TestProtected(guard, Path.Combine(userProfile, @"Documents\WeChat Files\wxid_123\Msg\MSG0.db"), true, "WeChat chat DB must be protected");
                TestProtected(guard, Path.Combine(userProfile, @"Documents\WeChat Files\wxid_123\FileStorage\Cache\thumb.dat"), false, "WeChat explicit Cache subfolder should be cleanable");
                TestProtected(guard, Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Google\Chrome\User Data\Default\Bookmarks"), true, "Browser Bookmarks must be protected");
                TestProtected(guard, Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Google\Chrome\User Data\Default\Login Data"), true, "Browser Login Data must be protected");

                // 2. User Whitelist tests (precompiled regex & path prefix)
                string protectedSub = Path.Combine(junkDir, "KeepFolder");
                string protectedFile = Path.Combine(protectedSub, "notes.txt");
                string wildcardFile = Path.Combine(junkDir, "important.keepme");
                string normalJunk1 = Path.Combine(junkDir, "old_cache.tmp");
                string normalJunk2 = Path.Combine(junkDir, "sub", "stale.log");
                string freshFile = Path.Combine(junkDir, "brand_new.tmp");

                Directory.CreateDirectory(protectedSub);
                Directory.CreateDirectory(Path.Combine(junkDir, "sub"));

                File.WriteAllText(protectedFile, "do not delete me");
                File.WriteAllText(wildcardFile, "keep by wildcard");
                File.WriteAllText(normalJunk1, new string('A', 2048));
                File.WriteAllText(normalJunk2, new string('B', 4096));
                File.WriteAllText(freshFile, new string('C', 1024));

                DateTime oldTime = DateTime.Now.AddMinutes(-20);
                File.SetLastWriteTime(normalJunk1, oldTime);
                File.SetLastWriteTime(normalJunk2, oldTime);
                File.SetLastWriteTime(protectedFile, oldTime);
                File.SetLastWriteTime(wildcardFile, oldTime);

                guard.AddWhitelistEntry(protectedSub, "Test folder whitelist");
                guard.AddWhitelistEntry("*.keepme", "Test wildcard whitelist");

                TestProtected(guard, protectedFile, true, "Whitelisted folder child must be protected");
                TestProtected(guard, wildcardFile, true, "Whitelisted wildcard file must be protected");
                TestProtected(guard, normalJunk1, false, "Normal junk file should NOT be protected");

                // 3. Settings persistence test
                var settings = new AppSettings { DryRunMode = true, OnlyShowDetected = false, MoveNonSafeToRecycleBin = false, WindowWidth = 1280, WindowHeight = 800 };
                guard.SaveSettings(settings);
                AppSettings reloaded = guard.LoadSettings();
                Assert(reloaded.DryRunMode == true && reloaded.OnlyShowDetected == false && reloaded.WindowWidth == 1280, "AppSettings should persist and reload accurately");

                // 4. Native Win32 fast scan accuracy test
                var testRule = new CleanRule
                {
                    Id = "test_rule",
                    Name = "Test Junk Rule",
                    Category = CleanCategory.SystemJunk,
                    Risk = RiskLevel.Safe,
                    DefaultSelected = true,
                    Targets = new List<CleanTargetSpec>
                    {
                        new CleanTargetSpec { PathPattern = junkDir, Recursive = true, MinAgeMinutes = 5 }
                    }
                };

                RuleScanResult scanResult = engine.ScanSingleRule(testRule, CancellationToken.None);
                Assert(scanResult.FileCount == 2, string.Format("Expected 2 cleanable files (old junk only), got {0}", scanResult.FileCount));
                Assert(scanResult.TotalBytes == 6144, string.Format("Expected 6144 bytes, got {0}", scanResult.TotalBytes));
                Assert(scanResult.SkippedProtectedCount >= 2, string.Format("Expected >=2 protected skipped items, got {0}", scanResult.SkippedProtectedCount));

                // 5. Dry-Run cleanup test (must delete ZERO files, generate streaming audit log)
                CleanExecutionReport dryReport = engine.CleanAsync(
                    new List<RuleScanResult> { scanResult },
                    new CleanOptions { IsDryRun = true },
                    null,
                    CancellationToken.None).Result;

                Assert(dryReport.IsDryRun, "Dry report IsDryRun should be true");
                Assert(dryReport.FreedBytes == 6144, "Dry report should report 6144 estimated bytes");
                Assert(File.Exists(normalJunk1) && File.Exists(normalJunk2), "Dry run MUST NOT delete any actual files");
                Assert(!string.IsNullOrEmpty(dryReport.LogFilePath) && File.Exists(dryReport.LogFilePath), "Dry run must generate streaming audit log file");

                // 6. Real cleanup test (must delete old junk, keep whitelisted & fresh files, remove empty subdirs)
                CleanExecutionReport realReport = engine.CleanAsync(
                    new List<RuleScanResult> { scanResult },
                    new CleanOptions { IsDryRun = false, MoveNonSafeToRecycleBin = false },
                    null,
                    CancellationToken.None).Result;

                Assert(!realReport.IsDryRun, "Real report IsDryRun should be false");
                Assert(realReport.DeletedFiles == 2, string.Format("Expected 2 deleted files, got {0}", realReport.DeletedFiles));
                Assert(realReport.FreedBytes == 6144, string.Format("Expected 6144 freed bytes, got {0}", realReport.FreedBytes));
                Assert(!File.Exists(normalJunk1) && !File.Exists(normalJunk2), "Junk files should be deleted");
                Assert(!Directory.Exists(Path.Combine(junkDir, "sub")), "Empty subdirectory should be cleaned");
                Assert(File.Exists(protectedFile), "Whitelisted folder file MUST survive real clean");
                Assert(File.Exists(wildcardFile), "Whitelisted wildcard file MUST survive real clean");
                Assert(File.Exists(freshFile), "Fresh (<5 min) file MUST survive real clean");
                Assert(!string.IsNullOrEmpty(realReport.LogFilePath) && File.Exists(realReport.LogFilePath), "Real clean must generate streaming audit log");

                // 7. Parallel ScanAsync test on custom ruleset
                var parallelResults = engine.ScanAsync(new List<CleanRule> { testRule }, null, CancellationToken.None).Result;
                Assert(parallelResults.Count == 1 && parallelResults[0].FileCount == 0, "Parallel ScanAsync should run cleanly and find 0 remaining old junk files");

                // 8. Default ruleset verification
                List<CleanRule> defaultRules = RulesEngine.BuildDefaultRules();
                Assert(defaultRules.Count >= 18, "Default ruleset should contain >= 18 rules");
                Assert(defaultRules.Any(r => r.Category == CleanCategory.SystemJunk), "Has SystemJunk rules");
                Assert(defaultRules.Any(r => r.Category == CleanCategory.BrowserCache), "Has BrowserCache rules");
                Assert(defaultRules.Any(r => r.Category == CleanCategory.CommonApps), "Has CommonApps rules");
                Assert(defaultRules.Any(r => r.Category == CleanCategory.DevTools), "Has DevTools rules");
                Assert(defaultRules.Where(r => r.Category == CleanCategory.BrowserCache).All(r => !r.DefaultSelected), "BrowserCache rules must NOT be default-selected");
                Assert(defaultRules.Where(r => r.Category == CleanCategory.DevTools).All(r => !r.DefaultSelected), "DevTools rules must NOT be default-selected");
                Assert(defaultRules.Where(r => r.Category == CleanCategory.CommonApps).All(r => !r.DefaultSelected), "CommonApps rules must NOT be default-selected");
                Assert(defaultRules.Any(r => r.AssociatedProcesses != null && r.AssociatedProcesses.Length > 0), "Rules include AssociatedProcesses for running-app detection");

                // 9. Uninstaller safety guardrails test
                Assert(!UninstallCore.IsSafeRemovableAppFolder(@"C:\"), "Uninstaller must NEVER allow removing C:\\");
                Assert(!UninstallCore.IsSafeRemovableAppFolder(@"D:\"), "Uninstaller must NEVER allow removing D:\\");
                Assert(!UninstallCore.IsSafeRemovableAppFolder(Path.Combine(userProfile, "Desktop")), "Uninstaller must NEVER allow removing Desktop");
                Assert(!UninstallCore.IsSafeRemovableAppFolder(@"D:\MyRandomFolder"), "Uninstaller must NEVER allow removing arbitrary folders");
                Assert(UninstallCore.IsSafeRemovableAppFolder(@"D:\SmartCCleaner"), "Uninstaller allows SmartCCleaner folder");
                Assert(UninstallCore.IsSafeRemovableAppFolder(@"D:\SmartCCleaner\dist"), "Uninstaller allows dist folder");

                Console.WriteLine(string.Format("\nRESULT: {0} passed, {1} failed.", _passed, _failed));
                return _failed == 0 ? 0 : 1;
            }
            finally
            {
                try
                {
                    if (Directory.Exists(sandboxRoot))
                    {
                        Directory.Delete(sandboxRoot, true);
                    }
                }
                catch
                {
                }
            }
        }

        private static void TestProtected(SafetyGuard guard, string path, bool expectedProtected, string message)
        {
            string reason;
            bool actual = guard.IsProtected(path, out reason);
            Assert(actual == expectedProtected, string.Format("{0} (path={1}, actual={2}, reason={3})", message, path, actual, reason));
        }

        private static void Assert(bool condition, string message)
        {
            if (condition)
            {
                _passed++;
                Console.WriteLine("[PASS] " + message);
            }
            else
            {
                _failed++;
                Console.WriteLine("[FAIL] " + message);
            }
        }
    }
}
