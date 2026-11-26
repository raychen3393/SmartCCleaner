using System;
using System.Collections.Generic;
using System.Diagnostics;
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

                RunAtomicUnitTests(guard, engine, sandboxRoot);
                RunRecycleAccountingTests(engine, sandboxRoot);
                RunJunctionSwapTests(guard, engine, sandboxRoot);
                RunAgeRecheckTests(engine, sandboxRoot);
                RunSingleInstanceGateTests();

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

        // 10. Package caches are deleted as whole units: never half-deleted
        private static void RunAtomicUnitTests(SafetyGuard guard, CleanerEngine engine, string sandboxRoot)
        {
            string pkgRoot = Path.Combine(sandboxRoot, "FakeNuget");
            string fooVer = Path.Combine(pkgRoot, "foo", "1.0.0");
            string barVer = Path.Combine(pkgRoot, "bar", "2.0.0");
            string bazVer = Path.Combine(pkgRoot, "baz", "3.0.0");
            Directory.CreateDirectory(Path.Combine(fooVer, "lib"));
            Directory.CreateDirectory(barVer);
            Directory.CreateDirectory(bazVer);

            string fooDll = Path.Combine(fooVer, "lib", "foo.dll");
            string fooMarker = Path.Combine(fooVer, "foo.1.0.0.nupkg.metadata");
            string barDll = Path.Combine(barVer, "bar.dll");
            string bazDll = Path.Combine(bazVer, "baz.dll");
            string bazKeep = Path.Combine(bazVer, "keep.lock");
            File.WriteAllText(fooDll, new string('D', 8192));
            File.WriteAllText(fooMarker, "{}");
            File.WriteAllText(barDll, new string('E', 1000));
            File.WriteAllText(bazDll, new string('F', 500));
            File.WriteAllText(bazKeep, "whitelisted");
            File.SetAttributes(barDll, FileAttributes.ReadOnly);
            guard.AddWhitelistEntry(bazKeep, "Test whitelist inside a package unit");

            var unitRule = new CleanRule
            {
                Id = "test_unit_rule",
                Name = "Test Package Unit Rule",
                Category = CleanCategory.DevTools,
                Risk = RiskLevel.Medium,
                DefaultSelected = true,
                Targets = new List<CleanTargetSpec>
                {
                    new CleanTargetSpec { PathPattern = pkgRoot, Recursive = true, AtomicUnitDepth = 2 }
                }
            };

            RuleScanResult scan = engine.ScanSingleRule(unitRule, CancellationToken.None);
            ScannedFileItem dllItem = scan.Items.FirstOrDefault(x => string.Equals(x.FullPath, fooDll, StringComparison.OrdinalIgnoreCase));
            Assert(dllItem != null && string.Equals(dllItem.UnitRoot, fooVer, StringComparison.OrdinalIgnoreCase),
                "Files under <id>\\<version> must be tagged with their package unit root");

            CleanExecutionReport lockedReport;
            using (new FileStream(fooMarker, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                // The small marker file is in use: the large dll must NOT be deleted on its own.
                lockedReport = engine.CleanAsync(
                    new List<RuleScanResult> { scan },
                    new CleanOptions { IsDryRun = false, MoveNonSafeToRecycleBin = false },
                    null,
                    CancellationToken.None).Result;
            }

            Assert(File.Exists(fooDll) && File.Exists(fooMarker), "A package with a locked file must be kept whole (dll not deleted alone)");
            Assert(!Directory.Exists(barVer), "An unlocked package unit (incl. read-only file) must be deleted entirely");
            Assert(File.Exists(bazDll) && File.Exists(bazKeep), "A package containing a whitelisted file must be kept whole");
            Assert(lockedReport.LockedOrDeniedFiles >= 2, string.Format("Locked package should count its files as locked, got {0}", lockedReport.LockedOrDeniedFiles));
            Assert(lockedReport.FreedBytes == 1000, string.Format("Only the bar package (1000 bytes) should be freed, got {0}", lockedReport.FreedBytes));

            RuleScanResult rescan = engine.ScanSingleRule(unitRule, CancellationToken.None);
            CleanExecutionReport secondReport = engine.CleanAsync(
                new List<RuleScanResult> { rescan },
                new CleanOptions { IsDryRun = false, MoveNonSafeToRecycleBin = false },
                null,
                CancellationToken.None).Result;

            Assert(!Directory.Exists(fooVer), "Once unlocked, the whole package unit must be deleted");
            Assert(!Directory.Exists(Path.Combine(pkgRoot, "foo")), "Empty package id folder should be cleaned afterwards");
            Assert(Directory.GetDirectories(pkgRoot, "*.sccdel-*", SearchOption.AllDirectories).Length == 0, "No tombstone folders may be left behind");
            Assert(secondReport.DeletedFiles == 2, string.Format("Second clean should delete the 2 files of foo, got {0}", secondReport.DeletedFiles));
        }

        // 11. Recycle Bin moves are NOT counted as freed space
        private static void RunRecycleAccountingTests(CleanerEngine engine, string sandboxRoot)
        {
            string dir = Path.Combine(sandboxRoot, "RecycleAccounting");
            Directory.CreateDirectory(dir);
            File.WriteAllText(Path.Combine(dir, "cache.bin"), new string('R', 3000));

            var mediumRule = new CleanRule
            {
                Id = "test_medium_rule",
                Name = "Test Medium Rule",
                Category = CleanCategory.CommonApps,
                Risk = RiskLevel.Medium,
                DefaultSelected = true,
                Targets = new List<CleanTargetSpec> { new CleanTargetSpec { PathPattern = dir, Recursive = true } }
            };

            RuleScanResult scan = engine.ScanSingleRule(mediumRule, CancellationToken.None);
            CleanExecutionReport dry = engine.CleanAsync(
                new List<RuleScanResult> { scan },
                new CleanOptions { IsDryRun = true, MoveNonSafeToRecycleBin = true },
                null,
                CancellationToken.None).Result;

            Assert(dry.FreedBytes == 0, string.Format("Recycle-bin-bound files must not count as freed, got {0}", dry.FreedBytes));
            Assert(dry.RecycledBytes == 3000 && dry.RecycledFiles == 1, string.Format("Recycle-bin-bound bytes must be reported separately, got {0}", dry.RecycledBytes));
        }

        // 12. Junction swapped into an ancestor between scan and clean must not redirect deletion
        private static void RunJunctionSwapTests(SafetyGuard guard, CleanerEngine engine, string sandboxRoot)
        {
            string swapRoot = Path.Combine(sandboxRoot, "SwapTarget");
            string swapSub = Path.Combine(swapRoot, "sub");
            string outside = Path.Combine(sandboxRoot, "Outside");
            Directory.CreateDirectory(swapSub);
            Directory.CreateDirectory(Path.Combine(outside, "emptydir"));
            File.WriteAllText(Path.Combine(swapSub, "victim.tmp"), "scanned junk");
            string outsideFile = Path.Combine(outside, "victim.tmp");
            File.WriteAllText(outsideFile, "MUST SURVIVE");

            var swapRule = new CleanRule
            {
                Id = "test_swap_rule",
                Name = "Test Junction Swap Rule",
                Category = CleanCategory.SystemJunk,
                Risk = RiskLevel.Safe,
                DefaultSelected = true,
                Targets = new List<CleanTargetSpec> { new CleanTargetSpec { PathPattern = swapRoot, Recursive = true } }
            };

            RuleScanResult scan = engine.ScanSingleRule(swapRule, CancellationToken.None);
            Assert(scan.FileCount == 1, string.Format("Swap test should scan 1 file, got {0}", scan.FileCount));

            // Attacker: replace the scanned sub-directory with a junction pointing elsewhere.
            File.Delete(Path.Combine(swapSub, "victim.tmp"));
            Directory.Delete(swapSub);
            bool junctionCreated = CreateJunction(swapSub, outside);
            Assert(junctionCreated, "Test setup: junction must be created");

            try
            {
                CleanExecutionReport report = engine.CleanAsync(
                    new List<RuleScanResult> { scan },
                    new CleanOptions { IsDryRun = false },
                    null,
                    CancellationToken.None).Result;

                Assert(File.Exists(outsideFile), "File reached through a swapped-in junction MUST survive");
                Assert(report.DeletedFiles == 0 && report.ProtectedSkippedFiles == 1,
                    string.Format("Redirected delete must be blocked and counted as protected (deleted={0}, protected={1})", report.DeletedFiles, report.ProtectedSkippedFiles));

                string detail;
                SafeOpOutcome dirOutcome = NativeFileScanner.TrySafeDelete(Path.Combine(swapSub, "emptydir"), true, guard, out detail);
                Assert(dirOutcome == SafeOpOutcome.Redirected && Directory.Exists(Path.Combine(outside, "emptydir")),
                    "Empty-directory delete through a junction must be refused");
            }
            finally
            {
                if (junctionCreated)
                {
                    // Removes only the link itself, never the target.
                    try { Directory.Delete(swapSub); } catch { }
                }
            }
        }

        // 13. "Skip files modified within N minutes" is re-evaluated at delete time, not just at scan time
        private static void RunAgeRecheckTests(CleanerEngine engine, string sandboxRoot)
        {
            string dir = Path.Combine(sandboxRoot, "AgeRecheck");
            Directory.CreateDirectory(dir);
            string staleFile = Path.Combine(dir, "stale.tmp");
            string reusedFile = Path.Combine(dir, "reused.tmp");
            File.WriteAllText(staleFile, new string('S', 700));
            File.WriteAllText(reusedFile, new string('U', 300));
            DateTime old = DateTime.Now.AddMinutes(-20);
            File.SetLastWriteTime(staleFile, old);
            File.SetLastWriteTime(reusedFile, old);

            var tempRule = new CleanRule
            {
                Id = "test_age_rule",
                Name = "Test Age Recheck Rule",
                Category = CleanCategory.SystemJunk,
                Risk = RiskLevel.Safe,
                DefaultSelected = true,
                Targets = new List<CleanTargetSpec> { new CleanTargetSpec { PathPattern = dir, Recursive = true, MinAgeMinutes = 5 } }
            };

            RuleScanResult scan = engine.ScanSingleRule(tempRule, CancellationToken.None);
            Assert(scan.FileCount == 2 && scan.Items.All(x => x.MinAgeMinutes == 5), "Age test: both old files scanned and tagged with the 5-minute threshold");

            // After the scan, an installer starts using one of the files again.
            File.WriteAllText(reusedFile, "in use again");

            CleanExecutionReport report = engine.CleanAsync(
                new List<RuleScanResult> { scan },
                new CleanOptions { IsDryRun = false },
                null,
                CancellationToken.None).Result;

            Assert(File.Exists(reusedFile), "File modified after the scan (now inside the 5-minute window) MUST survive");
            Assert(!File.Exists(staleFile), "Untouched old file should still be deleted");
            Assert(report.DeletedFiles == 1 && report.ProtectedSkippedFiles == 1,
                string.Format("Age recheck: expected 1 deleted / 1 protected, got {0} / {1}", report.DeletedFiles, report.ProtectedSkippedFiles));
        }

        // 14. Single-instance gate: an elevated restart waits for the old instance instead of bailing out
        private static void RunSingleInstanceGateTests()
        {
            string name = @"Local\SmartCCleaner_TestGate_" + Guid.NewGuid().ToString("N");
            var held = new ManualResetEvent(false);
            var release = new ManualResetEvent(false);

            var holder = new Thread(() =>
            {
                using (SingleInstanceGate gate = SingleInstanceGate.Acquire(name, 0))
                {
                    held.Set();
                    release.WaitOne(10000);
                }
            });
            holder.Start();
            held.WaitOne(5000);

            using (SingleInstanceGate second = SingleInstanceGate.Acquire(name, 0))
            {
                Assert(!second.IsOwner, "Normal second launch must NOT get the instance lock while the first is running");
            }

            bool waiterGotLock = false;
            var waiter = new Thread(() =>
            {
                using (SingleInstanceGate gate = SingleInstanceGate.Acquire(name, 5000))
                {
                    waiterGotLock = gate.IsOwner;
                }
            });
            waiter.Start();
            Thread.Sleep(300);
            release.Set(); // old instance shuts down
            waiter.Join(10000);
            holder.Join(10000);
            Assert(waiterGotLock, "Elevated restart must take over the lock once the old instance exits");

            string abandonedName = @"Local\SmartCCleaner_TestGate_" + Guid.NewGuid().ToString("N");
            var crashed = new Thread(() =>
            {
                // Simulates a crash: lock taken, thread ends without releasing it.
                SingleInstanceGate.Acquire(abandonedName, 0);
            });
            crashed.Start();
            crashed.Join(5000);
            using (SingleInstanceGate afterCrash = SingleInstanceGate.Acquire(abandonedName, 1000))
            {
                Assert(afterCrash.IsOwner, "A lock abandoned by a crashed instance must be taken over");
            }
        }

        private static bool CreateJunction(string link, string target)
        {
            var psi = new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = string.Format("/c mklink /J \"{0}\" \"{1}\"", link, target),
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true
            };
            using (Process p = Process.Start(psi))
            {
                p.StandardOutput.ReadToEnd();
                p.WaitForExit();
                return p.ExitCode == 0 && NativeFileScanner.IsReparsePointFast(link);
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
