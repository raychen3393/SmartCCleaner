using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace SmartCCleaner
{
    public static class UninstallCore
    {
        public static string GetUserAppDataDir()
        {
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SmartCCleaner");
        }

        public static long MeasureDirectorySize(string dir)
        {
            if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) return 0;
            long total = 0;
            try
            {
                var stack = new Stack<string>();
                stack.Push(dir);
                while (stack.Count > 0)
                {
                    string cur = stack.Pop();
                    try
                    {
                        string[] files = Directory.GetFiles(cur);
                        for (int i = 0; i < files.Length; i++)
                        {
                            try { total += new FileInfo(files[i]).Length; } catch { }
                        }
                        string[] subs = Directory.GetDirectories(cur);
                        for (int i = 0; i < subs.Length; i++)
                        {
                            stack.Push(subs[i]);
                        }
                    }
                    catch
                    {
                    }
                }
            }
            catch
            {
            }
            return total;
        }

        /// <summary>
        /// Safety guard ensuring Uninstall.exe NEVER deletes a drive root, Desktop, Downloads, Documents, or unrelated folder.
        /// </summary>
        public static bool IsSafeRemovableAppFolder(string folderPath)
        {
            if (string.IsNullOrWhiteSpace(folderPath)) return false;
            string norm;
            try
            {
                norm = Path.GetFullPath(folderPath.Trim()).TrimEnd('\\');
            }
            catch
            {
                return false;
            }

            if (norm.Length <= 3) return false; // e.g. C:\ or D:\

            string folderName = Path.GetFileName(norm);
            if (string.IsNullOrEmpty(folderName)) return false;

            // Only allow auto-removing folders explicitly named SmartCCleaner, dist, or containing "C盘智清"
            bool nameMatches =
                string.Equals(folderName, "SmartCCleaner", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(folderName, "dist", StringComparison.OrdinalIgnoreCase) ||
                folderName.IndexOf("C盘智清", StringComparison.OrdinalIgnoreCase) >= 0;

            if (!nameMatches) return false;

            // Double check it's not a protected system/user shell folder
            string[] forbidden =
            {
                Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86)
            };

            for (int i = 0; i < forbidden.Length; i++)
            {
                if (string.IsNullOrEmpty(forbidden[i])) continue;
                string fNorm = Path.GetFullPath(forbidden[i]).TrimEnd('\\');
                if (string.Equals(norm, fNorm, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }
            }

            return true;
        }

        public static List<string> FindKnownShortcuts()
        {
            var found = new List<string>();
            var roots = new List<string>();

            string desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
            string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            string startMenu = Environment.GetFolderPath(Environment.SpecialFolder.Programs);

            if (!string.IsNullOrEmpty(desktop)) roots.Add(desktop);
            if (!string.IsNullOrEmpty(userProfile))
            {
                string defDesktop = Path.Combine(userProfile, "Desktop");
                if (!roots.Contains(defDesktop, StringComparer.OrdinalIgnoreCase)) roots.Add(defDesktop);
            }
            if (!string.IsNullOrEmpty(startMenu)) roots.Add(startMenu);

            string[] names = { "C盘智清.lnk", "SmartCCleaner.lnk" };
            for (int r = 0; r < roots.Count; r++)
            {
                for (int n = 0; n < names.Length; n++)
                {
                    string candidate = Path.Combine(roots[r], names[n]);
                    if (File.Exists(candidate) && !found.Contains(candidate, StringComparer.OrdinalIgnoreCase))
                    {
                        found.Add(candidate);
                    }
                }
            }

            return found;
        }

        public static bool IsMainAppRunning()
        {
            try
            {
                Process[] procs = Process.GetProcessesByName("SmartCCleaner");
                bool running = procs != null && procs.Length > 0;
                if (procs != null)
                {
                    for (int i = 0; i < procs.Length; i++)
                    {
                        try { procs[i].Dispose(); } catch { }
                    }
                }
                return running;
            }
            catch
            {
                return false;
            }
        }

        public static void CloseRunningMainApp()
        {
            try
            {
                Process[] procs = Process.GetProcessesByName("SmartCCleaner");
                for (int i = 0; i < procs.Length; i++)
                {
                    try
                    {
                        procs[i].CloseMainWindow();
                        if (!procs[i].WaitForExit(2000))
                        {
                            procs[i].Kill();
                            procs[i].WaitForExit(2000);
                        }
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
        }

        public static string DetectSourceProjectRoot(string currentDir)
        {
            try
            {
                var dir = new DirectoryInfo(currentDir);
                if (dir.Name.Equals("dist", StringComparison.OrdinalIgnoreCase) && dir.Parent != null)
                {
                    string parent = dir.Parent.FullName;
                    if (File.Exists(Path.Combine(parent, "build.ps1")) &&
                        Directory.Exists(Path.Combine(parent, "src")) &&
                        IsSafeRemovableAppFolder(parent))
                    {
                        return parent;
                    }
                }
            }
            catch
            {
            }
            return string.Empty;
        }

        public static void ScheduleSelfDelete(string selfExePath, string removableDir, string removableParentDir)
        {
            try
            {
                var sb = new StringBuilder();
                sb.Append("/c ping 127.0.0.1 -n 3 > nul");
                sb.AppendFormat(" & del /f /q \"{0}\" > nul 2>&1", selfExePath);

                if (!string.IsNullOrEmpty(removableDir) && IsSafeRemovableAppFolder(removableDir))
                {
                    sb.AppendFormat(" & rd \"{0}\" > nul 2>&1", removableDir);
                }
                if (!string.IsNullOrEmpty(removableParentDir) && IsSafeRemovableAppFolder(removableParentDir))
                {
                    sb.AppendFormat(" & rd \"{0}\" > nul 2>&1", removableParentDir);
                }

                var psi = new ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = sb.ToString(),
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    WindowStyle = ProcessWindowStyle.Hidden
                };
                Process.Start(psi);
            }
            catch
            {
            }
        }
    }

    public class UninstallWindow : Window
    {
        private readonly string _selfPath;
        private readonly string _installDir;
        private readonly string _mainExePath;
        private readonly string _appDataDir;
        private readonly string _sourceProjectRoot;

        private CheckBox _removeMainChk;
        private CheckBox _removeUserDataChk;
        private CheckBox _removeSourceChk;
        private TextBlock _statusText;
        private ProgressBar _progressBar;
        private Button _uninstallBtn;
        private Button _cancelBtn;

        public UninstallWindow()
        {
            _selfPath = Process.GetCurrentProcess().MainModule.FileName;
            _installDir = Path.GetDirectoryName(_selfPath);
            _mainExePath = Path.Combine(_installDir, "SmartCCleaner.exe");
            _appDataDir = UninstallCore.GetUserAppDataDir();
            _sourceProjectRoot = UninstallCore.DetectSourceProjectRoot(_installDir);

            Title = "卸载 C盘智清 (SmartCCleaner)";
            Width = 540;
            Height = string.IsNullOrEmpty(_sourceProjectRoot) ? 430 : 475;
            ResizeMode = ResizeMode.NoResize;
            WindowStartupLocation = WindowStartupLocation.CenterScreen;
            Background = UiTheme.BgCanvas;
            FontFamily = UiTheme.MainFont;
            Foreground = UiTheme.TextPrimary;

            try
            {
                using (var sysIcon = System.Drawing.Icon.ExtractAssociatedIcon(_selfPath))
                {
                    if (sysIcon != null)
                    {
                        Icon = System.Windows.Interop.Imaging.CreateBitmapSourceFromHIcon(
                            sysIcon.Handle,
                            Int32Rect.Empty,
                            System.Windows.Media.Imaging.BitmapSizeOptions.FromEmptyOptions());
                    }
                }
            }
            catch
            {
            }

            Content = BuildLayout();
        }

        private UIElement BuildLayout()
        {
            var root = new Grid();
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            // Header banner
            var header = new Border
            {
                Background = UiTheme.BgCard,
                BorderBrush = UiTheme.BorderLight,
                BorderThickness = new Thickness(0, 0, 0, 1),
                Padding = new Thickness(22, 16, 22, 16)
            };

            var hStack = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
            var badge = new Border
            {
                Width = 40,
                Height = 40,
                CornerRadius = new CornerRadius(10),
                Background = UiTheme.DangerRed,
                Margin = new Thickness(0, 0, 12, 0),
                Child = new TextBlock
                {
                    Text = "×",
                    Foreground = Brushes.White,
                    FontSize = 24,
                    FontWeight = FontWeights.Bold,
                    HorizontalAlignment = HorizontalAlignment.Center,
                    VerticalAlignment = VerticalAlignment.Center
                }
            };
            hStack.Children.Add(badge);

            var titleStack = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
            titleStack.Children.Add(new TextBlock
            {
                Text = "卸载 C盘智清 (SmartCCleaner)",
                FontSize = 16.5,
                FontWeight = FontWeights.Bold,
                Foreground = UiTheme.TextPrimary
            });
            titleStack.Children.Add(new TextBlock
            {
                Text = "干净移除程序文件与可选本地配置，不触碰任何其他个人文件",
                FontSize = 12,
                Foreground = UiTheme.TextMuted
            });
            hStack.Children.Add(titleStack);
            header.Child = hStack;
            Grid.SetRow(header, 0);
            root.Children.Add(header);

            // Body card
            var bodyStack = new StackPanel();
            bodyStack.Children.Add(new TextBlock
            {
                Text = "程序所在目录：" + _installDir,
                FontSize = 12,
                Foreground = UiTheme.TextSecondary,
                TextTrimming = TextTrimming.CharacterEllipsis,
                Margin = new Thickness(0, 0, 0, 12)
            });

            List<string> shortcuts = UninstallCore.FindKnownShortcuts();
            bool mainExists = File.Exists(_mainExePath);
            _removeMainChk = new CheckBox
            {
                Content = string.Format("移除主程序 SmartCCleaner.exe{0}、分享包及桌面/开始菜单快捷方式（检测到 {1} 个）",
                    mainExists ? "" : "（当前目录未检测到）", shortcuts.Count),
                IsChecked = true,
                FontSize = 12.5,
                Margin = new Thickness(0, 0, 0, 10)
            };
            bodyStack.Children.Add(_removeMainChk);

            long appDataBytes = UninstallCore.MeasureDirectorySize(_appDataDir);
            _removeUserDataChk = new CheckBox
            {
                Content = string.Format("同时清空本机配置、白名单与清理审计日志（{0}）",
                    Directory.Exists(_appDataDir) ? FormatHelper.FormatBytes(appDataBytes) : "未产生数据"),
                IsChecked = true,
                FontSize = 12.5,
                Margin = new Thickness(0, 0, 0, 10)
            };
            bodyStack.Children.Add(_removeUserDataChk);

            if (!string.IsNullOrEmpty(_sourceProjectRoot))
            {
                _removeSourceChk = new CheckBox
                {
                    Content = "同时删除当前项目目录中的源码与编译脚本（" + _sourceProjectRoot + "）",
                    IsChecked = false,
                    FontSize = 12.5,
                    Foreground = UiTheme.WarnAmberText,
                    Margin = new Thickness(0, 0, 0, 10)
                };
                bodyStack.Children.Add(_removeSourceChk);
            }

            if (UninstallCore.IsMainAppRunning())
            {
                var warnBanner = new Border
                {
                    Background = UiTheme.WarnAmberSoft,
                    BorderBrush = UiTheme.Brush("#FDE68A"),
                    BorderThickness = new Thickness(1),
                    CornerRadius = new CornerRadius(8),
                    Padding = new Thickness(10, 7, 10, 7),
                    Margin = new Thickness(0, 2, 0, 10),
                    Child = new TextBlock
                    {
                        Text = "检测到「C盘智清」正在运行，点击卸载后将自动安全关闭它。",
                        FontSize = 12,
                        Foreground = UiTheme.WarnAmberText
                    }
                };
                bodyStack.Children.Add(warnBanner);
            }

            _statusText = new TextBlock
            {
                Text = "勾选需要清理的项目后，点击右下角「确认卸载」。卸载完成后本卸载程序将自动清理自身。",
                FontSize = 12,
                Foreground = UiTheme.TextSecondary,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 4, 0, 8)
            };
            bodyStack.Children.Add(_statusText);

            _progressBar = new ProgressBar
            {
                Height = 7,
                Minimum = 0,
                Maximum = 100,
                Value = 0,
                Foreground = UiTheme.DangerRed,
                Background = UiTheme.Brush("#E2E8F0"),
                BorderThickness = new Thickness(0)
            };
            bodyStack.Children.Add(_progressBar);

            var card = UiTheme.CreateCard(bodyStack, new Thickness(20, 16, 20, 16));
            card.Margin = new Thickness(18, 14, 18, 12);
            Grid.SetRow(card, 1);
            root.Children.Add(card);

            // Footer buttons
            var footer = new Border
            {
                Background = UiTheme.BgCard,
                BorderBrush = UiTheme.BorderLight,
                BorderThickness = new Thickness(0, 1, 0, 0),
                Padding = new Thickness(20, 12, 20, 12)
            };

            var btnRow = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
            _cancelBtn = UiTheme.CreateOutlineButton("取消", 34, new Thickness(18, 0, 18, 0));
            _cancelBtn.Margin = new Thickness(0, 0, 10, 0);
            _cancelBtn.Click += delegate { Close(); };
            btnRow.Children.Add(_cancelBtn);

            _uninstallBtn = UiTheme.CreateButton("确认卸载", UiTheme.DangerRed, UiTheme.DangerRedHover, Brushes.White, 34, new Thickness(20, 0, 20, 0));
            _uninstallBtn.Click += delegate { ExecuteUninstall(); };
            btnRow.Children.Add(_uninstallBtn);

            footer.Child = btnRow;
            Grid.SetRow(footer, 2);
            root.Children.Add(footer);

            return root;
        }

        private void ExecuteUninstall()
        {
            MessageBoxResult confirm = MessageBox.Show(
                this,
                "确定要卸载「C盘智清 (SmartCCleaner)」吗？",
                "确认卸载",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);

            if (confirm != MessageBoxResult.Yes) return;

            _uninstallBtn.IsEnabled = false;
            _cancelBtn.IsEnabled = false;

            var log = new List<string>();
            try
            {
                _progressBar.Value = 15;
                _statusText.Text = "正在关闭运行中的主程序...";
                UninstallCore.CloseRunningMainApp();
                Thread.Sleep(250);

                if (_removeMainChk.IsChecked == true)
                {
                    _progressBar.Value = 45;
                    _statusText.Text = "正在删除主程序与快捷方式...";

                    if (File.Exists(_mainExePath))
                    {
                        File.Delete(_mainExePath);
                        log.Add("已删除主程序 SmartCCleaner.exe");
                    }

                    // Clean companion files created by release bundle in the same directory
                    string[] companions = { "使用说明.txt", "C盘智清_v2.0_绿色分享版.zip", "SmartCCleaner.Tests.exe" };
                    for (int i = 0; i < companions.Length; i++)
                    {
                        string fp = Path.Combine(_installDir, companions[i]);
                        if (File.Exists(fp))
                        {
                            try { File.Delete(fp); log.Add("已删除伴随文件 " + companions[i]); } catch { }
                        }
                    }

                    List<string> shortcuts = UninstallCore.FindKnownShortcuts();
                    for (int i = 0; i < shortcuts.Count; i++)
                    {
                        try
                        {
                            File.Delete(shortcuts[i]);
                            log.Add("已删除快捷方式 " + Path.GetFileName(shortcuts[i]));
                        }
                        catch
                        {
                        }
                    }
                }

                if (_removeUserDataChk.IsChecked == true)
                {
                    _progressBar.Value = 75;
                    _statusText.Text = "正在清空本机白名单、偏好设置与清理日志...";
                    if (Directory.Exists(_appDataDir))
                    {
                        Directory.Delete(_appDataDir, true);
                        log.Add("已清空本地数据目录 " + _appDataDir);
                    }
                }

                string parentToRemoveIfEmpty = string.Empty;
                if (_removeSourceChk != null && _removeSourceChk.IsChecked == true && !string.IsNullOrEmpty(_sourceProjectRoot))
                {
                    _progressBar.Value = 90;
                    _statusText.Text = "正在移除项目源码与构建文件...";
                    string[] subDirs = { "src", "tests", "assets", "build" };
                    for (int i = 0; i < subDirs.Length; i++)
                    {
                        string d = Path.Combine(_sourceProjectRoot, subDirs[i]);
                        if (Directory.Exists(d))
                        {
                            try { Directory.Delete(d, true); } catch { }
                        }
                    }
                    string[] rootFiles = { "build.ps1", "README.md" };
                    for (int i = 0; i < rootFiles.Length; i++)
                    {
                        string f = Path.Combine(_sourceProjectRoot, rootFiles[i]);
                        if (File.Exists(f))
                        {
                            try { File.Delete(f); } catch { }
                        }
                    }
                    parentToRemoveIfEmpty = _sourceProjectRoot;
                    log.Add("已移除项目源码与构建文件");
                }

                _progressBar.Value = 100;
                _statusText.Text = "卸载完成！";

                string summary = "「C盘智清 (SmartCCleaner)」已卸载完成！\n\n" +
                    (log.Count > 0 ? "• " + string.Join("\n• ", log) : "未检测到残留文件。") +
                    "\n\n点击「确定」后，本卸载程序将自动删除自身。";

                MessageBox.Show(this, summary, "卸载完成", MessageBoxButton.OK, MessageBoxImage.Information);

                string removableDir = UninstallCore.IsSafeRemovableAppFolder(_installDir) ? _installDir : string.Empty;
                UninstallCore.ScheduleSelfDelete(_selfPath, removableDir, parentToRemoveIfEmpty);
                Application.Current.Shutdown();
            }
            catch (Exception ex)
            {
                _uninstallBtn.IsEnabled = true;
                _cancelBtn.IsEnabled = true;
                _statusText.Text = "卸载出现异常：" + ex.Message;
                MessageBox.Show(this, "卸载过程中发生错误：\n" + ex.Message, "卸载失败", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }

    public static class UninstallerProgram
    {
        [STAThread]
        public static void Main(string[] args)
        {
            var app = new Application();
            app.ShutdownMode = ShutdownMode.OnMainWindowClose;
            var win = new UninstallWindow();
            app.MainWindow = win;
            app.Run(win);
        }
    }
}
