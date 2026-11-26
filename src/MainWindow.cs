using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Shapes;

namespace SmartCCleaner
{
    public class MainWindow : Window
    {
        private readonly SafetyGuard _guard;
        private readonly CleanerEngine _engine;
        private readonly List<CleanRule> _rules;
        private readonly AppSettings _settings;
        private List<RuleScanResult> _scanResults;
        private RuleScanResult _activeRuleResult;
        private CancellationTokenSource _cts;
        private bool _isBusy;
        private int _activeCategoryFilter;
        private bool _onlyDetected;

        // Top & Hero controls
        private Canvas _gaugeCanvas;
        private TextBlock _gaugePercentText;
        private TextBlock _driveMetaText;
        private TextBlock _heroTitleText;
        private TextBlock _heroSubText;
        private ProgressBar _heroProgress;
        private Button _scanBtn;
        private Button _cleanBtn;
        private CheckBox _dryRunCheck;
        private CheckBox _recycleMediumCheck;

        // Navigation tabs
        private Button _tabCleanBtn;
        private Button _tabWhitelistBtn;
        private Button _tabLogsBtn;
        private Grid _cleanView;
        private Grid _whitelistView;
        private Grid _logsView;

        // Clean view controls
        private StackPanel _filterBar;
        private StackPanel _ruleListPanel;
        private TextBlock _previewHeaderTitle;
        private TextBlock _previewSafetyNote;
        private TextBox _previewSearchBox;
        private ListView _previewListView;
        private TextBlock _previewFooterHint;
        private Button _openLocationBtn;
        private Button _addToWhitelistBtn;

        // Whitelist view controls
        private TextBox _wlPatternInput;
        private TextBox _wlNoteInput;
        private ListView _wlListView;

        // Logs view controls
        private ListBox _logsListBox;
        private TextBox _logContentBox;

        // Status bar
        private TextBlock _statusLeftText;
        private TextBlock _statusRightText;

        public MainWindow()
        {
            _guard = new SafetyGuard();
            _engine = new CleanerEngine(_guard);
            _rules = RulesEngine.BuildDefaultRules();
            _settings = _guard.LoadSettings();
            _scanResults = new List<RuleScanResult>();
            _activeCategoryFilter = -1;
            _onlyDetected = _settings.OnlyShowDetected;

            InitializeWindowProperties();
            Content = BuildRootLayout();

            RefreshDriveGauge();
            RefreshWhitelistView();
            RefreshLogsView();
            UpdateStatusBar("就绪 — v2.0 已启用 Win32 高速枚举、4 线程并发与超长路径支持");

            Loaded += delegate
            {
                StartScanAsync();
            };

            Closing += delegate
            {
                PersistSettings();
            };
        }

        private void PersistSettings()
        {
            try
            {
                _settings.DryRunMode = (_dryRunCheck != null && _dryRunCheck.IsChecked == true);
                _settings.MoveNonSafeToRecycleBin = (_recycleMediumCheck != null && _recycleMediumCheck.IsChecked == true);
                _settings.OnlyShowDetected = _onlyDetected;
                if (WindowState == WindowState.Normal)
                {
                    _settings.WindowWidth = Math.Max(MinWidth, Width);
                    _settings.WindowHeight = Math.Max(MinHeight, Height);
                }
                _guard.SaveSettings(_settings);
            }
            catch
            {
            }
        }

        private void InitializeWindowProperties()
        {
            Title = Program.MainWindowTitle;
            Width = (_settings.WindowWidth >= 960 && _settings.WindowWidth <= 2400) ? _settings.WindowWidth : 1140;
            Height = (_settings.WindowHeight >= 640 && _settings.WindowHeight <= 1600) ? _settings.WindowHeight : 760;
            MinWidth = 960;
            MinHeight = 640;
            WindowStartupLocation = WindowStartupLocation.CenterScreen;
            Background = UiTheme.BgCanvas;
            FontFamily = UiTheme.MainFont;
            Foreground = UiTheme.TextPrimary;
            TextOptions.SetTextFormattingMode(this, TextFormattingMode.Display);

            try
            {
                string exePath = Process.GetCurrentProcess().MainModule.FileName;
                using (var sysIcon = System.Drawing.Icon.ExtractAssociatedIcon(exePath))
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
        }

        private UIElement BuildRootLayout()
        {
            var root = new Grid();
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            var header = BuildHeaderBar();
            Grid.SetRow(header, 0);
            root.Children.Add(header);

            var hero = BuildHeroDashboard();
            Grid.SetRow(hero, 1);
            root.Children.Add(hero);

            var nav = BuildNavTabsBar();
            Grid.SetRow(nav, 2);
            root.Children.Add(nav);

            var bodyContainer = new Grid { Margin = new Thickness(20, 8, 20, 12) };
            _cleanView = BuildCleanView();
            _whitelistView = BuildWhitelistView();
            _logsView = BuildLogsView();
            _whitelistView.Visibility = Visibility.Collapsed;
            _logsView.Visibility = Visibility.Collapsed;

            bodyContainer.Children.Add(_cleanView);
            bodyContainer.Children.Add(_whitelistView);
            bodyContainer.Children.Add(_logsView);
            Grid.SetRow(bodyContainer, 3);
            root.Children.Add(bodyContainer);

            var statusBar = BuildStatusBar();
            Grid.SetRow(statusBar, 4);
            root.Children.Add(statusBar);

            return root;
        }

        private UIElement BuildHeaderBar()
        {
            var bar = new Border
            {
                Background = UiTheme.BgCard,
                BorderBrush = UiTheme.BorderLight,
                BorderThickness = new Thickness(0, 0, 0, 1),
                Padding = new Thickness(20, 12, 20, 12)
            };

            var dock = new DockPanel { LastChildFill = false };

            var brandStack = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
            var logoBadge = new Border
            {
                Width = 34,
                Height = 34,
                CornerRadius = new CornerRadius(9),
                Background = UiTheme.AccentBlue,
                Margin = new Thickness(0, 0, 10, 0),
                Child = new TextBlock
                {
                    Text = "C",
                    Foreground = Brushes.White,
                    FontSize = 18,
                    FontWeight = FontWeights.Bold,
                    HorizontalAlignment = HorizontalAlignment.Center,
                    VerticalAlignment = VerticalAlignment.Center
                }
            };
            brandStack.Children.Add(logoBadge);

            var titleStack = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
            var titleLine = new StackPanel { Orientation = Orientation.Horizontal };
            titleLine.Children.Add(new TextBlock
            {
                Text = "C盘智清 SmartCCleaner",
                FontSize = 16,
                FontWeight = FontWeights.Bold,
                Foreground = UiTheme.TextPrimary,
                Margin = new Thickness(0, 0, 8, 0)
            });
            titleLine.Children.Add(UiTheme.CreatePill("v2.0", UiTheme.AccentBlueSoft, UiTheme.AccentBlue));
            titleStack.Children.Add(titleLine);

            titleStack.Children.Add(new TextBlock
            {
                Text = "Win32 高速并行扫描 · 超长路径支持 · 清理前预览与防误删保护",
                FontSize = 11.5,
                Foreground = UiTheme.TextMuted
            });
            brandStack.Children.Add(titleStack);
            DockPanel.SetDock(brandStack, Dock.Left);
            dock.Children.Add(brandStack);

            var rightStack = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };

            bool isAdmin = CleanerEngine.IsRunningAsAdministrator();
            if (isAdmin)
            {
                var adminPill = UiTheme.CreatePill("已开启管理员深度清理权限", UiTheme.SafeGreenSoft, UiTheme.SafeGreenText);
                adminPill.Margin = new Thickness(0, 0, 8, 0);
                rightStack.Children.Add(adminPill);
            }
            else
            {
                var elevateBtn = UiTheme.CreateButton(
                    "标准权限 · 点击提权深度清理",
                    UiTheme.WarnAmberSoft,
                    UiTheme.Brush("#FEF3C7"),
                    UiTheme.WarnAmberText,
                    30,
                    new Thickness(12, 0, 12, 0));
                elevateBtn.FontSize = 12;
                elevateBtn.Margin = new Thickness(0, 0, 8, 0);
                elevateBtn.ToolTip = "以管理员身份重启后，可深度清理 Windows 更新缓存、系统 Temp 与诊断日志";
                elevateBtn.Click += delegate { RestartAsAdministrator(); };
                rightStack.Children.Add(elevateBtn);
            }

            var shortcutBtn = UiTheme.CreateOutlineButton("创建桌面快捷方式", 30, new Thickness(10, 0, 10, 0));
            shortcutBtn.Margin = new Thickness(0, 0, 8, 0);
            shortcutBtn.ToolTip = "在桌面生成「C盘智清」快捷方式，方便随时一键打开";
            shortcutBtn.Click += delegate { CreateDesktopShortcut(); };
            rightStack.Children.Add(shortcutBtn);

            var openLogsBtn = UiTheme.CreateOutlineButton("打开日志目录", 30, new Thickness(10, 0, 10, 0));
            openLogsBtn.Click += delegate { OpenFolderInExplorer(_guard.LogsDirectory); };
            rightStack.Children.Add(openLogsBtn);

            DockPanel.SetDock(rightStack, Dock.Right);
            dock.Children.Add(rightStack);

            bar.Child = dock;
            return bar;
        }

        private UIElement BuildHeroDashboard()
        {
            var grid = new Grid();
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            var gaugeContainer = new StackPanel { VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 22, 0) };
            var gaugeHost = new Grid { Width = 104, Height = 104, HorizontalAlignment = HorizontalAlignment.Center };
            _gaugeCanvas = new Canvas { Width = 104, Height = 104 };
            gaugeHost.Children.Add(_gaugeCanvas);

            var gaugeCenter = new StackPanel { VerticalAlignment = VerticalAlignment.Center, HorizontalAlignment = HorizontalAlignment.Center };
            _gaugePercentText = new TextBlock
            {
                Text = "--%",
                FontSize = 21,
                FontWeight = FontWeights.Bold,
                Foreground = UiTheme.TextPrimary,
                HorizontalAlignment = HorizontalAlignment.Center
            };
            gaugeCenter.Children.Add(_gaugePercentText);
            gaugeCenter.Children.Add(new TextBlock
            {
                Text = "C 盘已用",
                FontSize = 11,
                Foreground = UiTheme.TextMuted,
                HorizontalAlignment = HorizontalAlignment.Center
            });
            gaugeHost.Children.Add(gaugeCenter);
            gaugeContainer.Children.Add(gaugeHost);

            _driveMetaText = new TextBlock
            {
                Text = "读取磁盘中...",
                FontSize = 11.5,
                Foreground = UiTheme.TextSecondary,
                HorizontalAlignment = HorizontalAlignment.Center,
                Margin = new Thickness(0, 6, 0, 0)
            };
            gaugeContainer.Children.Add(_driveMetaText);
            Grid.SetColumn(gaugeContainer, 0);
            grid.Children.Add(gaugeContainer);

            var centerStack = new StackPanel { VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 24, 0) };
            _heroTitleText = new TextBlock
            {
                Text = "正在初始化 C 盘智能体检...",
                FontSize = 18.5,
                FontWeight = FontWeights.Bold,
                Foreground = UiTheme.TextPrimary,
                TextWrapping = TextWrapping.Wrap
            };
            centerStack.Children.Add(_heroTitleText);

            _heroSubText = new TextBlock
            {
                Text = "扫描完成后可逐项预览待删文件；系统核心目录、个人文档与符号链接均受硬保护。",
                FontSize = 12.5,
                Foreground = UiTheme.TextSecondary,
                Margin = new Thickness(0, 6, 0, 12),
                TextTrimming = TextTrimming.CharacterEllipsis
            };
            centerStack.Children.Add(_heroSubText);

            _heroProgress = new ProgressBar
            {
                Height = 8,
                Minimum = 0,
                Maximum = 100,
                Value = 0,
                Foreground = UiTheme.AccentBlue,
                Background = UiTheme.Brush("#E2E8F0"),
                BorderThickness = new Thickness(0)
            };
            centerStack.Children.Add(_heroProgress);

            Grid.SetColumn(centerStack, 1);
            grid.Children.Add(centerStack);

            var actionStack = new StackPanel { VerticalAlignment = VerticalAlignment.Center, HorizontalAlignment = HorizontalAlignment.Right };
            var btnRow = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };

            _scanBtn = UiTheme.CreateButton("一键智能扫描", UiTheme.AccentBlue, UiTheme.AccentBlueHover, Brushes.White, 42, new Thickness(20, 0, 20, 0));
            _scanBtn.FontSize = 14;
            _scanBtn.Margin = new Thickness(0, 0, 10, 0);
            _scanBtn.Click += delegate { OnScanButtonClicked(); };
            btnRow.Children.Add(_scanBtn);

            _cleanBtn = UiTheme.CreateButton("一键安全清理", UiTheme.SafeGreen, UiTheme.SafeGreenHover, Brushes.White, 42, new Thickness(22, 0, 22, 0));
            _cleanBtn.FontSize = 14;
            _cleanBtn.IsEnabled = false;
            _cleanBtn.Click += delegate { OnCleanButtonClicked(); };
            btnRow.Children.Add(_cleanBtn);

            actionStack.Children.Add(btnRow);

            _dryRunCheck = new CheckBox
            {
                Content = "演练模式（仅模拟清理并生成日志，不实际删除文件）",
                IsChecked = _settings.DryRunMode,
                FontSize = 12,
                Foreground = UiTheme.TextSecondary,
                Margin = new Thickness(0, 9, 0, 0),
                HorizontalAlignment = HorizontalAlignment.Right,
                VerticalContentAlignment = VerticalAlignment.Center
            };
            _dryRunCheck.Checked += delegate { UpdateCleanButtonText(); PersistSettings(); };
            _dryRunCheck.Unchecked += delegate { UpdateCleanButtonText(); PersistSettings(); };
            actionStack.Children.Add(_dryRunCheck);

            _recycleMediumCheck = new CheckBox
            {
                Content = "常用/开发缓存优先移入回收站（提供一层可撤销保护）",
                IsChecked = _settings.MoveNonSafeToRecycleBin,
                FontSize = 12,
                Foreground = UiTheme.TextSecondary,
                Margin = new Thickness(0, 4, 0, 0),
                HorizontalAlignment = HorizontalAlignment.Right,
                VerticalContentAlignment = VerticalAlignment.Center
            };
            _recycleMediumCheck.Checked += delegate { PersistSettings(); };
            _recycleMediumCheck.Unchecked += delegate { PersistSettings(); };
            actionStack.Children.Add(_recycleMediumCheck);

            Grid.SetColumn(actionStack, 2);
            grid.Children.Add(actionStack);

            var card = UiTheme.CreateCard(grid, new Thickness(22, 16, 22, 16));
            card.Margin = new Thickness(20, 14, 20, 10);
            return card;
        }

        private UIElement BuildNavTabsBar()
        {
            var container = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                Margin = new Thickness(20, 2, 20, 2)
            };

            _tabCleanBtn = CreateTabButton("智能清理与预览", true);
            _tabCleanBtn.Click += delegate { SwitchTab(0); };

            _tabWhitelistBtn = CreateTabButton("白名单与防误删保护", false);
            _tabWhitelistBtn.Click += delegate { SwitchTab(1); };

            _tabLogsBtn = CreateTabButton("清理审计日志", false);
            _tabLogsBtn.Click += delegate { SwitchTab(2); };

            container.Children.Add(_tabCleanBtn);
            container.Children.Add(_tabWhitelistBtn);
            container.Children.Add(_tabLogsBtn);

            return container;
        }

        private Button CreateTabButton(string text, bool active)
        {
            var btn = new Button
            {
                Content = text,
                FontFamily = UiTheme.MainFont,
                FontSize = 13,
                FontWeight = active ? FontWeights.Bold : FontWeights.Medium,
                Height = 34,
                Padding = new Thickness(16, 0, 16, 0),
                Margin = new Thickness(0, 0, 8, 0),
                Cursor = Cursors.Hand
            };
            ApplyTabVisual(btn, active);
            return btn;
        }

        private void ApplyTabVisual(Button btn, bool active)
        {
            btn.FontWeight = active ? FontWeights.Bold : FontWeights.Medium;
            btn.Foreground = active ? UiTheme.AccentBlue : UiTheme.TextSecondary;
            btn.Template = UiTheme.BuildRoundedButtonTemplate(
                active ? UiTheme.AccentBlueSoft : Brushes.Transparent,
                active ? UiTheme.AccentBlueSoft : UiTheme.Brush("#E2E8F0"),
                active ? UiTheme.Brush("#BFDBFE") : null,
                8);
        }

        private void SwitchTab(int index)
        {
            _cleanView.Visibility = index == 0 ? Visibility.Visible : Visibility.Collapsed;
            _whitelistView.Visibility = index == 1 ? Visibility.Visible : Visibility.Collapsed;
            _logsView.Visibility = index == 2 ? Visibility.Visible : Visibility.Collapsed;

            ApplyTabVisual(_tabCleanBtn, index == 0);
            ApplyTabVisual(_tabWhitelistBtn, index == 1);
            ApplyTabVisual(_tabLogsBtn, index == 2);

            if (index == 1) RefreshWhitelistView();
            if (index == 2) RefreshLogsView();
        }

        #region Tab 1: Smart Clean & Preview View

        private Grid BuildCleanView()
        {
            var grid = new Grid();
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            grid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });

            var toolbarDock = new DockPanel { Margin = new Thickness(0, 0, 0, 10) };

            _filterBar = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
            BuildCategoryFilterButtons();
            DockPanel.SetDock(_filterBar, Dock.Left);
            toolbarDock.Children.Add(_filterBar);

            var rightTools = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center, HorizontalAlignment = HorizontalAlignment.Right };
            var onlyDetectedChk = new CheckBox
            {
                Content = "仅显示已检测到项",
                IsChecked = _onlyDetected,
                FontSize = 12,
                Foreground = UiTheme.TextSecondary,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 12, 0)
            };
            onlyDetectedChk.Checked += delegate { _onlyDetected = true; PersistSettings(); RenderRuleList(); };
            onlyDetectedChk.Unchecked += delegate { _onlyDetected = false; PersistSettings(); RenderRuleList(); };
            rightTools.Children.Add(onlyDetectedChk);

            var safeSelectBtn = UiTheme.CreateOutlineButton("仅选安全推荐", 28, new Thickness(10, 0, 10, 0));
            safeSelectBtn.Margin = new Thickness(0, 0, 6, 0);
            safeSelectBtn.Click += delegate { ApplyQuickSelection("safe"); };
            rightTools.Children.Add(safeSelectBtn);

            var selectAllBtn = UiTheme.CreateOutlineButton("全选当前", 28, new Thickness(10, 0, 10, 0));
            selectAllBtn.Margin = new Thickness(0, 0, 6, 0);
            selectAllBtn.Click += delegate { ApplyQuickSelection("all"); };
            rightTools.Children.Add(selectAllBtn);

            var clearSelBtn = UiTheme.CreateOutlineButton("清空勾选", 28, new Thickness(10, 0, 10, 0));
            clearSelBtn.Click += delegate { ApplyQuickSelection("none"); };
            rightTools.Children.Add(clearSelBtn);

            DockPanel.SetDock(rightTools, Dock.Right);
            toolbarDock.Children.Add(rightTools);

            Grid.SetRow(toolbarDock, 0);
            grid.Children.Add(toolbarDock);

            var split = new Grid();
            split.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1.28, GridUnitType.Star) });
            split.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(14) });
            split.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1.0, GridUnitType.Star) });

            _ruleListPanel = new StackPanel { Margin = new Thickness(2, 2, 6, 2) };
            var ruleScroll = new ScrollViewer
            {
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled,
                Content = _ruleListPanel
            };
            var leftCard = UiTheme.CreateCard(ruleScroll, new Thickness(10, 10, 6, 10));
            Grid.SetColumn(leftCard, 0);
            split.Children.Add(leftCard);

            var previewGrid = new Grid();
            previewGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            previewGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            previewGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            previewGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            _previewHeaderTitle = new TextBlock
            {
                Text = "清理前文件预览",
                FontSize = 14.5,
                FontWeight = FontWeights.Bold,
                Foreground = UiTheme.TextPrimary,
                Margin = new Thickness(0, 0, 0, 4)
            };
            Grid.SetRow(_previewHeaderTitle, 0);
            previewGrid.Children.Add(_previewHeaderTitle);

            var previewSubStack = new StackPanel { Margin = new Thickness(0, 0, 0, 8) };
            _previewSafetyNote = new TextBlock
            {
                Text = "点击左侧任意清理项，即可在此处逐条检查待删除文件并支持一键加入白名单。",
                FontSize = 12,
                Foreground = UiTheme.TextSecondary,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 0, 0, 8)
            };
            previewSubStack.Children.Add(_previewSafetyNote);

            _previewSearchBox = new TextBox
            {
                Height = 30,
                Padding = new Thickness(8, 5, 8, 5),
                FontSize = 12.5,
                BorderBrush = UiTheme.BorderLight,
                BorderThickness = new Thickness(1),
                Background = UiTheme.BgSubtle,
                ToolTip = "输入关键词过滤待删文件名或路径"
            };
            _previewSearchBox.TextChanged += delegate { RefreshPreviewList(); };
            previewSubStack.Children.Add(_previewSearchBox);
            Grid.SetRow(previewSubStack, 1);
            previewGrid.Children.Add(previewSubStack);

            _previewListView = new ListView
            {
                BorderBrush = UiTheme.BorderLight,
                BorderThickness = new Thickness(1),
                Background = Brushes.White,
                FontSize = 12
            };
            var gv = new GridView();
            gv.Columns.Add(new GridViewColumn { Header = "文件 / 项目", Width = 175, DisplayMemberBinding = new System.Windows.Data.Binding("DisplayName") });
            gv.Columns.Add(new GridViewColumn { Header = "大小", Width = 78, DisplayMemberBinding = new System.Windows.Data.Binding("SizeText") });
            gv.Columns.Add(new GridViewColumn { Header = "完整路径", Width = 240, DisplayMemberBinding = new System.Windows.Data.Binding("FullPath") });
            _previewListView.View = gv;
            _previewListView.SelectionChanged += delegate { UpdatePreviewActionButtons(); };
            Grid.SetRow(_previewListView, 2);
            previewGrid.Children.Add(_previewListView);

            var previewFooter = new DockPanel { Margin = new Thickness(0, 8, 0, 0) };
            _previewFooterHint = new TextBlock
            {
                Text = "未选择清理项",
                FontSize = 11.5,
                Foreground = UiTheme.TextMuted,
                VerticalAlignment = VerticalAlignment.Center
            };
            DockPanel.SetDock(_previewFooterHint, Dock.Left);
            previewFooter.Children.Add(_previewFooterHint);

            var previewBtns = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
            _openLocationBtn = UiTheme.CreateOutlineButton("打开位置", 28, new Thickness(10, 0, 10, 0));
            _openLocationBtn.Margin = new Thickness(0, 0, 6, 0);
            _openLocationBtn.IsEnabled = false;
            _openLocationBtn.Click += delegate { OnOpenSelectedPreviewLocation(); };
            previewBtns.Children.Add(_openLocationBtn);

            _addToWhitelistBtn = UiTheme.CreateButton("加入白名单保护", UiTheme.WarnAmberSoft, UiTheme.Brush("#FEF3C7"), UiTheme.WarnAmberText, 28, new Thickness(10, 0, 10, 0));
            _addToWhitelistBtn.FontSize = 12;
            _addToWhitelistBtn.IsEnabled = false;
            _addToWhitelistBtn.Click += delegate { OnAddSelectedPreviewToWhitelist(); };
            previewBtns.Children.Add(_addToWhitelistBtn);

            DockPanel.SetDock(previewBtns, Dock.Right);
            previewFooter.Children.Add(previewBtns);

            Grid.SetRow(previewFooter, 3);
            previewGrid.Children.Add(previewFooter);

            var rightCard = UiTheme.CreateCard(previewGrid, new Thickness(14, 12, 14, 12));
            Grid.SetColumn(rightCard, 2);
            split.Children.Add(rightCard);

            Grid.SetRow(split, 1);
            grid.Children.Add(split);

            return grid;
        }

        private void BuildCategoryFilterButtons()
        {
            _filterBar.Children.Clear();
            var items = new[]
            {
                new { Key = -1, Label = "全部" },
                new { Key = (int)CleanCategory.SystemJunk, Label = "系统垃圾" },
                new { Key = (int)CleanCategory.BrowserCache, Label = "浏览器缓存" },
                new { Key = (int)CleanCategory.CommonApps, Label = "常用软件" },
                new { Key = (int)CleanCategory.DevTools, Label = "开发工具" }
            };

            for (int i = 0; i < items.Length; i++)
            {
                int key = items[i].Key;
                bool active = (_activeCategoryFilter == key);
                var btn = new Button
                {
                    Content = items[i].Label,
                    Height = 28,
                    Padding = new Thickness(11, 0, 11, 0),
                    Margin = new Thickness(0, 0, 6, 0),
                    FontFamily = UiTheme.MainFont,
                    FontSize = 12,
                    FontWeight = active ? FontWeights.Bold : FontWeights.Normal,
                    Foreground = active ? Brushes.White : UiTheme.TextSecondary,
                    Cursor = Cursors.Hand
                };
                btn.Template = UiTheme.BuildRoundedButtonTemplate(
                    active ? UiTheme.AccentBlue : UiTheme.BgCard,
                    active ? UiTheme.AccentBlueHover : UiTheme.BgSubtle,
                    active ? null : UiTheme.BorderLight,
                    14);
                btn.Click += delegate
                {
                    _activeCategoryFilter = key;
                    BuildCategoryFilterButtons();
                    RenderRuleList();
                };
                _filterBar.Children.Add(btn);
            }
        }

        #endregion

        #region Tab 2: Whitelist & Safety View

        private Grid BuildWhitelistView()
        {
            var grid = new Grid();
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            grid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });

            var builtInStack = new StackPanel();
            builtInStack.Children.Add(new TextBlock
            {
                Text = "内置硬编码防误删保护（不可关闭）",
                FontSize = 14.5,
                FontWeight = FontWeights.Bold,
                Foreground = UiTheme.TextPrimary,
                Margin = new Thickness(0, 0, 0, 8)
            });

            IList<string> summaries = _guard.GetBuiltInProtectedSummary();
            for (int i = 0; i < summaries.Count; i++)
            {
                builtInStack.Children.Add(new TextBlock
                {
                    Text = "✓  " + summaries[i],
                    FontSize = 12.5,
                    Foreground = UiTheme.SafeGreenText,
                    Margin = new Thickness(0, 2, 0, 2)
                });
            }

            var builtInCard = UiTheme.CreateCard(builtInStack, new Thickness(18, 14, 18, 14));
            builtInCard.Margin = new Thickness(0, 0, 0, 12);
            Grid.SetRow(builtInCard, 0);
            grid.Children.Add(builtInCard);

            var customGrid = new Grid();
            customGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            customGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            customGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            customGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            var headerText = new TextBlock
            {
                Text = "自定义白名单规则（预编译正则加速，扫描与清理阶段均自动跳过）",
                FontSize = 14.5,
                FontWeight = FontWeights.Bold,
                Foreground = UiTheme.TextPrimary,
                Margin = new Thickness(0, 0, 0, 10)
            };
            Grid.SetRow(headerText, 0);
            customGrid.Children.Add(headerText);

            var addBar = new Grid { Margin = new Thickness(0, 0, 0, 10) };
            addBar.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(2.2, GridUnitType.Star) });
            addBar.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1.2, GridUnitType.Star) });
            addBar.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            addBar.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            _wlPatternInput = new TextBox
            {
                Height = 32,
                Padding = new Thickness(8, 6, 8, 6),
                Margin = new Thickness(0, 0, 8, 0),
                BorderBrush = UiTheme.BorderLight,
                ToolTip = "输入完整文件夹/文件路径或通配符（例如 *.sqlite 或 C:\\Users\\...\\KeepMe）"
            };
            Grid.SetColumn(_wlPatternInput, 0);
            addBar.Children.Add(_wlPatternInput);

            _wlNoteInput = new TextBox
            {
                Height = 32,
                Padding = new Thickness(8, 6, 8, 6),
                Margin = new Thickness(0, 0, 8, 0),
                BorderBrush = UiTheme.BorderLight,
                Text = "自定义保护项",
                ToolTip = "可选备注"
            };
            Grid.SetColumn(_wlNoteInput, 1);
            addBar.Children.Add(_wlNoteInput);

            var browseBtn = UiTheme.CreateOutlineButton("选择目录...", 32, new Thickness(12, 0, 12, 0));
            browseBtn.Margin = new Thickness(0, 0, 8, 0);
            browseBtn.Click += delegate { BrowseFolderForWhitelist(); };
            Grid.SetColumn(browseBtn, 2);
            addBar.Children.Add(browseBtn);

            var addBtn = UiTheme.CreateButton("添加白名单", UiTheme.AccentBlue, UiTheme.AccentBlueHover, Brushes.White, 32, new Thickness(14, 0, 14, 0));
            addBtn.Click += delegate { AddManualWhitelistRule(); };
            Grid.SetColumn(addBtn, 3);
            addBar.Children.Add(addBtn);

            Grid.SetRow(addBar, 1);
            customGrid.Children.Add(addBar);

            _wlListView = new ListView
            {
                BorderBrush = UiTheme.BorderLight,
                BorderThickness = new Thickness(1),
                FontSize = 12.5
            };
            var wgv = new GridView();
            wgv.Columns.Add(new GridViewColumn { Header = "保护路径 / 通配符", Width = 460, DisplayMemberBinding = new System.Windows.Data.Binding("Pattern") });
            wgv.Columns.Add(new GridViewColumn { Header = "备注说明", Width = 220, DisplayMemberBinding = new System.Windows.Data.Binding("Note") });
            wgv.Columns.Add(new GridViewColumn { Header = "添加时间", Width = 160, DisplayMemberBinding = new System.Windows.Data.Binding("AddedAt") });
            _wlListView.View = wgv;
            Grid.SetRow(_wlListView, 2);
            customGrid.Children.Add(_wlListView);

            var footerDock = new DockPanel { Margin = new Thickness(0, 10, 0, 0) };
            var hint = new TextBlock
            {
                Text = "支持目录前缀（如 C:\\Users\\Me\\AppData\\Local\\Temp\\Keep）或通配符（如 *.db、*important*）。配置文件持久化于本地。",
                FontSize = 11.5,
                Foreground = UiTheme.TextMuted,
                VerticalAlignment = VerticalAlignment.Center
            };
            DockPanel.SetDock(hint, Dock.Left);
            footerDock.Children.Add(hint);

            var removeBtn = UiTheme.CreateButton("移除选中规则", UiTheme.DangerRedSoft, UiTheme.Brush("#FEE2E2"), UiTheme.DangerRedText, 30, new Thickness(12, 0, 12, 0));
            removeBtn.FontSize = 12;
            removeBtn.Click += delegate { RemoveSelectedWhitelistRule(); };
            DockPanel.SetDock(removeBtn, Dock.Right);
            footerDock.Children.Add(removeBtn);

            Grid.SetRow(footerDock, 3);
            customGrid.Children.Add(footerDock);

            var customCard = UiTheme.CreateCard(customGrid, new Thickness(18, 14, 18, 14));
            Grid.SetRow(customCard, 1);
            grid.Children.Add(customCard);

            return grid;
        }

        #endregion

        #region Tab 3: Audit Logs View

        private Grid BuildLogsView()
        {
            var grid = new Grid();
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(280) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(14) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

            var leftGrid = new Grid();
            leftGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            leftGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            leftGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            var leftTitle = new TextBlock
            {
                Text = "历史清理记录（流式完整保存）",
                FontSize = 14,
                FontWeight = FontWeights.Bold,
                Margin = new Thickness(0, 0, 0, 8)
            };
            Grid.SetRow(leftTitle, 0);
            leftGrid.Children.Add(leftTitle);

            _logsListBox = new ListBox
            {
                BorderBrush = UiTheme.BorderLight,
                BorderThickness = new Thickness(1),
                FontSize = 12.5
            };
            _logsListBox.SelectionChanged += delegate { LoadSelectedLogFile(); };
            Grid.SetRow(_logsListBox, 1);
            leftGrid.Children.Add(_logsListBox);

            var logBtns = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 8, 0, 0) };
            var refreshBtn = UiTheme.CreateOutlineButton("刷新列表", 28, new Thickness(10, 0, 10, 0));
            refreshBtn.Margin = new Thickness(0, 0, 6, 0);
            refreshBtn.Click += delegate { RefreshLogsView(); };
            logBtns.Children.Add(refreshBtn);

            var openDirBtn = UiTheme.CreateOutlineButton("打开目录", 28, new Thickness(10, 0, 10, 0));
            openDirBtn.Click += delegate { OpenFolderInExplorer(_guard.LogsDirectory); };
            logBtns.Children.Add(openDirBtn);

            Grid.SetRow(logBtns, 2);
            leftGrid.Children.Add(logBtns);

            var leftCard = UiTheme.CreateCard(leftGrid, new Thickness(14, 12, 14, 12));
            Grid.SetColumn(leftCard, 0);
            grid.Children.Add(leftCard);

            var rightGrid = new Grid();
            rightGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            rightGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });

            var rightTitle = new TextBlock
            {
                Text = "日志详细内容",
                FontSize = 14,
                FontWeight = FontWeights.Bold,
                Margin = new Thickness(0, 0, 0, 8)
            };
            Grid.SetRow(rightTitle, 0);
            rightGrid.Children.Add(rightTitle);

            _logContentBox = new TextBox
            {
                IsReadOnly = true,
                FontFamily = UiTheme.MonoFont,
                FontSize = 12,
                Background = UiTheme.BgSubtle,
                BorderBrush = UiTheme.BorderLight,
                BorderThickness = new Thickness(1),
                Padding = new Thickness(10),
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                HorizontalScrollBarVisibility = ScrollBarVisibility.Auto,
                Text = "暂无选中的清理日志。执行一次演练模式或真实清理后，完整审计日志将自动保存在这里。"
            };
            Grid.SetRow(_logContentBox, 1);
            rightGrid.Children.Add(_logContentBox);

            var rightCard = UiTheme.CreateCard(rightGrid, new Thickness(14, 12, 14, 12));
            Grid.SetColumn(rightCard, 2);
            grid.Children.Add(rightCard);

            return grid;
        }

        #endregion

        private UIElement BuildStatusBar()
        {
            var bar = new Border
            {
                Background = UiTheme.BgCard,
                BorderBrush = UiTheme.BorderLight,
                BorderThickness = new Thickness(0, 1, 0, 0),
                Padding = new Thickness(20, 7, 20, 7)
            };
            var dock = new DockPanel();
            _statusLeftText = new TextBlock
            {
                FontSize = 11.5,
                Foreground = UiTheme.TextSecondary,
                TextTrimming = TextTrimming.CharacterEllipsis
            };
            DockPanel.SetDock(_statusLeftText, Dock.Left);
            dock.Children.Add(_statusLeftText);

            _statusRightText = new TextBlock
            {
                FontSize = 11.5,
                Foreground = UiTheme.TextMuted,
                HorizontalAlignment = HorizontalAlignment.Right
            };
            DockPanel.SetDock(_statusRightText, Dock.Right);
            dock.Children.Add(_statusRightText);

            bar.Child = dock;
            return bar;
        }

        #region Scanning & Cleaning Actions

        private void OnScanButtonClicked()
        {
            if (_isBusy)
            {
                if (_cts != null) _cts.Cancel();
                return;
            }
            StartScanAsync();
        }

        private async void StartScanAsync()
        {
            if (_isBusy) return;
            _isBusy = true;
            _cts = new CancellationTokenSource();
            var sw = Stopwatch.StartNew();

            _scanBtn.Content = "停止扫描";
            _scanBtn.Template = UiTheme.BuildRoundedButtonTemplate(UiTheme.DangerRed, UiTheme.DangerRedHover, null, 8);
            _cleanBtn.IsEnabled = false;
            _heroProgress.IsIndeterminate = false;
            _heroProgress.Value = 4;
            _heroTitleText.Text = "正在高速并行扫描 C 盘垃圾与软件缓存...";
            _heroSubText.Text = "正在检测系统临时文件、浏览器缓存、常用软件与开发工具缓存...";

            var progress = new Progress<ScanProgressInfo>(info =>
            {
                double pct = info.TotalRules > 0 ? (double)info.CompletedRules * 100.0 / info.TotalRules : 0;
                _heroProgress.Value = Math.Max(5, pct);
                _heroSubText.Text = string.Format("并行扫描 ({0}/{1})：{2} — 已发现 {3}",
                    info.CompletedRules, info.TotalRules, info.CurrentRuleName, FormatHelper.FormatBytes(info.FoundBytesSoFar));
                UpdateStatusBar(string.Format("扫描中：{0}", info.CurrentRuleName));
            });

            try
            {
                _scanResults = await _engine.ScanAsync(_rules, progress, _cts.Token);
                sw.Stop();
                _heroProgress.Value = 100;
                RefreshDriveGauge();
                RenderRuleList();
                SelectFirstNonEmptyRule();
                UpdateHeroTotals();
                UpdateStatusBar(string.Format("扫描完成（耗时 {0:F2} 秒，{1:HH:mm:ss}）— 共检测 {2} 项规则",
                    sw.Elapsed.TotalSeconds, DateTime.Now, _scanResults.Count));
            }
            catch (OperationCanceledException)
            {
                _heroTitleText.Text = "扫描已取消";
                _heroSubText.Text = "可随时重新点击「一键智能扫描」。";
                _heroProgress.Value = 0;
                UpdateStatusBar("用户已取消扫描");
            }
            catch (Exception ex)
            {
                _heroTitleText.Text = "扫描出现异常";
                _heroSubText.Text = ex.Message;
                UpdateStatusBar("扫描失败：" + ex.Message);
            }
            finally
            {
                _isBusy = false;
                if (_cts != null)
                {
                    _cts.Dispose();
                    _cts = null;
                }
                _scanBtn.Content = "重新智能扫描";
                _scanBtn.Template = UiTheme.BuildRoundedButtonTemplate(UiTheme.AccentBlue, UiTheme.AccentBlueHover, null, 8);
                UpdateCleanButtonText();
            }
        }

        private async void OnCleanButtonClicked()
        {
            if (_isBusy) return;
            List<RuleScanResult> selected = _scanResults
                .Where(r => r.IsSelected && r.Items.Any(x => !x.IsAdvisory))
                .ToList();

            if (selected.Count == 0)
            {
                MessageBox.Show(this, "当前没有勾选可清理的项目。", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            bool isDryRun = _dryRunCheck.IsChecked == true;
            bool moveNonSafeToRecycle = _recycleMediumCheck.IsChecked == true;
            long selectedBytes = selected.Sum(r => r.TotalBytes);
            int selectedFiles = selected.Sum(r => r.FileCount);
            int nonSafeCount = selected.Count(r => r.Rule.Risk != RiskLevel.Safe);
            List<string> runningApps = selected
                .SelectMany(r => r.RunningProcesses)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            string runningHint = runningApps.Count > 0
                ? string.Format("\n• 检测到运行中的关联程序：{0}（被占用文件将自动安全跳过）", string.Join(", ", runningApps))
                : "";

            string recycleHint = (!isDryRun && nonSafeCount > 0 && moveNonSafeToRecycle)
                ? "\n• 保护策略：已开启「常用/开发缓存优先移入回收站（可撤销）」"
                : "";

            string confirmMsg = string.Format(
                "即将执行：{0}\n\n" +
                "• 选中规则数：{1} 项{2}\n" +
                "• 预计处理文件：{3} 个\n" +
                "• 预计释放空间：{4}{5}{6}\n\n" +
                "{7}",
                isDryRun ? "【演练模式】模拟清理（不会删除任何真实文件）" : "【真实清理】清理选中缓存与垃圾",
                selected.Count,
                nonSafeCount > 0 ? string.Format("（含 {0} 项按需勾选的软件/开发缓存）", nonSafeCount) : "（全部为安全推荐项）",
                selectedFiles,
                FormatHelper.FormatBytes(selectedBytes),
                runningHint,
                recycleHint,
                isDryRun ? "演练完成后将生成完整审计日志供核对。是否继续？" : "内置白名单与防误删保护已全程开启，确定开始一键清理吗？");

            MessageBoxResult answer = MessageBox.Show(
                this,
                confirmMsg,
                isDryRun ? "确认启动演练模式" : "确认一键智能清理",
                MessageBoxButton.YesNo,
                isDryRun ? MessageBoxImage.Information : MessageBoxImage.Question);

            if (answer != MessageBoxResult.Yes) return;

            _isBusy = true;
            _cts = new CancellationTokenSource();
            _scanBtn.Content = "中止清理";
            _scanBtn.Template = UiTheme.BuildRoundedButtonTemplate(UiTheme.DangerRed, UiTheme.DangerRedHover, null, 8);
            _cleanBtn.IsEnabled = false;
            _heroProgress.Value = 0;
            _heroTitleText.Text = isDryRun ? "正在执行模拟演练清理..." : "正在安全清理 C 盘空间...";

            var progress = new Progress<CleanProgressInfo>(info =>
            {
                double pct = info.TotalItems > 0 ? (double)info.ProcessedItems * 100.0 / info.TotalItems : 0;
                _heroProgress.Value = Math.Min(100, pct);
                _heroSubText.Text = string.Format("{0}：{1} — 已处理 {2}（跳过 {3} 项）",
                    isDryRun ? "演练中" : "清理中",
                    info.CurrentRuleName,
                    FormatHelper.FormatBytes(info.FreedBytesSoFar),
                    info.SkippedCount);
                UpdateStatusBar("处理中：" + info.CurrentFilePath);
            });

            var options = new CleanOptions
            {
                IsDryRun = isDryRun,
                MoveNonSafeToRecycleBin = moveNonSafeToRecycle,
                CoordinateWindowsUpdateService = true
            };

            try
            {
                CleanExecutionReport report = await _engine.CleanAsync(selected, options, progress, _cts.Token);
                _heroProgress.Value = 100;
                RefreshDriveGauge();
                RefreshLogsView();

                string summary = string.Format(
                    "{0}完成！\n\n" +
                    "• {1}空间：{2}\n" +
                    "• 彻底删除：{3} 个 | 移入回收站：{4} 个 | 清理空目录：{5} 个\n" +
                    "• 安全跳过：{6} 个（白名单/防误删拦截 {7} 个，占用或权限不足 {8} 个）\n\n" +
                    "完整无截断审计日志已自动保存，可前往「清理审计日志」查看。",
                    isDryRun ? "模拟演练" : "一键清理",
                    isDryRun ? "预计可释放" : "成功处理",
                    FormatHelper.FormatBytes(report.FreedBytes),
                    report.DeletedFiles,
                    report.RecycledFiles,
                    report.DeletedDirectories,
                    report.SkippedFiles,
                    report.ProtectedSkippedFiles,
                    report.LockedOrDeniedFiles);

                MessageBox.Show(this, summary, "清理报告", MessageBoxButton.OK, MessageBoxImage.Information);

                if (!isDryRun)
                {
                    _isBusy = false;
                    if (_cts != null) { _cts.Dispose(); _cts = null; }
                    StartScanAsync();
                    return;
                }
                else
                {
                    _heroTitleText.Text = string.Format("演练完成：预计可释放 {0}（未删除真实文件）", FormatHelper.FormatBytes(report.FreedBytes));
                    _heroSubText.Text = "可在「清理审计日志」中逐条审阅演练明细，确认无误后取消勾选「演练模式」即可真实清理。";
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, "清理过程中发生错误：" + ex.Message, "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                if (_isBusy)
                {
                    _isBusy = false;
                    if (_cts != null)
                    {
                        _cts.Dispose();
                        _cts = null;
                    }
                    _scanBtn.Content = "重新智能扫描";
                    _scanBtn.Template = UiTheme.BuildRoundedButtonTemplate(UiTheme.AccentBlue, UiTheme.AccentBlueHover, null, 8);
                    UpdateCleanButtonText();
                }
            }
        }

        #endregion

        #region UI Rendering & State Sync

        private void RefreshDriveGauge()
        {
            DriveUsageInfo info = CleanerEngine.GetCDriveUsage();
            _gaugeCanvas.Children.Clear();

            double pct = Math.Max(0, Math.Min(100, info.UsedPercent));
            SolidColorBrush ringBrush = pct >= 88
                ? UiTheme.DangerRed
                : (pct >= 75 ? UiTheme.WarnAmber : UiTheme.SafeGreen);

            var bgCircle = new Ellipse
            {
                Width = 88,
                Height = 88,
                Stroke = UiTheme.Brush("#E2E8F0"),
                StrokeThickness = 9
            };
            Canvas.SetLeft(bgCircle, 8);
            Canvas.SetTop(bgCircle, 8);
            _gaugeCanvas.Children.Add(bgCircle);

            double sweep = pct * 3.6;
            System.Windows.Shapes.Path arc = UiTheme.CreateArcPath(52, 52, 44, 0, sweep, ringBrush, 9);
            _gaugeCanvas.Children.Add(arc);

            _gaugePercentText.Text = string.Format("{0:F0}%", pct);
            _gaugePercentText.Foreground = ringBrush;
            _driveMetaText.Text = string.Format("可用 {0} / 共 {1}",
                FormatHelper.FormatBytes(info.FreeBytes),
                FormatHelper.FormatBytes(info.TotalBytes));
        }

        private void RenderRuleList()
        {
            _ruleListPanel.Children.Clear();

            IEnumerable<RuleScanResult> filtered = _scanResults;
            if (_activeCategoryFilter >= 0)
            {
                CleanCategory cat = (CleanCategory)_activeCategoryFilter;
                filtered = filtered.Where(r => r.Rule.Category == cat);
            }
            if (_onlyDetected)
            {
                filtered = filtered.Where(r => r.TotalBytes > 0 || r.Items.Any(x => x.IsAdvisory) || r.NeedsElevationForFullAccess);
            }

            List<RuleScanResult> list = filtered
                .OrderByDescending(r => r.TotalBytes)
                .ThenBy(r => (int)r.Rule.Category)
                .ToList();

            if (list.Count == 0)
            {
                _ruleListPanel.Children.Add(new TextBlock
                {
                    Text = _scanResults.Count == 0
                        ? "正在等待扫描结果..."
                        : "当前分类下暂无可清理的垃圾缓存（你的 C 盘非常干净！可取消勾选「仅显示已检测到项」查看全部规则）。",
                    FontSize = 13,
                    Foreground = UiTheme.TextMuted,
                    TextWrapping = TextWrapping.Wrap,
                    Margin = new Thickness(16, 28, 16, 16),
                    HorizontalAlignment = HorizontalAlignment.Center
                });
                return;
            }

            for (int i = 0; i < list.Count; i++)
            {
                _ruleListPanel.Children.Add(BuildRuleCard(list[i]));
            }
        }

        private Border BuildRuleCard(RuleScanResult result)
        {
            bool isActive = (_activeRuleResult == result);

            var card = new Border
            {
                Background = isActive ? UiTheme.AccentBlueSoft : UiTheme.BgCard,
                BorderBrush = isActive ? UiTheme.BorderFocus : UiTheme.BorderLight,
                BorderThickness = new Thickness(isActive ? 1.5 : 1),
                CornerRadius = new CornerRadius(10),
                Padding = new Thickness(12, 10, 12, 10),
                Margin = new Thickness(0, 0, 0, 8),
                Cursor = Cursors.Hand
            };

            var grid = new Grid();
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            bool hasActionable = result.Items.Any(x => !x.IsAdvisory);
            var chk = new CheckBox
            {
                IsChecked = result.IsSelected && hasActionable,
                IsEnabled = hasActionable,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 10, 0)
            };
            chk.Checked += delegate
            {
                result.IsSelected = true;
                UpdateHeroTotals();
            };
            chk.Unchecked += delegate
            {
                result.IsSelected = false;
                UpdateHeroTotals();
            };
            Grid.SetColumn(chk, 0);
            grid.Children.Add(chk);

            var midStack = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
            var titleRow = new WrapPanel { Orientation = Orientation.Horizontal };
            titleRow.Children.Add(new TextBlock
            {
                Text = result.Rule.Name,
                FontSize = 13.5,
                FontWeight = FontWeights.SemiBold,
                Foreground = UiTheme.TextPrimary,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 8, 2)
            });

            SolidColorBrush pillBg = result.Rule.Risk == RiskLevel.Safe
                ? UiTheme.SafeGreenSoft
                : (result.Rule.Risk == RiskLevel.Medium ? UiTheme.WarnAmberSoft : UiTheme.DangerRedSoft);
            SolidColorBrush pillFg = result.Rule.Risk == RiskLevel.Safe
                ? UiTheme.SafeGreenText
                : (result.Rule.Risk == RiskLevel.Medium ? UiTheme.WarnAmberText : UiTheme.DangerRedText);
            var riskPill = UiTheme.CreatePill(FormatHelper.RiskName(result.Rule.Risk), pillBg, pillFg);
            riskPill.Margin = new Thickness(0, 0, 6, 2);
            titleRow.Children.Add(riskPill);

            var catPill = UiTheme.CreatePill(FormatHelper.CategoryName(result.Rule.Category), UiTheme.BgSubtle, UiTheme.TextSecondary);
            catPill.Margin = new Thickness(0, 0, 6, 2);
            titleRow.Children.Add(catPill);

            if (result.Rule.RequiresAdmin || result.NeedsElevationForFullAccess)
            {
                var admPill = UiTheme.CreatePill("需管理员", UiTheme.AdminPurpleSoft, UiTheme.AdminPurpleText);
                admPill.Margin = new Thickness(0, 0, 6, 2);
                titleRow.Children.Add(admPill);
            }

            if (result.RunningProcesses != null && result.RunningProcesses.Count > 0)
            {
                var runPill = UiTheme.CreatePill(
                    "运行中: " + string.Join("/", result.RunningProcesses),
                    UiTheme.DangerRedSoft,
                    UiTheme.DangerRedText);
                runPill.Margin = new Thickness(0, 0, 6, 2);
                runPill.ToolTip = "该软件当前正在运行，建议关闭后再清理以释放更多被占用缓存";
                titleRow.Children.Add(runPill);
            }

            midStack.Children.Add(titleRow);

            string desc = !string.IsNullOrEmpty(result.StatusHint)
                ? result.StatusHint
                : result.Rule.Description;
            midStack.Children.Add(new TextBlock
            {
                Text = desc,
                FontSize = 11.5,
                Foreground = UiTheme.TextSecondary,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 3, 10, 0)
            });

            Grid.SetColumn(midStack, 1);
            grid.Children.Add(midStack);

            var rightStack = new StackPanel { VerticalAlignment = VerticalAlignment.Center, HorizontalAlignment = HorizontalAlignment.Right };
            rightStack.Children.Add(new TextBlock
            {
                Text = FormatHelper.FormatBytes(result.TotalBytes),
                FontSize = 14.5,
                FontWeight = FontWeights.Bold,
                Foreground = result.TotalBytes > 100L * 1024 * 1024 ? UiTheme.AccentBlue : UiTheme.TextPrimary,
                HorizontalAlignment = HorizontalAlignment.Right
            });
            rightStack.Children.Add(new TextBlock
            {
                Text = result.FileCount > 0
                    ? string.Format("{0} 个文件", result.FileCount)
                    : (result.Items.Any(x => x.IsAdvisory) ? "仅提示项" : "0 项"),
                FontSize = 11.5,
                Foreground = UiTheme.TextMuted,
                HorizontalAlignment = HorizontalAlignment.Right
            });
            Grid.SetColumn(rightStack, 2);
            grid.Children.Add(rightStack);

            card.Child = grid;
            card.MouseLeftButtonUp += delegate(object s, MouseButtonEventArgs e)
            {
                if (e.OriginalSource is CheckBox) return;
                _activeRuleResult = result;
                RenderRuleList();
                RefreshPreviewList();
            };

            return card;
        }

        private void SelectFirstNonEmptyRule()
        {
            _activeRuleResult = _scanResults
                .OrderByDescending(r => r.TotalBytes)
                .FirstOrDefault(r => r.Items.Count > 0);
            RefreshPreviewList();
        }

        private class PreviewRowViewModel
        {
            public ScannedFileItem Raw { get; set; }
            public string DisplayName { get { return Raw.DisplayName; } }
            public string SizeText { get { return FormatHelper.FormatBytes(Raw.SizeBytes); } }
            public string FullPath { get { return Raw.FullPath; } }
        }

        private void RefreshPreviewList()
        {
            if (_activeRuleResult == null)
            {
                _previewHeaderTitle.Text = "清理前文件预览";
                _previewSafetyNote.Text = "点击左侧任意清理项，即可在此逐条检查待删文件。";
                _previewListView.ItemsSource = null;
                _previewFooterHint.Text = "未选择清理项";
                UpdatePreviewActionButtons();
                return;
            }

            _previewHeaderTitle.Text = string.Format("预览：{0}", _activeRuleResult.Rule.Name);
            _previewSafetyNote.Text = string.Format("安全说明：{0}", _activeRuleResult.Rule.SafetyNote);

            string query = (_previewSearchBox.Text ?? "").Trim();
            IEnumerable<ScannedFileItem> seq = _activeRuleResult.Items;
            if (!string.IsNullOrEmpty(query))
            {
                seq = seq.Where(x =>
                    (x.DisplayName != null && x.DisplayName.IndexOf(query, StringComparison.OrdinalIgnoreCase) >= 0) ||
                    (x.FullPath != null && x.FullPath.IndexOf(query, StringComparison.OrdinalIgnoreCase) >= 0));
            }

            const int maxRender = 500;
            List<ScannedFileItem> matched = seq.ToList();
            List<PreviewRowViewModel> rows = matched
                .Take(maxRender)
                .Select(x => new PreviewRowViewModel { Raw = x })
                .ToList();

            _previewListView.ItemsSource = rows;
            if (matched.Count > maxRender)
            {
                _previewFooterHint.Text = string.Format("按体积降序显示前 {0} 项（共 {1} 项）", maxRender, matched.Count);
            }
            else
            {
                _previewFooterHint.Text = string.Format("共 {0} 项，总计 {1}",
                    matched.Count, FormatHelper.FormatBytes(matched.Where(x => !x.IsAdvisory).Sum(x => x.SizeBytes)));
            }
            UpdatePreviewActionButtons();
        }

        private void UpdatePreviewActionButtons()
        {
            var row = _previewListView.SelectedItem as PreviewRowViewModel;
            bool validFile = row != null && !row.Raw.IsRecycleBinEntry;
            _openLocationBtn.IsEnabled = validFile;
            _addToWhitelistBtn.IsEnabled = validFile && !row.Raw.IsAdvisory;
        }

        private void UpdateHeroTotals()
        {
            long totalFound = _scanResults.Sum(r => r.TotalBytes);
            long selectedBytes = _scanResults.Where(r => r.IsSelected).Sum(r => r.TotalBytes);
            int selectedFiles = _scanResults.Where(r => r.IsSelected).Sum(r => r.FileCount);
            int selectedRulesCount = _scanResults.Count(r => r.IsSelected && r.Items.Any(x => !x.IsAdvisory));

            if (totalFound == 0)
            {
                _heroTitleText.Text = "C 盘状态非常整洁，未发现明显可清理垃圾";
                _heroSubText.Text = "如需深度检测系统更新缓存，可点击右上角以管理员权限运行。";
            }
            else
            {
                _heroTitleText.Text = string.Format("已勾选可释放 {0}（共扫描发现 {1}）",
                    FormatHelper.FormatBytes(selectedBytes),
                    FormatHelper.FormatBytes(totalFound));
                _heroSubText.Text = string.Format("已勾选 {0} 类规则 / {1} 个文件。浏览器、常用软件与开发工具缓存默认未勾选，可按需手动选择。",
                    selectedRulesCount, selectedFiles);
            }

            UpdateCleanButtonText();
        }

        private void UpdateCleanButtonText()
        {
            long selectedBytes = _scanResults.Where(r => r.IsSelected).Sum(r => r.TotalBytes);
            bool hasSelected = !_isBusy && _scanResults.Any(r => r.IsSelected && r.Items.Any(x => !x.IsAdvisory));
            _cleanBtn.IsEnabled = hasSelected;

            bool isDryRun = _dryRunCheck.IsChecked == true;
            if (isDryRun)
            {
                _cleanBtn.Content = selectedBytes > 0
                    ? string.Format("演练模拟 ({0})", FormatHelper.FormatBytes(selectedBytes))
                    : "开始模拟演练";
                _cleanBtn.Template = UiTheme.BuildRoundedButtonTemplate(UiTheme.WarnAmber, UiTheme.Brush("#D97706"), null, 8);
            }
            else
            {
                _cleanBtn.Content = selectedBytes > 0
                    ? string.Format("一键清理 ({0})", FormatHelper.FormatBytes(selectedBytes))
                    : "一键安全清理";
                _cleanBtn.Template = UiTheme.BuildRoundedButtonTemplate(UiTheme.SafeGreen, UiTheme.SafeGreenHover, null, 8);
            }
        }

        private void ApplyQuickSelection(string mode)
        {
            for (int i = 0; i < _scanResults.Count; i++)
            {
                RuleScanResult r = _scanResults[i];
                bool inFilter = _activeCategoryFilter < 0 || (int)r.Rule.Category == _activeCategoryFilter;
                if (!inFilter) continue;

                bool hasActionable = r.Items.Any(x => !x.IsAdvisory);
                if (!hasActionable)
                {
                    r.IsSelected = false;
                    continue;
                }

                if (mode == "safe")
                {
                    r.IsSelected = r.Rule.DefaultSelected;
                }
                else if (mode == "all")
                {
                    r.IsSelected = true;
                }
                else if (mode == "none")
                {
                    r.IsSelected = false;
                }
            }

            RenderRuleList();
            UpdateHeroTotals();
        }

        #endregion

        #region Whitelist, Shortcut & Preview Helpers

        private void CreateDesktopShortcut()
        {
            try
            {
                string desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
                if (string.IsNullOrEmpty(desktop))
                {
                    desktop = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Desktop");
                }
                string exePath = Process.GetCurrentProcess().MainModule.FileName;
                string lnkPath = System.IO.Path.Combine(desktop, "C盘智清.lnk");

                Type shellType = Type.GetTypeFromProgID("WScript.Shell");
                object shell = Activator.CreateInstance(shellType);
                object shortcut = shellType.InvokeMember("CreateShortcut", System.Reflection.BindingFlags.InvokeMethod, null, shell, new object[] { lnkPath });
                Type scType = shortcut.GetType();
                scType.InvokeMember("TargetPath", System.Reflection.BindingFlags.SetProperty, null, shortcut, new object[] { exePath });
                scType.InvokeMember("WorkingDirectory", System.Reflection.BindingFlags.SetProperty, null, shortcut, new object[] { System.IO.Path.GetDirectoryName(exePath) });
                scType.InvokeMember("Description", System.Reflection.BindingFlags.SetProperty, null, shortcut, new object[] { "C盘智清 - Windows C盘一键智能安全清理工具" });
                scType.InvokeMember("IconLocation", System.Reflection.BindingFlags.SetProperty, null, shortcut, new object[] { exePath + ",0" });
                scType.InvokeMember("Save", System.Reflection.BindingFlags.InvokeMethod, null, shortcut, null);

                MessageBox.Show(this, "已在桌面创建「C盘智清」快捷方式！\n路径：" + lnkPath, "创建成功", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, "创建桌面快捷方式失败：" + ex.Message, "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        private void OnOpenSelectedPreviewLocation()
        {
            var row = _previewListView.SelectedItem as PreviewRowViewModel;
            if (row == null || string.IsNullOrEmpty(row.FullPath)) return;

            try
            {
                if (File.Exists(row.FullPath))
                {
                    Process.Start("explorer.exe", string.Format("/select,\"{0}\"", row.FullPath));
                }
                else
                {
                    string dir = System.IO.Path.GetDirectoryName(row.FullPath);
                    if (Directory.Exists(dir))
                    {
                        Process.Start("explorer.exe", string.Format("\"{0}\"", dir));
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, "无法打开目录：" + ex.Message, "提示", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        private void OnAddSelectedPreviewToWhitelist()
        {
            var row = _previewListView.SelectedItem as PreviewRowViewModel;
            if (row == null || string.IsNullOrEmpty(row.FullPath)) return;

            string path = row.FullPath;
            bool added = _guard.AddWhitelistEntry(path, "从清理预览列表添加保护");
            if (added)
            {
                for (int i = 0; i < _scanResults.Count; i++)
                {
                    RuleScanResult rr = _scanResults[i];
                    int removed = rr.Items.RemoveAll(item =>
                    {
                        string reason;
                        return !item.IsRecycleBinEntry && !item.IsAdvisory && _guard.IsProtected(item.FullPath, out reason);
                    });
                    if (removed > 0)
                    {
                        rr.FileCount = rr.Items.Count(x => !x.IsAdvisory);
                        rr.TotalBytes = rr.Items.Where(x => !x.IsAdvisory).Sum(x => x.SizeBytes);
                        rr.SkippedProtectedCount += removed;
                    }
                }

                RenderRuleList();
                RefreshPreviewList();
                RefreshWhitelistView();
                UpdateHeroTotals();
                UpdateStatusBar("已加入白名单保护：" + path);
            }
            else
            {
                MessageBox.Show(this, "该路径已在白名单中。", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        private void BrowseFolderForWhitelist()
        {
            using (var dlg = new System.Windows.Forms.FolderBrowserDialog())
            {
                dlg.Description = "选择要加入白名单永久保护的文件夹";
                dlg.ShowNewFolderButton = false;
                if (dlg.ShowDialog() == System.Windows.Forms.DialogResult.OK)
                {
                    _wlPatternInput.Text = dlg.SelectedPath;
                }
            }
        }

        private void AddManualWhitelistRule()
        {
            string pattern = (_wlPatternInput.Text ?? "").Trim();
            if (string.IsNullOrEmpty(pattern))
            {
                MessageBox.Show(this, "请输入要保护的路径或通配符（例如 *.sqlite 或完整文件夹路径）。", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            if (_guard.AddWhitelistEntry(pattern, _wlNoteInput.Text))
            {
                _wlPatternInput.Text = "";
                RefreshWhitelistView();
                UpdateStatusBar("已新增白名单规则：" + pattern);
            }
            else
            {
                MessageBox.Show(this, "该白名单规则已存在。", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        private void RemoveSelectedWhitelistRule()
        {
            var entry = _wlListView.SelectedItem as WhitelistEntry;
            if (entry == null)
            {
                MessageBox.Show(this, "请先在列表中选中一条要移除的白名单规则。", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            if (_guard.RemoveWhitelistEntry(entry.Pattern))
            {
                RefreshWhitelistView();
                UpdateStatusBar("已移除白名单规则：" + entry.Pattern);
            }
        }

        private void RefreshWhitelistView()
        {
            List<WhitelistEntry> entries = _guard.GetWhitelistEntries();
            _wlListView.ItemsSource = entries;
            UpdateStatusBar(null);
        }

        private void RefreshLogsView()
        {
            List<FileInfo> files = _guard.GetLogFiles();
            _logsListBox.ItemsSource = files;
            _logsListBox.DisplayMemberPath = "Name";
            if (files.Count > 0 && _logsListBox.SelectedIndex < 0)
            {
                _logsListBox.SelectedIndex = 0;
            }
        }

        private void LoadSelectedLogFile()
        {
            var fi = _logsListBox.SelectedItem as FileInfo;
            if (fi == null || !fi.Exists)
            {
                return;
            }

            try
            {
                _logContentBox.Text = File.ReadAllText(fi.FullName);
            }
            catch (Exception ex)
            {
                _logContentBox.Text = "读取日志失败：" + ex.Message;
            }
        }

        private void UpdateStatusBar(string leftMessage)
        {
            if (leftMessage != null)
            {
                _statusLeftText.Text = leftMessage;
            }
            int wlCount = _guard.GetWhitelistEntries().Count;
            _statusRightText.Text = string.Format("内置防误删保护已开启 · 自定义白名单 {0} 条 · v2.0.0", wlCount);
        }

        private void RestartAsAdministrator()
        {
            try
            {
                PersistSettings();
                string exePath = Process.GetCurrentProcess().MainModule.FileName;
                var psi = new ProcessStartInfo
                {
                    FileName = exePath,
                    UseShellExecute = true,
                    Verb = "runas"
                };
                Process.Start(psi);
                Application.Current.Shutdown();
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, "未能获取管理员权限：" + ex.Message, "提权取消", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        private void OpenFolderInExplorer(string dir)
        {
            try
            {
                Directory.CreateDirectory(dir);
                Process.Start("explorer.exe", string.Format("\"{0}\"", dir));
            }
            catch
            {
            }
        }

        #endregion
    }
}
