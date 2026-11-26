using System;
using System.Runtime.InteropServices;
using System.Threading;
using System.Windows;

namespace SmartCCleaner
{
    public static class Program
    {
        private const string SingleInstanceMutexName = "Local\\SmartCCleaner_SingleInstance_Mutex_v2";
        public const string MainWindowTitle = "C盘智清 (SmartCCleaner v2.0) - Windows 智能安全清理工具";

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern IntPtr FindWindowW(string lpClassName, string lpWindowName);

        [DllImport("user32.dll")]
        private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        [DllImport("user32.dll")]
        private static extern bool SetForegroundWindow(IntPtr hWnd);

        private const int SW_RESTORE = 9;

        [STAThread]
        public static void Main(string[] args)
        {
            bool createdNew;
            using (var mutex = new Mutex(true, SingleInstanceMutexName, out createdNew))
            {
                if (!createdNew)
                {
                    IntPtr existing = FindWindowW(null, MainWindowTitle);
                    if (existing != IntPtr.Zero)
                    {
                        ShowWindow(existing, SW_RESTORE);
                        SetForegroundWindow(existing);
                    }
                    else
                    {
                        MessageBox.Show(
                            "「C盘智清」已经在运行中，请勿同时打开多个清理窗口。",
                            "C盘智清",
                            MessageBoxButton.OK,
                            MessageBoxImage.Information);
                    }
                    return;
                }

                var app = new Application();
                app.ShutdownMode = ShutdownMode.OnMainWindowClose;

                app.DispatcherUnhandledException += delegate(object sender, System.Windows.Threading.DispatcherUnhandledExceptionEventArgs e)
                {
                    MessageBox.Show(
                        "程序遇到未处理异常，但已安全拦截不会影响系统文件：\n\n" + e.Exception.Message,
                        "C盘智清 - 异常保护",
                        MessageBoxButton.OK,
                        MessageBoxImage.Warning);
                    e.Handled = true;
                };

                var win = new MainWindow();
                app.MainWindow = win;
                app.Run(win);
            }
        }
    }
}
