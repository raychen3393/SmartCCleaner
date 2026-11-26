using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;

namespace SmartCCleaner
{
    public struct NativeFileEntry
    {
        public string FullPath;
        public string Name;
        public long SizeBytes;
        public DateTime LastWriteTime;
        public FileAttributes Attributes;
        public bool IsDirectory;
        public bool IsReparsePoint;
    }

    /// <summary>
    /// High-performance Win32 FindFirstFileExW enumerator with extended-length (\\?\) path support
    /// and safe Recycle Bin / long-path deletion helpers.
    /// </summary>
    public static class NativeFileScanner
    {
        private static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
        private const int FIND_FIRST_EX_LARGE_FETCH = 2;
        private const int FindExInfoBasic = 1;
        private const int FindExSearchNameMatch = 0;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WIN32_FIND_DATAW
        {
            public uint dwFileAttributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME ftCreationTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME ftLastAccessTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME ftLastWriteTime;
            public uint nFileSizeHigh;
            public uint nFileSizeLow;
            public uint dwReserved0;
            public uint dwReserved1;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string cFileName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 14)]
            public string cAlternateFileName;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr FindFirstFileExW(
            string lpFileName,
            int fInfoLevelId,
            out WIN32_FIND_DATAW lpFindFileData,
            int fSearchOp,
            IntPtr lpSearchFilter,
            int dwAdditionalFlags);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool FindNextFileW(IntPtr hFindFile, out WIN32_FIND_DATAW lpFindFileData);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool FindClose(IntPtr hFindFile);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint GetFileAttributesW(string lpFileName);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool SetFileAttributesW(string lpFileName, uint dwFileAttributes);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool DeleteFileW(string lpFileName);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool RemoveDirectoryW(string lpPathName);

        private const uint INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF;
        private const uint FILE_ATTRIBUTE_READONLY = 0x00000001;
        private const uint FILE_ATTRIBUTE_DIRECTORY = 0x00000010;
        private const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct SHFILEOPSTRUCTW
        {
            public IntPtr hwnd;
            public uint wFunc;
            public string pFrom;
            public string pTo;
            public ushort fFlags;
            public bool fAnyOperationsAborted;
            public IntPtr hNameMappings;
            public string lpszProgressTitle;
        }

        [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
        private static extern int SHFileOperationW(ref SHFILEOPSTRUCTW FileOp);

        private const uint FO_DELETE = 0x0003;
        private const ushort FOF_SILENT = 0x0004;
        private const ushort FOF_NOCONFIRMATION = 0x0010;
        private const ushort FOF_ALLOWUNDO = 0x0040;
        private const ushort FOF_NOERRORUI = 0x0400;

        public static string ToExtendedPath(string path)
        {
            if (string.IsNullOrEmpty(path)) return path;
            if (path.StartsWith(@"\\?\")) return path;
            if (path.StartsWith(@"\\"))
            {
                return @"\\?\UNC\" + path.Substring(2);
            }
            return @"\\?\" + path;
        }

        public static bool IsReparsePointFast(string path)
        {
            uint attrs = GetFileAttributesW(ToExtendedPath(path));
            if (attrs == INVALID_FILE_ATTRIBUTES) return false;
            return (attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
        }

        public static bool FileExistsFast(string path)
        {
            uint attrs = GetFileAttributesW(ToExtendedPath(path));
            return attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0;
        }

        /// <summary>
        /// Enumerates direct children of a directory in a single Win32 pass (with long-path support).
        /// </summary>
        public static bool TryEnumerateChildren(string dirPath, string searchPattern, List<NativeFileEntry> output, out bool accessDenied)
        {
            accessDenied = false;
            string pat = string.IsNullOrEmpty(searchPattern) ? "*" : searchPattern;
            string cleanDir = dirPath.EndsWith("\\") ? dirPath.TrimEnd('\\') : dirPath;
            string query = ToExtendedPath(cleanDir + "\\" + pat);

            WIN32_FIND_DATAW findData;
            IntPtr handle = FindFirstFileExW(
                query,
                FindExInfoBasic,
                out findData,
                FindExSearchNameMatch,
                IntPtr.Zero,
                FIND_FIRST_EX_LARGE_FETCH);

            if (handle == INVALID_HANDLE_VALUE)
            {
                int err = Marshal.GetLastWin32Error();
                if (err == 5) // ERROR_ACCESS_DENIED
                {
                    accessDenied = true;
                }
                return false;
            }

            try
            {
                do
                {
                    string name = findData.cFileName;
                    if (name == "." || name == "..") continue;

                    bool isDir = (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
                    bool isReparse = (findData.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
                    long size = isDir ? 0L : (((long)findData.nFileSizeHigh << 32) | (long)findData.nFileSizeLow);

                    long ft = (((long)findData.ftLastWriteTime.dwHighDateTime << 32) | (uint)findData.ftLastWriteTime.dwLowDateTime);
                    DateTime lwt;
                    try
                    {
                        lwt = DateTime.FromFileTime(ft);
                    }
                    catch
                    {
                        lwt = DateTime.MinValue;
                    }

                    output.Add(new NativeFileEntry
                    {
                        FullPath = cleanDir + "\\" + name,
                        Name = name,
                        SizeBytes = size,
                        LastWriteTime = lwt,
                        Attributes = (FileAttributes)findData.dwFileAttributes,
                        IsDirectory = isDir,
                        IsReparsePoint = isReparse
                    });
                }
                while (FindNextFileW(handle, out findData));
            }
            finally
            {
                FindClose(handle);
            }

            return true;
        }

        /// <summary>
        /// Deletes a file with automatic long-path (\\?\) and ReadOnly attribute handling.
        /// </summary>
        public static bool TryDeleteFileLongPath(string fullPath, out string errorMessage)
        {
            errorMessage = null;
            string ext = ToExtendedPath(fullPath);

            uint attrs = GetFileAttributesW(ext);
            if (attrs == INVALID_FILE_ATTRIBUTES)
            {
                return true; // already gone
            }
            if ((attrs & FILE_ATTRIBUTE_READONLY) != 0)
            {
                SetFileAttributesW(ext, attrs & ~FILE_ATTRIBUTE_READONLY);
            }

            if (DeleteFileW(ext))
            {
                return true;
            }

            int err = Marshal.GetLastWin32Error();
            errorMessage = string.Format("Win32 Error {0}", err);
            return false;
        }

        public static bool TryRemoveEmptyDirectoryLongPath(string fullPath)
        {
            string ext = ToExtendedPath(fullPath);
            uint attrs = GetFileAttributesW(ext);
            if (attrs == INVALID_FILE_ATTRIBUTES) return false;
            if ((attrs & FILE_ATTRIBUTE_READONLY) != 0)
            {
                SetFileAttributesW(ext, attrs & ~FILE_ATTRIBUTE_READONLY);
            }
            return RemoveDirectoryW(ext);
        }

        /// <summary>
        /// Moves a file to Windows Recycle Bin (undoable). Falls back to false if long path > 259 chars or locked.
        /// </summary>
        public static bool TryMoveToRecycleBin(string fullPath, out string errorMessage)
        {
            errorMessage = null;
            if (string.IsNullOrEmpty(fullPath) || fullPath.Length >= 258)
            {
                errorMessage = "路径过长不支持移入回收站";
                return false;
            }

            try
            {
                var op = new SHFILEOPSTRUCTW
                {
                    hwnd = IntPtr.Zero,
                    wFunc = FO_DELETE,
                    pFrom = fullPath + "\0\0",
                    pTo = null,
                    fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT | FOF_NOERRORUI
                };
                int res = SHFileOperationW(ref op);
                if (res == 0 && !op.fAnyOperationsAborted)
                {
                    return true;
                }
                errorMessage = string.Format("SHFileOperation code {0}", res);
                return false;
            }
            catch (Exception ex)
            {
                errorMessage = ex.Message;
                return false;
            }
        }
    }
}
