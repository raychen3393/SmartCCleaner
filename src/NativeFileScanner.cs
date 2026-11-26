using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace SmartCCleaner
{
    /// <summary>
    /// 基于句柄的安全删除/重命名结果。
    /// </summary>
    public enum SafeOpOutcome
    {
        Done,
        AlreadyGone,
        /// <summary>真实路径与扫描时的路径不一致（祖先目录被替换成了目录联接/符号链接）。</summary>
        Redirected,
        /// <summary>真实路径受保护，或目标本身是重解析点。</summary>
        Protected,
        /// <summary>扫描之后文件又被修改过，进入了「最近 N 分钟内」的保护期。</summary>
        TooRecent,
        /// <summary>被占用、无权限或目录非空。</summary>
        Failed
    }

    /// <summary>
    /// 整树安全删除的统计信息。
    /// </summary>
    public class TreeDeleteStats
    {
        private const int MaxNotes = 200;

        public int DeletedFiles;
        public long DeletedBytes;
        public int Failures;
        public readonly List<string> Notes = new List<string>();

        public void AddFailure(string path, string detail)
        {
            Failures++;
            if (Notes.Count < MaxNotes)
            {
                Notes.Add(string.Format("{0} ({1})", path, detail));
            }
        }
    }

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

        #region Handle-based safe operations (junction / TOCTOU hardening)

        // 旧实现按路径调用 DeleteFileW / RemoveDirectoryW，只检查了路径最后一级是否为重解析点。
        // 若扫描结束后某个祖先目录被替换成目录联接（例如普通用户可写的 C:\Windows\Temp），
        // 以管理员运行的清理就会顺着联接删到别处。新实现：
        //   1. 以 FILE_FLAG_OPEN_REPARSE_POINT 打开对象本身（不跟随最后一级链接）；
        //   2. 用 GetFinalPathNameByHandleW 取得句柄指向的真实路径，必须与扫描时路径完全一致，且不受保护；
        //   3. 通过同一个句柄设置 FileDispositionInfo 删除——校验与删除作用于同一个对象，没有竞态窗口。

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateFileW(
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            IntPtr lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint GetFinalPathNameByHandleW(IntPtr hFile, StringBuilder lpszFilePath, uint cchFilePath, uint dwFlags);

        [StructLayout(LayoutKind.Sequential)]
        private struct FILE_BASIC_INFO
        {
            public long CreationTime;
            public long LastAccessTime;
            public long LastWriteTime;
            public long ChangeTime;
            public uint FileAttributes;
        }

        [DllImport("kernel32.dll", EntryPoint = "GetFileInformationByHandleEx", SetLastError = true)]
        private static extern bool GetFileBasicInfoByHandle(IntPtr hFile, int fileInformationClass, out FILE_BASIC_INFO info, uint bufferSize);

        [DllImport("kernel32.dll", EntryPoint = "SetFileInformationByHandle", SetLastError = true)]
        private static extern bool SetFileBasicInfoByHandle(IntPtr hFile, int fileInformationClass, ref FILE_BASIC_INFO info, uint bufferSize);

        [DllImport("kernel32.dll", EntryPoint = "SetFileInformationByHandle", SetLastError = true)]
        private static extern bool SetFileDispositionByHandle(IntPtr hFile, int fileInformationClass, ref byte deleteFile, uint bufferSize);

        [DllImport("kernel32.dll", EntryPoint = "SetFileInformationByHandle", SetLastError = true)]
        private static extern bool SetFileInfoRaw(IntPtr hFile, int fileInformationClass, IntPtr buffer, uint bufferSize);

        private const uint ACCESS_DELETE = 0x00010000;
        private const uint ACCESS_READ_ATTRIBUTES = 0x00000080;
        private const uint ACCESS_WRITE_ATTRIBUTES = 0x00000100;
        private const uint FILE_SHARE_ALL = 0x00000007;
        private const uint OPEN_EXISTING = 3;
        private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
        private const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
        private const uint FILE_ATTRIBUTE_NORMAL = 0x00000080;
        private const uint FILE_ATTRIBUTE_VALID_SET_FLAGS = 0x000031A7;

        private const int FileBasicInfoClass = 0;
        private const int FileRenameInfoClass = 3;
        private const int FileDispositionInfoClass = 4;

        private const int ERROR_FILE_NOT_FOUND = 2;
        private const int ERROR_PATH_NOT_FOUND = 3;
        private const int ERROR_ACCESS_DENIED = 5;
        private const int ERROR_SHARING_VIOLATION = 32;
        private const int ERROR_DIR_NOT_EMPTY = 145;

        /// <summary>
        /// Opens the object itself (never follows a reparse point in the LAST component).
        /// Intermediate components may still be redirected, which is why callers must verify the final path.
        /// </summary>
        private static IntPtr OpenNoFollow(string path, uint access, out int error)
        {
            IntPtr h = CreateFileW(
                ToExtendedPath(path),
                access,
                FILE_SHARE_ALL,
                IntPtr.Zero,
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
                IntPtr.Zero);
            error = h == INVALID_HANDLE_VALUE ? Marshal.GetLastWin32Error() : 0;
            return h;
        }

        /// <summary>
        /// Returns the real DOS path the handle points to (without the \\?\ prefix), or null.
        /// </summary>
        private static string GetFinalPath(IntPtr handle)
        {
            var sb = new StringBuilder(512);
            uint n = GetFinalPathNameByHandleW(handle, sb, (uint)sb.Capacity, 0);
            if (n == 0) return null;
            if (n >= sb.Capacity)
            {
                sb = new StringBuilder((int)n + 1);
                n = GetFinalPathNameByHandleW(handle, sb, (uint)sb.Capacity, 0);
                if (n == 0 || n >= sb.Capacity) return null;
            }

            string p = sb.ToString();
            if (p.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
            {
                return @"\\" + p.Substring(8);
            }
            if (p.StartsWith(@"\\?\"))
            {
                return p.Substring(4);
            }
            return p;
        }

        private static string DescribeOpenError(int err)
        {
            if (err == ERROR_SHARING_VIOLATION) return "文件正被其他程序占用";
            if (err == ERROR_ACCESS_DENIED) return "无权限或正被占用";
            return string.Format("Win32 Error {0}", err);
        }

        /// <summary>
        /// Verifies that an opened handle is exactly the object scanned at <paramref name="expectedPath"/>:
        /// not a reparse point, same file/directory type, same real path, and not protected by the guard.
        /// </summary>
        private static SafeOpOutcome ValidateHandle(
            IntPtr handle,
            string expectedPath,
            bool expectDirectory,
            SafetyGuard guard,
            DateTime modifiedNotAfterUtc,
            out FILE_BASIC_INFO basic,
            out string detail)
        {
            detail = null;
            if (!GetFileBasicInfoByHandle(handle, FileBasicInfoClass, out basic, (uint)Marshal.SizeOf(typeof(FILE_BASIC_INFO))))
            {
                detail = string.Format("读取属性失败 Win32 Error {0}", Marshal.GetLastWin32Error());
                return SafeOpOutcome.Failed;
            }

            if ((basic.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
            {
                detail = "目标本身是符号链接/目录联接";
                return SafeOpOutcome.Protected;
            }

            bool isDirectory = (basic.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
            if (isDirectory != expectDirectory)
            {
                detail = "对象类型与扫描时不一致";
                return SafeOpOutcome.Redirected;
            }

            // 时间取自同一句柄：扫描后被重新写入（例如安装程序正在使用的临时文件）就不再删除。
            if (modifiedNotAfterUtc != DateTime.MaxValue && basic.LastWriteTime > 0)
            {
                DateTime lastWriteUtc = DateTime.FromFileTimeUtc(basic.LastWriteTime);
                if (lastWriteUtc > modifiedNotAfterUtc)
                {
                    detail = string.Format("扫描后被修改（{0:yyyy-MM-dd HH:mm:ss}），仍在保护期内", lastWriteUtc.ToLocalTime());
                    return SafeOpOutcome.TooRecent;
                }
            }

            string finalPath = GetFinalPath(handle);
            if (finalPath == null)
            {
                detail = "无法解析真实路径";
                return SafeOpOutcome.Failed;
            }

            string expected = SafetyGuard.NormalizePath(expectedPath);
            if (!string.Equals(finalPath, expected, StringComparison.OrdinalIgnoreCase))
            {
                detail = "真实路径被重定向至 " + finalPath;
                return SafeOpOutcome.Redirected;
            }

            if (guard != null)
            {
                string reason;
                if (guard.IsProtected(finalPath, out reason))
                {
                    detail = reason;
                    return SafeOpOutcome.Protected;
                }
            }

            return SafeOpOutcome.Done;
        }

        /// <summary>
        /// Verifies a path without modifying it (used right before shell operations such as Recycle Bin moves).
        /// </summary>
        public static SafeOpOutcome VerifyPath(string fullPath, bool isDirectory, SafetyGuard guard, out string detail)
        {
            return VerifyPath(fullPath, isDirectory, guard, DateTime.MaxValue, out detail);
        }

        /// <param name="modifiedNotAfterUtc">拒绝在此时间之后修改过的对象；DateTime.MaxValue 表示不检查。</param>
        public static SafeOpOutcome VerifyPath(string fullPath, bool isDirectory, SafetyGuard guard, DateTime modifiedNotAfterUtc, out string detail)
        {
            detail = null;
            int err;
            IntPtr h = OpenNoFollow(fullPath, ACCESS_READ_ATTRIBUTES, out err);
            if (h == INVALID_HANDLE_VALUE)
            {
                if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND) return SafeOpOutcome.AlreadyGone;
                detail = DescribeOpenError(err);
                return SafeOpOutcome.Failed;
            }

            try
            {
                FILE_BASIC_INFO basic;
                return ValidateHandle(h, fullPath, isDirectory, guard, modifiedNotAfterUtc, out basic, out detail);
            }
            finally
            {
                CloseHandle(h);
            }
        }

        /// <summary>
        /// Deletes a file (or an EMPTY directory) after validating its real path through the same handle.
        /// Clears the ReadOnly attribute when needed; long paths supported.
        /// </summary>
        public static SafeOpOutcome TrySafeDelete(string fullPath, bool isDirectory, SafetyGuard guard, out string detail)
        {
            return TrySafeDelete(fullPath, isDirectory, guard, DateTime.MaxValue, out detail);
        }

        /// <param name="modifiedNotAfterUtc">拒绝删除在此时间之后修改过的对象；DateTime.MaxValue 表示不检查。</param>
        public static SafeOpOutcome TrySafeDelete(string fullPath, bool isDirectory, SafetyGuard guard, DateTime modifiedNotAfterUtc, out string detail)
        {
            detail = null;
            int err;
            IntPtr h = OpenNoFollow(fullPath, ACCESS_DELETE | ACCESS_READ_ATTRIBUTES | ACCESS_WRITE_ATTRIBUTES, out err);
            if (h == INVALID_HANDLE_VALUE && err == ERROR_ACCESS_DENIED)
            {
                // Some ACLs grant DELETE (via the parent's FILE_DELETE_CHILD) without FILE_WRITE_ATTRIBUTES.
                h = OpenNoFollow(fullPath, ACCESS_DELETE | ACCESS_READ_ATTRIBUTES, out err);
            }
            if (h == INVALID_HANDLE_VALUE)
            {
                if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND) return SafeOpOutcome.AlreadyGone;
                detail = DescribeOpenError(err);
                return SafeOpOutcome.Failed;
            }

            try
            {
                FILE_BASIC_INFO basic;
                SafeOpOutcome check = ValidateHandle(h, fullPath, isDirectory, guard, modifiedNotAfterUtc, out basic, out detail);
                if (check != SafeOpOutcome.Done) return check;
                return DeleteThroughHandle(h, basic, out detail);
            }
            finally
            {
                CloseHandle(h);
            }
        }

        private static SafeOpOutcome DeleteThroughHandle(IntPtr handle, FILE_BASIC_INFO basic, out string detail)
        {
            detail = null;
            uint basicSize = (uint)Marshal.SizeOf(typeof(FILE_BASIC_INFO));
            bool clearedReadOnly = false;

            if ((basic.FileAttributes & FILE_ATTRIBUTE_READONLY) != 0)
            {
                // Zero timestamps mean "leave unchanged".
                var update = new FILE_BASIC_INFO();
                update.FileAttributes = basic.FileAttributes & FILE_ATTRIBUTE_VALID_SET_FLAGS & ~FILE_ATTRIBUTE_READONLY;
                if (update.FileAttributes == 0) update.FileAttributes = FILE_ATTRIBUTE_NORMAL;
                clearedReadOnly = SetFileBasicInfoByHandle(handle, FileBasicInfoClass, ref update, basicSize);
            }

            byte deleteFlag = 1;
            if (SetFileDispositionByHandle(handle, FileDispositionInfoClass, ref deleteFlag, 1))
            {
                return SafeOpOutcome.Done;
            }

            int err = Marshal.GetLastWin32Error();
            if (clearedReadOnly)
            {
                var restore = new FILE_BASIC_INFO();
                restore.FileAttributes = basic.FileAttributes & FILE_ATTRIBUTE_VALID_SET_FLAGS;
                if (restore.FileAttributes == 0) restore.FileAttributes = FILE_ATTRIBUTE_NORMAL;
                SetFileBasicInfoByHandle(handle, FileBasicInfoClass, ref restore, basicSize);
            }

            detail = err == ERROR_DIR_NOT_EMPTY ? "目录非空" : string.Format("Win32 Error {0}", err);
            return SafeOpOutcome.Failed;
        }

        /// <summary>
        /// Atomically renames a directory to a sibling name through a validated handle.
        /// Fails as a whole (nothing changes) when any file inside the tree is open by another program,
        /// which makes it a reliable "is this package in use?" gate.
        /// </summary>
        public static SafeOpOutcome TryRenameDirectorySafe(
            string dirPath,
            string newLeafName,
            SafetyGuard guard,
            out string newFullPath,
            out string detail)
        {
            newFullPath = null;
            detail = null;

            string norm = SafetyGuard.NormalizePath(dirPath);
            int slash = norm.LastIndexOf('\\');
            if (slash <= 2 || string.IsNullOrEmpty(newLeafName) || newLeafName.IndexOf('\\') >= 0)
            {
                detail = "不允许重命名该目录";
                return SafeOpOutcome.Protected;
            }
            string target = norm.Substring(0, slash) + "\\" + newLeafName;

            int err;
            IntPtr h = OpenNoFollow(norm, ACCESS_DELETE | ACCESS_READ_ATTRIBUTES, out err);
            if (h == INVALID_HANDLE_VALUE)
            {
                if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND) return SafeOpOutcome.AlreadyGone;
                detail = DescribeOpenError(err);
                return SafeOpOutcome.Failed;
            }

            try
            {
                FILE_BASIC_INFO basic;
                SafeOpOutcome check = ValidateHandle(h, norm, true, guard, DateTime.MaxValue, out basic, out detail);
                if (check != SafeOpOutcome.Done) return check;

                if (!RenameThroughHandle(h, ToExtendedPath(target), out err))
                {
                    detail = err == ERROR_ACCESS_DENIED || err == ERROR_SHARING_VIOLATION
                        ? "目录内有文件正被其他程序占用"
                        : string.Format("Win32 Error {0}", err);
                    return SafeOpOutcome.Failed;
                }

                // Confirm where the directory actually landed before anybody deletes it.
                string landed = GetFinalPath(h);
                if (landed == null || !string.Equals(landed, target, StringComparison.OrdinalIgnoreCase))
                {
                    detail = "重命名后真实路径异常：" + (landed ?? "未知");
                    return SafeOpOutcome.Redirected;
                }

                newFullPath = target;
                return SafeOpOutcome.Done;
            }
            finally
            {
                CloseHandle(h);
            }
        }

        private static bool RenameThroughHandle(IntPtr handle, string absoluteTargetPath, out int error)
        {
            // FILE_RENAME_INFO { union { BOOLEAN ReplaceIfExists; DWORD Flags; }; HANDLE RootDirectory; DWORD FileNameLength; WCHAR FileName[1]; }
            // The union is padded to pointer alignment. Only absolute paths are accepted when RootDirectory is NULL.
            int rootOffset = IntPtr.Size;
            int lengthOffset = rootOffset + IntPtr.Size;
            int nameOffset = lengthOffset + 4;
            byte[] nameBytes = Encoding.Unicode.GetBytes(absoluteTargetPath);
            int size = nameOffset + nameBytes.Length + 2;

            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                for (int i = 0; i < size; i++)
                {
                    Marshal.WriteByte(buffer, i, 0);
                }
                Marshal.WriteIntPtr(buffer, rootOffset, IntPtr.Zero);
                Marshal.WriteInt32(buffer, lengthOffset, nameBytes.Length);
                Marshal.Copy(nameBytes, 0, IntPtr.Add(buffer, nameOffset), nameBytes.Length);

                bool ok = SetFileInfoRaw(handle, FileRenameInfoClass, buffer, (uint)size);
                error = ok ? 0 : Marshal.GetLastWin32Error();
                return ok;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        /// <summary>
        /// Deletes a whole directory tree. Never descends into reparse points (they are left in place),
        /// and every file/directory is validated through its own handle before deletion.
        /// </summary>
        public static void DeleteTreeSafe(string rootDir, SafetyGuard guard, TreeDeleteStats stats)
        {
            var children = new List<NativeFileEntry>();
            bool denied;
            TryEnumerateChildren(rootDir, "*", children, out denied);
            if (denied)
            {
                stats.AddFailure(rootDir, "无权限枚举");
            }

            for (int i = 0; i < children.Count; i++)
            {
                NativeFileEntry child = children[i];
                if (child.IsReparsePoint)
                {
                    stats.AddFailure(child.FullPath, "符号链接/目录联接，保留不跟随");
                    continue;
                }

                if (child.IsDirectory)
                {
                    DeleteTreeSafe(child.FullPath, guard, stats);
                    continue;
                }

                string detail;
                SafeOpOutcome r = TrySafeDelete(child.FullPath, false, guard, out detail);
                if (r == SafeOpOutcome.Done)
                {
                    stats.DeletedFiles++;
                    stats.DeletedBytes += child.SizeBytes;
                }
                else if (r != SafeOpOutcome.AlreadyGone)
                {
                    stats.AddFailure(child.FullPath, detail);
                }
            }

            string dirDetail;
            SafeOpOutcome dirResult = TrySafeDelete(rootDir, true, guard, out dirDetail);
            if (dirResult != SafeOpOutcome.Done && dirResult != SafeOpOutcome.AlreadyGone)
            {
                stats.AddFailure(rootDir, dirDetail);
            }
        }

        #endregion

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
