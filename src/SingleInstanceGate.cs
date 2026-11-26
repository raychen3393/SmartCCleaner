using System;
using System.Threading;

namespace SmartCCleaner
{
    /// <summary>
    /// 单实例互斥锁。普通启动时不等待（已有实例就唤醒它）；
    /// 「以管理员身份重启」时新进程会先等旧进程退出再接管，
    /// 避免新进程抢先拿锁失败、唤醒即将关闭的旧窗口后自己退出，导致程序直接消失。
    /// </summary>
    public sealed class SingleInstanceGate : IDisposable
    {
        private Mutex _mutex;
        private bool _owned;

        public bool IsOwner
        {
            get { return _owned; }
        }

        private SingleInstanceGate()
        {
        }

        public static SingleInstanceGate Acquire(string mutexName, int waitMilliseconds)
        {
            var gate = new SingleInstanceGate();
            gate._mutex = new Mutex(false, mutexName);
            try
            {
                gate._owned = gate._mutex.WaitOne(Math.Max(0, waitMilliseconds), false);
            }
            catch (AbandonedMutexException)
            {
                // 上一个实例未释放就退出（崩溃或被结束）：锁已转交给当前线程。
                gate._owned = true;
            }
            return gate;
        }

        public void Dispose()
        {
            if (_mutex == null) return;
            if (_owned)
            {
                try
                {
                    _mutex.ReleaseMutex();
                }
                catch (ApplicationException)
                {
                }
                _owned = false;
            }
            _mutex.Dispose();
            _mutex = null;
        }
    }
}
