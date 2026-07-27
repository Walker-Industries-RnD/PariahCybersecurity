using System.Diagnostics;
using System.Runtime.InteropServices;

namespace WISecureData
{
    // Opt-in, best-effort anti-tamper helpers for hardening a process against
    // debuggers and DLL injection. Nothing here runs on its own; you call it.
    // These raise the cost of an attack, they are not a guarantee.
    public static class AntiTamper
    {
        // native (Windows)
        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool IsDebuggerPresent();

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, ref bool isDebuggerPresent);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetProcessMitigationPolicy(int policy, ref uint buffer, UIntPtr length);

        // PROCESS_MITIGATION_POLICY.ProcessExtensionPointDisablePolicy
        private const int ProcessExtensionPointDisablePolicy = 6;

        // Detects a managed OR native debugger attached to this process. Read-only and
        // safe to call anywhere. Combines the CLR check with the Win32 IsDebuggerPresent
        // and CheckRemoteDebuggerPresent checks (the latter still sees a debugger that
        // detached the PEB flag).
        public static bool IsDebuggerAttached()
        {
            try
            {
                if (Debugger.IsAttached)
                    return true;

                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    if (IsDebuggerPresent())
                        return true;

                    bool remote = false;
                    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), ref remote) && remote)
                        return true;
                }
            }
            catch
            {
                // A missing API must not turn a hardening check into a crash.
            }
            return false;
        }

        // Best-effort: blocks legacy extension-point DLL injection (AppInit_DLLs,
        // cross-process SetWindowsHookEx, legacy IMEs) via SetProcessMitigationPolicy.
        // Windows-only, applies for the rest of the process lifetime, and only blocks
        // injection attempted after it runs. Returns whether it was applied.
        //
        // This is the low-risk mitigation. The stronger "only Microsoft-signed DLLs"
        // signature policy is deliberately NOT used here because it will also block
        // legitimate third-party native DLLs (and can stop your app from starting).
        public static bool TryHardenAgainstInjection()
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                return false;

            try
            {
                uint flags = 1; // PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY.DisableExtensionPoints
                return SetProcessMitigationPolicy(ProcessExtensionPointDisablePolicy, ref flags, (UIntPtr)sizeof(uint));
            }
            catch
            {
                return false;
            }
        }

        // watchdog
        private static Thread? _watchdog;
        private static volatile bool _watchRunning;

        // Opt-in background watchdog. Polls for a debugger and, the first time one is
        // seen, invokes onDetected exactly once (your chance to wipe every SecureData
        // you hold and bail out), then stops. Do NOT enable this in debug builds or
        // while developing: it will fire on your own debugger. onDetected runs once on
        // detection; pollMilliseconds is the poll interval, clamped to a 50 ms floor.
        public static void StartWatchdog(Action onDetected, int pollMilliseconds = 1000)
        {
            if (onDetected == null)
                throw new ArgumentNullException(nameof(onDetected));
            if (_watchRunning)
                return;

            _watchRunning = true;
            _watchdog = new Thread(() =>
            {
                while (_watchRunning)
                {
                    if (IsDebuggerAttached())
                    {
                        try { onDetected(); } catch { /* never let the reaction crash the watchdog */ }
                        _watchRunning = false;
                        break;
                    }
                    Thread.Sleep(Math.Max(50, pollMilliseconds));
                }
            })
            {
                IsBackground = true,
                Name = "PariahAntiTamperWatchdog"
            };
            _watchdog.Start();
        }

        // Stops the watchdog started by StartWatchdog (if any).
        public static void StopWatchdog() => _watchRunning = false;
    }
}
