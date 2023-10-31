using System;
using System.Runtime.InteropServices;

namespace ProcessLauncher
{
    public class LaunchHelper
    {
        #region constants
        private const UInt32 NORMAL_PRIORITY_CLASS = 0x00000020;
        private const UInt32 CREATE_NEW_CONSOLE = 0x00000010;
        #endregion

        #region structs
        [StructLayout(LayoutKind.Sequential)]
        private struct STARTUPINFO
        {
            public int cb;
            public String lpReserved;
            public String lpDesktop;
            public String lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }
        #endregion

        #region Enums
        private enum SECURITY_IMPERSONATION_LEVEL
        {
            SecurityAnonymous = 0,
            SecurityIdentification = 1,
            SecurityImpersonation = 2,
            SecurityDelegation = 3,
        }
        private enum TOKEN_TYPE
        {
            TokenPrimary = 1,
            TokenImpersonation = 2
        }
        #endregion

        #region DllImports
        [DllImport("kernel32.dll")]
        private static extern uint WTSGetActiveConsoleSessionId();

        [DllImport("Wtsapi32.dll")]
        private static extern uint WTSQueryUserToken(uint SessionId, ref IntPtr phToken);

        [DllImport("advapi32.dll", EntryPoint = "DuplicateTokenEx")]
        private static extern bool DuplicateTokenEx(
            IntPtr ExistingTokenHandle,
            uint dwDesiredAccess,
            IntPtr lpThreadAttributes,
            int TokenType,
            int ImpersonationLevel,
            ref IntPtr DuplicateTokenHandle);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hSnapshot);

        [DllImport("advapi32.dll", EntryPoint = "CreateProcessAsUser", SetLastError = true, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        private static extern bool CreateProcessAsUser(
            IntPtr hToken,
            String lpApplicationName,
            String lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandle,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            String lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);
        #endregion

        public static void StartProcessAsAdminUser(string appPath, string cmdLine="")
        {
            IntPtr userToken = IntPtr.Zero;
            IntPtr duplicatedUserToken = IntPtr.Zero;
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            int errorCode;
            try
            {
                uint activeSessionId = WTSGetActiveConsoleSessionId();
                if (WTSQueryUserToken(activeSessionId, ref userToken) == 0)
                {
                    errorCode = Marshal.GetLastWin32Error();
                    throw new Exception($"WTSQueryUserToken failed with error code : {errorCode}");
                }
                if(!DuplicateTokenEx(userToken, 0, IntPtr.Zero, (int)SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                    (int)TOKEN_TYPE.TokenPrimary, ref duplicatedUserToken))
                {
                    CloseHandle(userToken);
                    errorCode = Marshal.GetLastWin32Error();
                    throw new Exception($"DuplicateTokenEx failed with error code : {errorCode}");
                }
                CloseHandle(userToken);
                STARTUPINFO si = new STARTUPINFO();
                si.cb = Marshal.SizeOf(si);
                si.lpDesktop = @"winsta0\default";
                uint dwCreationFlags = NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE;
                if (CreateProcessAsUser(duplicatedUserToken, appPath, cmdLine, IntPtr.Zero, IntPtr.Zero, false, dwCreationFlags,
                    IntPtr.Zero, null, ref si, out pi))
                {

                }
                {

                }
            }
            finally
            {

            }
        }
    }
}
