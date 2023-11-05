using System;
using System.Runtime.InteropServices;

namespace ProcessLauncher
{
    public class LaunchHelper
    {
        #region constants
        private const uint NORMAL_PRIORITY_CLASS = 0x00000020;
        private const uint CREATE_NEW_CONSOLE = 0x00000010;
        #endregion

        #region structs
        [StructLayout(LayoutKind.Sequential)]
        private struct STARTUPINFO
        {
            public int cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
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
        [StructLayout(LayoutKind.Sequential)]
        private struct TOKEN_LINKED_TOKEN
        {
            public IntPtr LinkedToken;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct TOKEN_ELEVATION
        {

            public uint TokenIsElevated;
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
        private enum TOKEN_INFORMATION_CLASS
        {
            TokenUser = 1,
            TokenGroups,
            TokenPrivileges,
            TokenOwner,
            TokenPrimaryGroup,
            TokenDefaultDacl,
            TokenSource,
            TokenType,
            TokenImpersonationLevel,
            TokenStatistics,
            TokenRestrictedSids,
            TokenSessionId,
            TokenGroupsAndPrivileges,
            TokenSessionReference,
            TokenSandBoxInert,
            TokenAuditPolicy,
            TokenOrigin,
            TokenElevationType,
            TokenLinkedToken,
            TokenElevation,
            TokenHasRestrictions,
            TokenAccessInformation,
            TokenVirtualizationAllowed,
            TokenVirtualizationEnabled,
            TokenIntegrityLevel,
            TokenUiAccess,
            TokenMandatoryPolicy,
            TokenLogonSid,
            MaxTokenInfoClass
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
            string lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandle,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool GetTokenInformation(
            IntPtr TokenHandle,
            TOKEN_INFORMATION_CLASS TokenInformationClass,
            IntPtr TokenInformation,
            uint TokenInformationLength,
            out uint ReturnLength);
        #endregion

        public static void StartProcessAsAdminUser(string appPath, string cmdLine="")
        {
            IntPtr userToken = IntPtr.Zero;
            IntPtr duplicatedUserToken = IntPtr.Zero;
            IntPtr TokenInformationIsElevated = IntPtr.Zero;
            IntPtr TokenInformationLinkedToken = IntPtr.Zero;
            IntPtr linkedToken = IntPtr.Zero;
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
                    errorCode = Marshal.GetLastWin32Error();
                    throw new Exception($"DuplicateTokenEx failed with error code : {errorCode}");
                }
                uint TokenInfLength = 0;
                GetTokenInformation(duplicatedUserToken, TOKEN_INFORMATION_CLASS.TokenLinkedToken, IntPtr.Zero, TokenInfLength, out TokenInfLength);
                TokenInformationLinkedToken = Marshal.AllocHGlobal((IntPtr)TokenInfLength);
                GetTokenInformation(duplicatedUserToken, TOKEN_INFORMATION_CLASS.TokenLinkedToken, TokenInformationLinkedToken, TokenInfLength, out TokenInfLength);
                TOKEN_LINKED_TOKEN LT = (TOKEN_LINKED_TOKEN)Marshal.PtrToStructure(TokenInformationLinkedToken, typeof(TOKEN_LINKED_TOKEN));
                linkedToken = LT.LinkedToken;
                GetTokenInformation(linkedToken, TOKEN_INFORMATION_CLASS.TokenElevation, IntPtr.Zero, TokenInfLength, out TokenInfLength);
                TokenInformationIsElevated = Marshal.AllocHGlobal((IntPtr)TokenInfLength);
                GetTokenInformation(linkedToken, TOKEN_INFORMATION_CLASS.TokenElevation, TokenInformationIsElevated, TokenInfLength, out TokenInfLength);
                TOKEN_ELEVATION TE = (TOKEN_ELEVATION)Marshal.PtrToStructure(TokenInformationIsElevated, typeof(TOKEN_ELEVATION));
                if (TE.TokenIsElevated != 1)
                {
                    throw new Exception($"The currently interactive session lacks a logged-in admin user.");
                }
                STARTUPINFO si = new STARTUPINFO();
                si.cb = Marshal.SizeOf(si);
                si.lpDesktop = @"winsta0\default";
                uint dwCreationFlags = NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE;
                if (!CreateProcessAsUser(linkedToken, appPath, cmdLine, IntPtr.Zero, IntPtr.Zero, false, dwCreationFlags,
                    IntPtr.Zero, null, ref si, out pi))
                {
                    errorCode = Marshal.GetLastWin32Error();
                    throw new Exception($"CreateProcessAsUser failed with error code : {errorCode}");
                }
            }
            finally
            {
                if (userToken != IntPtr.Zero)
                {
                    CloseHandle(userToken);
                }
                if(duplicatedUserToken != IntPtr.Zero)
                {
                    CloseHandle(duplicatedUserToken);
                }
                if(TokenInformationLinkedToken != IntPtr.Zero)
                {
                    CloseHandle(TokenInformationLinkedToken);
                }
                if(TokenInformationIsElevated != IntPtr.Zero)
                {
                    CloseHandle(TokenInformationIsElevated);
                }
                if(linkedToken != IntPtr.Zero)
                {
                    CloseHandle(linkedToken);
                }
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
            }
        }
    }
}
