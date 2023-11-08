# CreateProcessAsAdminUser
A library to launch applications with elevated privileges. This works only when an admin user is logged-in the currently interactive user session.

# Usage
using ProcessLauncher;


LaunchHelper.StartProcessAsAdminUser(@"C:\windows\system32\cmd.exe");
