using Microsoft.Win32;
using System.Security.AccessControl;
using System.Security.Principal;

namespace BadBlocker.Core;

public static class Config
{
    private const string RegPath = @"SOFTWARE\BadWebsiteBlocker";
    public static readonly string DataDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "BadWebsiteBlocker");

    public static void WriteInstallConfig(bool blockSocial)
    {
        Directory.CreateDirectory(DataDir);
        using var key = Registry.LocalMachine.CreateSubKey(RegPath, writable: true);
        key.SetValue("BlockSocial", blockSocial ? 1 : 0, RegistryValueKind.DWord);
        key.SetValue("Installed", 1, RegistryValueKind.DWord);
        LockRegistryKey();
    }

    public static bool GetBlockSocial()
    {
        using var key = Registry.LocalMachine.OpenSubKey(RegPath);
        return key?.GetValue("BlockSocial") is int v && v == 1;
    }

    public static bool IsInstalled()
    {
        using var key = Registry.LocalMachine.OpenSubKey(RegPath);
        return key?.GetValue("Installed") is int v && v == 1;
    }

    private static void LockRegistryKey()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(RegPath, RegistryKeyPermissionCheck.ReadWriteSubTree,
                RegistryRights.ChangePermissions | RegistryRights.ReadKey);
            if (key == null) return;
            var acl = key.GetAccessControl();
            acl.SetAccessRuleProtection(true, false);
            var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            // SYSTEM can read+write; Admins can read (so IsInstalled/GetBlockSocial work) but not write
            acl.AddAccessRule(new RegistryAccessRule(system,
                RegistryRights.FullControl, InheritanceFlags.None,
                PropagationFlags.None, AccessControlType.Allow));
            acl.AddAccessRule(new RegistryAccessRule(admins,
                RegistryRights.ReadKey, InheritanceFlags.None,
                PropagationFlags.None, AccessControlType.Allow));
            key.SetAccessControl(acl);
        }
        catch { /* Best-effort */ }
    }
}
