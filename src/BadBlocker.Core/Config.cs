using Microsoft.Win32;
using System.Security.AccessControl;
using System.Security.Principal;

namespace BadBlocker.Core;

public record SocialCategories(
    bool Harmful,
    bool FeedsForums,
    bool Streaming,
    bool YouTube,
    bool Messaging)
{
    public bool AnyEnabled =>
        Harmful || FeedsForums || Streaming || YouTube || Messaging;

    public IEnumerable<string> EnabledFileNames()
    {
        if (Harmful)     yield return "social_harmful.txt";
        if (FeedsForums) yield return "social_feeds.txt";
        if (Streaming)   yield return "social_streaming.txt";
        if (YouTube)     yield return "social_youtube.txt";
        if (Messaging)   yield return "social_messaging.txt";
    }
}

public static class Config
{
    private const string RegPath = @"SOFTWARE\BadWebsiteBlocker";
    public static readonly string DataDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "BadWebsiteBlocker");

    public static void WriteInstallConfig(SocialCategories social)
    {
        Directory.CreateDirectory(DataDir);
        using var key = Registry.LocalMachine.CreateSubKey(RegPath, writable: true);
        key.SetValue("BlockHarmful",    social.Harmful    ? 1 : 0, RegistryValueKind.DWord);
        key.SetValue("BlockFeedsForums",social.FeedsForums? 1 : 0, RegistryValueKind.DWord);
        key.SetValue("BlockStreaming",  social.Streaming  ? 1 : 0, RegistryValueKind.DWord);
        key.SetValue("BlockYouTube",    social.YouTube    ? 1 : 0, RegistryValueKind.DWord);
        key.SetValue("BlockMessaging",  social.Messaging  ? 1 : 0, RegistryValueKind.DWord);
        key.SetValue("Installed", 1, RegistryValueKind.DWord);
        LockRegistryKey();
    }

    public static SocialCategories GetSocialCategories()
    {
        using var key = Registry.LocalMachine.OpenSubKey(RegPath);
        static bool Read(RegistryKey? k, string name) =>
            k?.GetValue(name) is int v && v == 1;
        return new SocialCategories(
            Harmful:    Read(key, "BlockHarmful"),
            FeedsForums:Read(key, "BlockFeedsForums"),
            Streaming:  Read(key, "BlockStreaming"),
            YouTube:    Read(key, "BlockYouTube"),
            Messaging:  Read(key, "BlockMessaging"));
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
            acl.AddAccessRule(new RegistryAccessRule(system,
                RegistryRights.FullControl, InheritanceFlags.None,
                PropagationFlags.None, AccessControlType.Allow));
            acl.AddAccessRule(new RegistryAccessRule(admins,
                RegistryRights.ReadKey, InheritanceFlags.None,
                PropagationFlags.None, AccessControlType.Allow));
            key.SetAccessControl(acl);
        }
        catch { }
    }
}
