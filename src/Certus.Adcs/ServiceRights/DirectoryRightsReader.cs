using System.DirectoryServices;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Certus.Core.ServiceRights;

namespace Certus.Adcs.ServiceRights;

/// <summary>
/// The directory and host half of the service rights check (issue #440): whether
/// this server is domain joined, which account the service is on the network,
/// which groups that account carries, and what a template's permission list says.
///
/// Plain LDAP plus one local Win32 call. No ADCS COM is involved, so the dispatch
/// rules in CLAUDE.md do not apply here, and the "Directory lookups" contract
/// does: nothing here throws, and every failure comes back as a
/// <see cref="ReadingOutcome"/> with a reason.
///
/// The service runs as LocalSystem, whose process token carries SYSTEM and the
/// local Administrators group and none of the computer account's domain groups.
/// Those only exist in the ticket the service presents to the CA. So for the
/// computer account the groups are read from its <c>tokenGroups</c> in the
/// directory, which a domain controller computes transitively, and never from
/// the process token.
///
/// Also compiled into tools/AdcsQiProbe, so the lab measures the reader that
/// ships. Keep it to the base class library, System.DirectoryServices and C# 12.
/// </summary>
internal static class DirectoryRightsReader
{
    /// <summary>
    /// Deadlines for every search here, so a domain controller that stops
    /// answering cannot pin a thread pool thread for the OS level TCP timeout
    /// (CLAUDE.md, "Directory lookups").
    /// </summary>
    private static readonly TimeSpan SearchClientTimeout = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan SearchServerTimeLimit = TimeSpan.FromSeconds(10);

    private const string LocalSystemSid = "S-1-5-18";
    private const string LocalServiceSid = "S-1-5-19";
    private const string NetworkServiceSid = "S-1-5-20";

    private const int AccessDeniedHResult = unchecked((int)0x80070005);
    private const int NoSuchDomainHResult = unchecked((int)0x8007054B);
    private const int ServerDownHResult = unchecked((int)0x8007203A);

    /// <summary>
    /// Which account the service reaches the network as, and its groups.
    /// </summary>
    public static PrincipalReading ReadServicePrincipal()
    {
        string processIdentity;
        string? processSid;
        List<string> processGroups;
        using (var identity = WindowsIdentity.GetCurrent())
        {
            processIdentity = identity.Name;
            processSid = identity.User?.Value;
            processGroups = identity.Groups?.Select(group => group.Value).ToList() ?? [];
        }

        var isMachineIdentity = processSid is LocalSystemSid or NetworkServiceSid;
        var (joined, domainName) = ReadJoinState();

        if (joined == false)
        {
            return new PrincipalReading(
                ReadingOutcome.NotDomainJoined, false, domainName, processIdentity, isMachineIdentity,
                null, null, [],
                "This server is not joined to a domain, so the CA cannot authenticate the service " +
                "and there is no directory to read.");
        }

        if (processSid == LocalServiceSid)
        {
            return new PrincipalReading(
                ReadingOutcome.Failed, joined, domainName, processIdentity, false, null, null, [],
                "The service runs as LocalService, which reaches the network anonymously, so the CA " +
                "would refuse it. The installer runs it as LocalSystem.");
        }

        if (!isMachineIdentity)
        {
            // An account of its own reaches the CA as itself, and its token
            // already carries its domain groups.
            return new PrincipalReading(
                ReadingOutcome.Ok, joined, domainName, processIdentity, false,
                processIdentity, processSid, processGroups);
        }

        var accountName = Environment.MachineName + "$";
        var displayName = domainName is null ? accountName : domainName + "\\" + accountName;
        try
        {
            var (defaultContext, _) = ReadNamingContexts();
            if (string.IsNullOrEmpty(defaultContext))
            {
                return new PrincipalReading(
                    ReadingOutcome.Unavailable, joined, domainName, processIdentity, true,
                    displayName, null, [],
                    "No domain controller returned the domain's naming context, so the computer " +
                    "account could not be read.");
            }

            string accountSid;
            using (var domainEntry = new DirectoryEntry("LDAP://" + defaultContext))
            using (var searcher = new DirectorySearcher(domainEntry)
            {
                Filter = $"(&(objectCategory=computer)(sAMAccountName={LdapFilterValue.Escape(accountName)}))",
                SearchScope = SearchScope.Subtree,
                SizeLimit = 2,
                ClientTimeout = SearchClientTimeout,
                ServerTimeLimit = SearchServerTimeLimit,
            })
            {
                searcher.PropertiesToLoad.Add("objectSid");
                var found = searcher.FindOne();
                if (found?.Properties["objectSid"] is not { Count: > 0 } sidValues
                    || sidValues[0] is not byte[] sidBytes)
                {
                    return new PrincipalReading(
                        ReadingOutcome.NotFound, joined, domainName, processIdentity, true,
                        displayName, null, [],
                        $"The directory returned no computer account named {accountName}, or did not " +
                        "answer in time.");
                }
                accountSid = new SecurityIdentifier(sidBytes, 0).Value;
            }

            // tokenGroups is computed by the domain controller on request, and
            // only for a base scope read of the object itself.
            var groups = new List<string>();
            using (var accountEntry = new DirectoryEntry($"LDAP://<SID={accountSid}>"))
            using (var tokenSearcher = new DirectorySearcher(accountEntry)
            {
                Filter = "(objectClass=*)",
                SearchScope = SearchScope.Base,
                ClientTimeout = SearchClientTimeout,
                ServerTimeLimit = SearchServerTimeLimit,
            })
            {
                tokenSearcher.PropertiesToLoad.Add("tokenGroups");
                var tokenResult = tokenSearcher.FindOne();
                if (tokenResult?.Properties["tokenGroups"] is { Count: > 0 } groupValues)
                {
                    foreach (var value in groupValues)
                    {
                        if (value is byte[] groupSid)
                            groups.Add(new SecurityIdentifier(groupSid, 0).Value);
                    }
                }
            }

            if (groups.Count == 0)
            {
                // Every computer account belongs at least to its primary group,
                // so an empty answer is a read that came back with nothing, not
                // an account with no groups.
                return new PrincipalReading(
                    ReadingOutcome.Failed, joined, domainName, processIdentity, true,
                    displayName, accountSid, [],
                    "The directory returned no group memberships for the computer account, so a " +
                    "permission granted through a group would be missed.");
            }

            return new PrincipalReading(
                ReadingOutcome.Ok, joined, domainName, processIdentity, true,
                displayName, accountSid, groups);
        }
        catch (Exception ex)
        {
            var (outcome, detail) = Classify(ex, "reading the service's computer account");
            return new PrincipalReading(
                outcome, joined, domainName, processIdentity, true, displayName, null, [], detail);
        }
    }

    /// <summary>
    /// One template's permission list, as the service's account can read it.
    /// </summary>
    /// <param name="templateName">The template's programmatic name (its <c>cn</c>).</param>
    public static TemplateDaclReading ReadTemplateDacl(string templateName)
    {
        try
        {
            var (_, configurationContext) = ReadNamingContexts();
            if (string.IsNullOrEmpty(configurationContext))
            {
                return new TemplateDaclReading(
                    templateName, ReadingOutcome.Unavailable, [],
                    Detail: "No domain controller returned the configuration naming context, so the " +
                            "template's permissions could not be read.");
            }

            var path = $"LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,{configurationContext}";
            using var container = new DirectoryEntry(path);
            using var searcher = new DirectorySearcher(container)
            {
                Filter = $"(&(objectClass=pKICertificateTemplate)(cn={LdapFilterValue.Escape(templateName)}))",
                SearchScope = SearchScope.OneLevel,
                SizeLimit = 2,
                ClientTimeout = SearchClientTimeout,
                ServerTimeLimit = SearchServerTimeLimit,
                // Without this the directory asks for the owner and the audit
                // list as well, and withholds nTSecurityDescriptor from any
                // account that may not read those, which is every account here.
                // The Enroll test needs the access list alone.
                SecurityMasks = SecurityMasks.Dacl,
            };
            searcher.PropertiesToLoad.Add("nTSecurityDescriptor");

            var found = searcher.FindOne();
            if (found is null)
            {
                return new TemplateDaclReading(
                    templateName, ReadingOutcome.NotFound, [],
                    Detail: $"The directory has no template named {templateName}, or did not answer in time.");
            }

            if (found.Properties["nTSecurityDescriptor"] is not { Count: > 0 } values
                || values[0] is not byte[] descriptor)
            {
                return new TemplateDaclReading(
                    templateName, ReadingOutcome.AccessDenied, [],
                    Detail: "The directory returned the template without its permissions, so the " +
                            "service's account may not read them.");
            }

            var entries = ToAclEntries(descriptor, out var sddl);
            return new TemplateDaclReading(templateName, ReadingOutcome.Ok, entries, sddl);
        }
        catch (Exception ex)
        {
            var (outcome, detail) = Classify(ex, $"reading the permissions of template {templateName}");
            return new TemplateDaclReading(templateName, outcome, [], Detail: detail);
        }
    }

    /// <summary>
    /// Turns a binary security descriptor into the entries of its access list,
    /// in stored order. Internal for unit tests.
    /// </summary>
    /// <param name="descriptor">The descriptor bytes, as nTSecurityDescriptor holds them.</param>
    /// <param name="accessListSddl">The access list alone, in SDDL.</param>
    internal static IReadOnlyList<AclEntry> ToAclEntries(byte[] descriptor, out string accessListSddl)
    {
        var raw = new RawSecurityDescriptor(descriptor, 0);
        accessListSddl = raw.GetSddlForm(AccessControlSections.Access);

        if (raw.DiscretionaryAcl is null)
        {
            // No access list at all is no restriction: Windows grants every
            // access to everyone, and saying so beats reporting "no grant".
            return
            [
                new AclEntry(
                    AclEntryKind.Allow, TemplateEnrollEvaluator.GenericAll, null, false, false,
                    TemplateEnrollEvaluator.EveryoneSid),
            ];
        }

        var entries = new List<AclEntry>(raw.DiscretionaryAcl.Count);
        foreach (GenericAce ace in raw.DiscretionaryAcl)
            entries.Add(ToEntry(ace));
        return entries;
    }

    private static AclEntry ToEntry(GenericAce ace)
    {
        var inheritOnly = (ace.AceFlags & AceFlags.InheritOnly) != 0;
        var inherited = ace.IsInherited;

        switch (ace)
        {
            case ObjectAce objectAce:
                return new AclEntry(
                    KindOf(objectAce.AceQualifier, objectAce.IsCallback),
                    objectAce.AccessMask,
                    (objectAce.ObjectAceFlags & ObjectAceFlags.ObjectAceTypePresent) != 0
                        ? objectAce.ObjectAceType
                        : null,
                    inheritOnly,
                    inherited,
                    objectAce.SecurityIdentifier.Value);

            case CommonAce commonAce:
                return new AclEntry(
                    KindOf(commonAce.AceQualifier, commonAce.IsCallback),
                    commonAce.AccessMask,
                    null,
                    inheritOnly,
                    inherited,
                    commonAce.SecurityIdentifier.Value);

            case KnownAce knownAce:
                // A compound entry, which Windows no longer writes: its trustee
                // is readable and its meaning here is not.
                return new AclEntry(
                    AclEntryKind.Unsupported, knownAce.AccessMask, null, inheritOnly, inherited,
                    knownAce.SecurityIdentifier.Value);

            default:
                // A type .NET cannot parse at all. It could be about anyone and
                // grant anything, so it is treated as exactly that.
                return new AclEntry(
                    AclEntryKind.Unsupported, -1, null, inheritOnly, inherited, AclEntry.AnyTrustee);
        }
    }

    private static AclEntryKind KindOf(AceQualifier qualifier, bool isCallback)
    {
        // A callback entry carries a condition only Windows can evaluate.
        if (isCallback)
            return AclEntryKind.Unsupported;

        return qualifier switch
        {
            AceQualifier.AccessAllowed => AclEntryKind.Allow,
            AceQualifier.AccessDenied => AclEntryKind.Deny,
            _ => AclEntryKind.Unsupported,
        };
    }

    private static (string? DefaultContext, string? ConfigurationContext) ReadNamingContexts()
    {
        using var rootDse = new DirectoryEntry("LDAP://RootDSE");
        return (
            rootDse.Properties["defaultNamingContext"]?.Value as string,
            rootDse.Properties["configurationNamingContext"]?.Value as string);
    }

    /// <summary>
    /// The local join state, answered without a domain controller. Null when
    /// the state itself could not be read.
    /// </summary>
    private static (bool? Joined, string? Name) ReadJoinState()
    {
        if (NativeMethods.NetGetJoinInformation(null, out var buffer, out var status) != 0)
            return (null, null);

        try
        {
            var name = Marshal.PtrToStringUni(buffer);
            return status switch
            {
                NativeMethods.NetSetupDomainName => (true, name),
                NativeMethods.NetSetupWorkgroupName or NativeMethods.NetSetupUnjoined => (false, name),
                _ => (null, name),
            };
        }
        finally
        {
            NativeMethods.NetApiBufferFree(buffer);
        }
    }

    private static (ReadingOutcome Outcome, string Detail) Classify(Exception ex, string activity) => ex switch
    {
        UnauthorizedAccessException =>
            (ReadingOutcome.AccessDenied, $"The directory refused the service's account while {activity}."),
        COMException { HResult: AccessDeniedHResult } =>
            (ReadingOutcome.AccessDenied, $"The directory refused the service's account while {activity}."),
        COMException { HResult: NoSuchDomainHResult or ServerDownHResult } =>
            (ReadingOutcome.Unavailable, $"No domain controller answered while {activity}."),
        _ => (ReadingOutcome.Failed, $"Failed while {activity}: {ex.Message}"),
    };

    private static class NativeMethods
    {
        // NETSETUP_JOIN_STATUS values.
        internal const int NetSetupUnjoined = 1;
        internal const int NetSetupWorkgroupName = 2;
        internal const int NetSetupDomainName = 3;

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        internal static extern int NetGetJoinInformation(string? server, out IntPtr nameBuffer, out int joinStatus);

        [DllImport("netapi32.dll")]
        internal static extern int NetApiBufferFree(IntPtr buffer);
    }
}
