using Certus.Core.Adcs;
using Certus.Core.Data;
using Certus.Core.Data.Entities;
using Microsoft.EntityFrameworkCore;

namespace Certus.Core.Services;

/// <summary>
/// Works out which certificate replaced which, and records it on
/// <see cref="SyncedCertificate.SupersededByCertificateId"/> (issue #154).
///
/// The CA database does not distinguish a renewal from a fresh issuance, so the
/// relationship cannot be read anywhere: it has to be inferred locally. Two
/// certificates are treated as one lineage when they came from the same template
/// and cover the same set of names, and within a lineage the later one replaces
/// the earlier.
///
/// This is an inference and every surface that shows it says so. Two teams
/// independently asking the same template for the same hostname produce rows this
/// rule calls a renewal, and it is wrong about them. The link annotates a row; it
/// never hides one, and it is never a filter, a sort key, or an aggregate.
/// </summary>
internal static class SupersessionLinker
{
    // Separators for the composed key. Control characters, so no template name
    // and no DNS name can contain one and forge a collision across the boundary
    // between the template part and the names part.
    private const char TemplateSeparator = (char)0x1F; // unit separator
    private const char NameSeparator = (char)0x1E;     // record separator

    // EF turns a Contains over a list into one parameter per element, and
    // SQLite's older default ceiling is 999. The tracked reload is chunked well
    // under it so a first run over a large inventory cannot trip the limit.
    private const int UpdateChunkSize = 500;

    /// <summary>
    /// The lineage key for one certificate, or null when there is nothing to key
    /// on.
    ///
    /// Null is load bearing. Without it every row with no template or no name at
    /// all would share the empty key and group into one enormous false lineage,
    /// in which unrelated certificates would claim to replace each other.
    /// </summary>
    internal static string? KeyFor(string? templateName, string? subject, string? sans)
    {
        // The template is half the identity of a lineage, so a row that does not
        // name one cannot be placed in any lineage at all.
        if (string.IsNullOrWhiteSpace(templateName))
            return null;

        var names = NormalizeSans(sans);

        if (names.Count == 0)
        {
            // No SANs: fall back to the subject CN. This is the enterprise shape,
            // the mirror of the SAN only ACME shape handled above.
            var commonName = CommonName(subject);
            if (string.IsNullOrWhiteSpace(commonName))
                return null;
            names = new List<string> { commonName.ToLowerInvariant() };
        }

        return string.Concat(
            templateName.Trim().ToLowerInvariant(),
            TemplateSeparator,
            string.Join(NameSeparator, names));
    }

    /// <summary>
    /// Recomputes the whole supersession map and applies it to the tracked
    /// entities. Returns how many rows changed; the caller saves, the same
    /// contract as the subject backfill in <see cref="CertificateSyncService"/>.
    ///
    /// The whole map rather than an incremental update, on purpose. A stored link
    /// goes wrong when a *newer* certificate arrives in a lineage, which is a row
    /// an incremental pass would not be looking at, so the partial path has a
    /// staleness hole the full rebuild simply does not have. Rebuilding reads six
    /// cheap columns once per sync cycle and writes only the rows whose answer
    /// actually moved, which in steady state is a handful.
    /// </summary>
    internal static async Task<int> RelinkAsync(
        CertusDbContext db, CancellationToken cancellationToken)
    {
        // Only certificates take part. Pending, denied, and failed rows are
        // requests that never became one: they carry no names and their validity
        // dates are placeholders, so they can neither supersede nor be superseded.
        var rows = await db.SyncedCertificates
            .Where(c => c.Status == CertificateQueryService.IssuedStatus
                     || c.Status == CertificateQueryService.RevokedStatus)
            .Select(c => new LineageRow(
                c.Id,
                c.TemplateName,
                c.Subject,
                c.SubjectAlternativeNames,
                c.NotBefore,
                c.Status,
                c.SupersededByCertificateId))
            .ToListAsync(cancellationToken);

        // Seeded to "no successor" for every row, so a link that no longer holds
        // is cleared rather than left behind. Rows with no key keep that seed.
        var desired = new Dictionary<int, int?>(rows.Count);
        foreach (var row in rows)
            desired[row.Id] = null;

        var lineages = rows
            .Select(row => (Row: row, Key: KeyFor(row.TemplateName, row.Subject, row.Sans)))
            .Where(keyed => keyed.Key != null)
            .GroupBy(keyed => keyed.Key!, keyed => keyed.Row, StringComparer.Ordinal);

        foreach (var lineage in lineages)
        {
            // Oldest first, with Id as the tiebreaker so two certificates issued
            // in the same second still have one defined order. Same reason the
            // list query appends ThenBy(c => c.Id).
            var ordered = lineage.OrderBy(row => row.NotBefore).ThenBy(row => row.Id).ToList();

            // Walk newest to oldest carrying the nearest later issued row.
            //
            // Three of the rules fall out of this one loop. The newest row is
            // never superseded, because nothing later has been seen yet. A revoked
            // certificate never supersedes, because it does not become the carried
            // value: it is not serving anything, and naming it as the replacement
            // would tell an operator the earlier certificate is safe to let go
            // when in fact nothing is in service. A revoked certificate can still
            // be superseded itself, because it is assigned from the carried value
            // like any other row.
            int? nextIssuedId = null;
            for (var i = ordered.Count - 1; i >= 0; i--)
            {
                var row = ordered[i];
                desired[row.Id] = nextIssuedId;
                if (row.Status == CertificateQueryService.IssuedStatus)
                    nextIssuedId = row.Id;
            }
        }

        var changedIds = rows
            .Where(row => row.SupersededByCertificateId != desired[row.Id])
            .Select(row => row.Id)
            .ToList();
        if (changedIds.Count == 0)
            return 0;

        foreach (var chunk in changedIds.Chunk(UpdateChunkSize))
        {
            var ids = chunk.ToList();
            var tracked = await db.SyncedCertificates
                .Where(c => ids.Contains(c.Id))
                .ToListAsync(cancellationToken);
            foreach (var entity in tracked)
                entity.SupersededByCertificateId = desired[entity.Id];
        }

        return changedIds.Count;
    }

    /// <summary>
    /// The stored comma separated SAN list as a canonical name set: labels
    /// stripped, lowercased, deduplicated, and sorted, so the comparison is order
    /// independent and case insensitive.
    /// </summary>
    private static List<string> NormalizeSans(string? sans)
    {
        if (string.IsNullOrWhiteSpace(sans))
            return new List<string>();

        // Sorted set: deduplication and ordering in one, which is what makes
        // "dns:A.example.com, dns:b.example.com" and
        // "dns:b.example.com, dns:a.example.com" the same key.
        var names = new SortedSet<string>(StringComparer.Ordinal);

        foreach (var raw in sans.Split(','))
        {
            var entry = raw.Trim();
            if (entry.Length == 0)
                continue;

            // Prefix checks rather than splitting on the colon, so an IPv6
            // address keeps its own colons. Same trap, same handling, as
            // AdcsClient.FirstSanDisplayName.
            if (entry.StartsWith("dns:", StringComparison.OrdinalIgnoreCase))
                entry = entry[4..].Trim();
            else if (entry.StartsWith("ip:", StringComparison.OrdinalIgnoreCase))
                entry = entry[3..].Trim();

            if (entry.Length > 0)
                names.Add(entry.ToLowerInvariant());
        }

        return names.ToList();
    }

    /// <summary>
    /// The CN from a subject DN, else the whole subject.
    ///
    /// The fallback is not decoration: when the CA hands back a SAN only row with
    /// no subject, CertificateSyncService backfills a bare name rather than a DN,
    /// and the dashboard's own extractCN falls back the same way, so a bare name
    /// has to key identically to the DN form it stands in for.
    ///
    /// Until issue #231 this split on the comma, which mattered here more than at
    /// the display sites. Two certificates whose common names differ only after a
    /// quoted comma both cut down to the same fragment, so they keyed into one
    /// lineage and the dashboard claimed one had replaced the other. Delegating
    /// to <see cref="DistinguishedNameParser"/> keeps them apart.
    ///
    /// An unescaped value can now carry a comma of its own, which is safe: the
    /// key joins names with <see cref="NameSeparator"/>, a control character no
    /// distinguished name can contain.
    /// </summary>
    private static string? CommonName(string? subject)
    {
        if (string.IsNullOrWhiteSpace(subject))
            return null;

        return DistinguishedNameParser.CommonName(subject) ?? subject.Trim();
    }

    /// <summary>The columns the inference needs, and nothing else.</summary>
    private sealed record LineageRow(
        int Id,
        string TemplateName,
        string Subject,
        string? Sans,
        DateTime NotBefore,
        string Status,
        int? SupersededByCertificateId);
}
