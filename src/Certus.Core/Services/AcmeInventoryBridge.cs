using System.Linq.Expressions;
using Certus.Core.Data.Entities;

namespace Certus.Core.Services;

/// <summary>
/// The one rule that decides whether an <see cref="AcmeCertificate"/> row and a
/// <see cref="SyncedCertificate"/> row describe the same certificate (issue #442).
///
/// <para>
/// No foreign key joins the two tables. The inventory is rebuilt from the CA and
/// keyed on the CA's request id, and the ACME row records the request id its order
/// was submitted under, so for a long time that number was the whole bridge. A
/// request id is only unique within one CA, though. An install pointed at another
/// CA, which <c>docs/quickstart.md</c> explains how to do, keeps ACME rows that
/// describe the old CA's requests while the inventory refills with the new CA's,
/// numbered from 1 again. Bridged on the number alone, a pair could join two
/// unrelated certificates, and every site that crossed the bridge then acted on the
/// wrong one: a revocation stamp cleared or written, a certificate made revocable
/// from the dashboard, an ACME badge and contact shown on someone else's
/// certificate, a renew now window answered from another CA's row.
/// </para>
///
/// <para>
/// So a pair must also agree on the serial number. The serial identifies a
/// certificate within its issuer, and ADCS puts random bits into it, so two
/// certificates from two CAs sharing both a request id and a serial is not a case
/// to plan for. The two columns spell it differently, which is the trap: the ACME
/// row holds <c>X509Certificate2.SerialNumber</c>, uppercase and sometimes carrying
/// a leading 00 sign pad, while the CA view returns lowercase hex with no pad.
/// SQLite compares TEXT case sensitively, so a plain equality would match nothing on
/// a real install and silently switch every site off. Both sides are therefore
/// compared in the form <see cref="Certus.Core.Adcs.SerialNumbers.Normalize"/>
/// produces, written here as <c>ToUpper().TrimStart('0')</c> because EF translates
/// that to SQLite's <c>ltrim(upper(x), '0')</c> and has no translation for
/// ToUpperInvariant. Only hex reaches either column, so the culture rules of
/// ToUpper cannot change the answer.
/// </para>
///
/// <para>
/// A pair that fails the rule is treated as no pair at all, and at every site that
/// is the safe direction: a revocation stamp stays put, the dashboard does not
/// widen what it may revoke, no inventory row is stamped, no badge or contact is
/// shown. The cost of a false negative is the same at every site, and it is why the
/// normalization matters as much as the serial term: a pair the rule wrongly
/// refuses is a revocation the dashboard and ACME stop telling each other about.
/// </para>
///
/// <para>
/// The rule lives in one expression, <see cref="SameCertificate"/>. The three shapes
/// the call sites need are built from it by substituting its parameters, never
/// written out again, so a site cannot carry a copy that drifts.
/// </para>
/// </summary>
public static class AcmeInventoryBridge
{
    /// <summary>
    /// How far outside an order's own life the CA's submission time may fall and
    /// still be taken as that order's request. See <see cref="MayBeTheOrdersRequest"/>.
    /// </summary>
    public static readonly TimeSpan OrderSubmissionTolerance = TimeSpan.FromDays(1);

    /// <summary>
    /// The rule. Each term is load bearing:
    /// <list type="bullet">
    /// <item><description>
    /// <c>AdcsRequestId &gt; 0</c>: an unset key selects by an unset value rather
    /// than by identity.
    /// </description></item>
    /// <item><description>
    /// The request ids agree: the index both sides are looked up by, and the half of
    /// the identity that is unique within one CA.
    /// </description></item>
    /// <item><description>
    /// The normalized ACME serial is not empty: an empty serial on both sides would
    /// otherwise compare equal, and a request row in the inventory carries none.
    /// </description></item>
    /// <item><description>
    /// The normalized serials agree: the half that tells two CAs apart.
    /// </description></item>
    /// </list>
    /// </summary>
    private static readonly Expression<Func<AcmeCertificate, SyncedCertificate, bool>> SameCertificate =
        (acme, inventory) =>
            acme.AdcsRequestId > 0
            && inventory.RequestId == acme.AdcsRequestId
            && acme.SerialNumber.ToUpper().TrimStart('0') != ""
            && acme.SerialNumber.ToUpper().TrimStart('0') == inventory.SerialNumber.ToUpper().TrimStart('0');

    private static readonly Expression<Func<AcmeInventoryPair, bool>> PairsThatMatch = BuildPairPredicate();

    /// <summary>
    /// The predicate selecting the ACME row or rows that issued
    /// <paramref name="inventory"/>, for a site holding one inventory row in memory.
    /// The row's values become query parameters, so the row need not be saved.
    /// </summary>
    public static Expression<Func<AcmeCertificate, bool>> AcmeRowsFor(SyncedCertificate inventory)
    {
        ArgumentNullException.ThrowIfNull(inventory);
        var acme = SameCertificate.Parameters[0];
        var body = ParameterReplacer.Replace(
            SameCertificate.Body,
            SameCertificate.Parameters[1],
            Expression.Constant(inventory, typeof(SyncedCertificate)));
        return Expression.Lambda<Func<AcmeCertificate, bool>>(body, acme);
    }

    /// <summary>
    /// The predicate selecting the inventory row of <paramref name="acme"/>, for a
    /// site holding one ACME row in memory. The inventory is unique on the request
    /// id, so this matches one row at most.
    /// </summary>
    public static Expression<Func<SyncedCertificate, bool>> InventoryRowsFor(AcmeCertificate acme)
    {
        ArgumentNullException.ThrowIfNull(acme);
        var inventory = SameCertificate.Parameters[1];
        var body = ParameterReplacer.Replace(
            SameCertificate.Body,
            SameCertificate.Parameters[0],
            Expression.Constant(acme, typeof(AcmeCertificate)));
        return Expression.Lambda<Func<SyncedCertificate, bool>>(body, inventory);
    }

    /// <summary>
    /// Every ACME row paired with its inventory row, for a site whose query reads
    /// both sides as columns: a correlated subquery inside a projection, or a set
    /// based update. Use it as a captured query inside the outer lambda, correlated
    /// on a primary key, for example <c>pairs.Any(p =&gt; p.Inventory.Id == c.Id)</c>.
    /// EF inlines it as a subquery joining the two tables on the request id, which
    /// the unique index on <see cref="SyncedCertificate.RequestId"/> and the index on
    /// <see cref="AcmeCertificate.AdcsRequestId"/> both serve.
    /// </summary>
    public static IQueryable<AcmeInventoryPair> Pairs(
        IQueryable<AcmeCertificate> acme, IQueryable<SyncedCertificate> inventory)
    {
        ArgumentNullException.ThrowIfNull(acme);
        ArgumentNullException.ThrowIfNull(inventory);
        return acme
            .Join(inventory,
                a => a.AdcsRequestId,
                s => s.RequestId,
                (a, s) => new AcmeInventoryPair { Acme = a, Inventory = s })
            .Where(PairsThatMatch);
    }

    /// <summary>
    /// Whether a CA request row with no certificate (pending, denied or failed) may
    /// be the request an ACME order submitted, judged by when the CA says it was
    /// submitted. The name backfill in <see cref="CertificateSyncService"/> is the
    /// one bridge with no serial on either side: the request row has none because
    /// nothing was issued, and the order has no certificate. So the serial term of
    /// the rule cannot apply there, and this is what stands in for it.
    ///
    /// <para>
    /// It is a bound the order's own history proves, not a guess. A finalize refuses
    /// an order past its expiry before it claims it, and submits straight after the
    /// claim, so the submission instant lies between the order's creation and its
    /// expiry on this server's clock. A request the CA dates well outside that span is
    /// some other request that happens to carry the same number, which is what an
    /// install pointed at another CA produces. The tolerance absorbs the two clocks
    /// differing and whichever time zone the CA's date arrives in, which nothing here
    /// has measured; a day covers every UTC offset.
    /// </para>
    ///
    /// <para>
    /// Written as differences rather than by adding the tolerance to a date, so a
    /// <see cref="DateTime.MinValue"/> from a CA row that carried no date cannot
    /// overflow; it reads as outside the span, which leaves the row unnamed.
    /// </para>
    /// </summary>
    public static bool MayBeTheOrdersRequest(
        DateTime caSubmittedAt, DateTime orderCreatedAt, DateTime orderExpiresAt) =>
        orderCreatedAt - caSubmittedAt <= OrderSubmissionTolerance
        && caSubmittedAt - orderExpiresAt <= OrderSubmissionTolerance;

    private static Expression<Func<AcmeInventoryPair, bool>> BuildPairPredicate()
    {
        var pair = Expression.Parameter(typeof(AcmeInventoryPair), "pair");
        var body = ParameterReplacer.Replace(
            SameCertificate.Body,
            SameCertificate.Parameters[0],
            Expression.Property(pair, nameof(AcmeInventoryPair.Acme)));
        body = ParameterReplacer.Replace(
            body,
            SameCertificate.Parameters[1],
            Expression.Property(pair, nameof(AcmeInventoryPair.Inventory)));
        return Expression.Lambda<Func<AcmeInventoryPair, bool>>(body, pair);
    }

    /// <summary>Swaps one parameter of an expression body for another expression.</summary>
    private sealed class ParameterReplacer : ExpressionVisitor
    {
        private readonly ParameterExpression _from;
        private readonly Expression _to;

        private ParameterReplacer(ParameterExpression from, Expression to)
        {
            _from = from;
            _to = to;
        }

        public static Expression Replace(Expression body, ParameterExpression from, Expression to) =>
            new ParameterReplacer(from, to).Visit(body);

        protected override Expression VisitParameter(ParameterExpression node) =>
            node == _from ? _to : base.VisitParameter(node);
    }
}

/// <summary>
/// An ACME row and the inventory row it bridges to, as
/// <see cref="AcmeInventoryBridge.Pairs"/> yields them. Only ever built inside a
/// query, which reads its two members as columns.
/// </summary>
public sealed class AcmeInventoryPair
{
    /// <summary>The certificate as Ducks issued it over ACME.</summary>
    public AcmeCertificate Acme { get; init; } = null!;

    /// <summary>The same certificate as the CA inventory holds it.</summary>
    public SyncedCertificate Inventory { get; init; } = null!;
}
