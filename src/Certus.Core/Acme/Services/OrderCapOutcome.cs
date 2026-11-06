namespace Certus.Core.Acme.Services;

/// <summary>
/// What <see cref="OrderService.CheckOrderCapsAsync"/> decided about a new-order
/// request. The controller maps each refusal to its RFC 8555 problem document:
/// too many identifiers is <c>malformed</c> (the request itself is out of
/// shape), too many open orders is <c>rateLimited</c> (the request is fine and
/// the account has to clear some first).
/// </summary>
public enum OrderCapOutcome
{
    /// <summary>Within both caps; carry on.</summary>
    Accepted,

    /// <summary>
    /// The request names more identifiers than
    /// <c>Certus:RateLimiting:MaxIdentifiersPerOrder</c> allows.
    /// </summary>
    TooManyIdentifiers,

    /// <summary>
    /// The account already holds <c>Certus:RateLimiting:MaxPendingOrdersPerAccount</c>
    /// orders that are pending or ready and not expired.
    /// </summary>
    TooManyPendingOrders
}
