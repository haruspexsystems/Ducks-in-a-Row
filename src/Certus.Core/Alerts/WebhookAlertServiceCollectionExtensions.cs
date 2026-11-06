using Microsoft.Extensions.DependencyInjection;

namespace Certus.Core.Alerts;

/// <summary>
/// Registers the webhook notifier and its HTTP client. Both hosts call this
/// once, right after the email notifier, so the two channels keep their order.
/// </summary>
public static class WebhookAlertServiceCollectionExtensions
{
    public static IServiceCollection AddWebhookAlertNotifier(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        // Without the HTTP client factory's own loggers. They log every request
        // URI at Information, which the service log keeps, with the query
        // redacted and the path whole, and the path is where Slack, Discord and
        // Teams connector URLs carry their secret. The notifier logs each
        // delivery itself, naming only the host.
        services.AddHttpClient<WebhookAlertNotifier>(client =>
            {
                client.Timeout = TimeSpan.FromSeconds(30);
            })
            .RemoveAllLoggers();
        services.AddScoped<IAlertNotifier>(sp =>
            sp.GetRequiredService<WebhookAlertNotifier>());

        return services;
    }
}
