using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Certus.Core.Data;

/// <summary>
/// Design time factory for the `dotnet ef` tooling. Lets migrations be added
/// from this class library without a startup project:
///
///     dotnet dotnet-ef migrations add &lt;Name&gt; --project src/Certus.Core --output-dir Data/Migrations
///
/// The connection string is a placeholder. Design time commands build the model
/// from it but never open the database when generating a migration.
/// </summary>
public sealed class CertusDbContextFactory : IDesignTimeDbContextFactory<CertusDbContext>
{
    public CertusDbContext CreateDbContext(string[] args)
    {
        var options = new DbContextOptionsBuilder<CertusDbContext>()
            .UseSqlite("Data Source=certus-design.db")
            .Options;

        return new CertusDbContext(options);
    }
}
