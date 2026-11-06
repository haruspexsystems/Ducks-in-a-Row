// One host at a time. Certus.Web.Tests found that parallel boots of a host race and fail
// intermittently, and disables parallelization for that reason; the service host shares
// the same process wide state, the static Serilog logger among it.
//
// A failed boot is hard to read. Program catches every exception and returns normally, so
// whatever went wrong before builder.Build(), WebApplicationFactory reports only "The entry
// point exited without ever building an IHost", the same words as issue #24.
[assembly: Xunit.CollectionBehavior(DisableTestParallelization = true)]

// No trait excludes these tests from the PR build. They boot the service host with the
// mock CA, a TestServer and a temporary data directory, and need nothing from the lab.
// Whether the PR build runner can boot a host at all is the question issue #413 asked of
// this project (V8 in its plan).
