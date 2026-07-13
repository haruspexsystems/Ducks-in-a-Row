// Integration tests boot full hosts through WebApplicationFactory by invoking
// the real Program entry point. Parallel entry-point boots race inside
// HostFactoryResolver and fail intermittently with "The entry point exited
// without ever building an IHost", so collections run sequentially here.
[assembly: Xunit.CollectionBehavior(DisableTestParallelization = true)]

// Every test class that boots a host carries
// [Trait("Category", "Integration")]. Those tests need the lab host
// (WSL, the port 80 portproxy, ADCS reachability) and cannot run on the
// isolated PR build runner, so CI excludes them with --filter
// "Category!=Integration" and runs only the pure unit tests (issue #24).
// A new test that boots a host must carry the same trait.
