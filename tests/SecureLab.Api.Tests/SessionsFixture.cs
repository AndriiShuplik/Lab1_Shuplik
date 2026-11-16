namespace SecureLab.Api.Tests;

public sealed class SessionsFixture : IDisposable
{
    private readonly Lazy<Task<HttpClient>> alice;
    private readonly Lazy<Task<HttpClient>> bob;
    private readonly Lazy<Task<HttpClient>> morgan;

    public SessionsFixture()
    {
        Factory = new SecureLabApiFactory();
        alice = new(() => Factory.LoginAsync("alice", StudyPassword).WithAntiforgeryTokenAsync());
        bob = new(() => Factory.LoginAsync("bob", StudyPassword).WithAntiforgeryTokenAsync());
        morgan = new(() => Factory.LoginAsync("morgan", StudyPassword).WithAntiforgeryTokenAsync());
    }

    public SecureLabApiFactory Factory { get; }

    public Task<HttpClient> Alice => alice.Value;

    public Task<HttpClient> Bob => bob.Value;

    public Task<HttpClient> Morgan => morgan.Value;

    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    private static void Release(Lazy<Task<HttpClient>> session)
    {
        if (session.IsValueCreated && session.Value.IsCompletedSuccessfully)
        {
            session.Value.Result.Dispose();
        }
    }

    public void Dispose()
    {
        Release(alice);
        Release(bob);
        Release(morgan);
        Factory.Dispose();
    }
}