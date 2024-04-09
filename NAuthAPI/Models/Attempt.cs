namespace NAuthAPI
{
    public record Attempt(string Id, DateTime Issued, bool Success);
}
