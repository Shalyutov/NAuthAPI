namespace NAuthAPI
{
    public class Request
    {
        public required string Client { get; set; }
        public required string Code { get; set; }
        public required string Verifier { get; set; }
        public required string User { get; set; }
        public required string Scope { get; set; }
        public DateTime Issued { get; set; }
    }
}
