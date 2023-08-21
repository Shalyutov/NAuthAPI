namespace NAuthAPI
{
    public interface IKVEngine
    {
        public string CreateKey(string key);
        public string GetKey(string key);
        public bool DeleteKey(string key);
        public string GetPepper();
    }
}
