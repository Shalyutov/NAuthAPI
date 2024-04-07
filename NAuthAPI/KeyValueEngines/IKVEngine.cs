namespace NAuthAPI
{
    public interface IKVEngine
    {
        public byte[] CreateKey(string key);
        public byte[] GetKey(string key);
        public bool DeleteKey(string key);
        public string GetPepper();
    }
}
