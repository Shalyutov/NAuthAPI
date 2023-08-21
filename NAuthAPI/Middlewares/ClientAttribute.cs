namespace NAuthAPI
{
    [AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
    public class ClientAttribute : Attribute
    {
        public ClientAttribute()
        {
            
        }
    }
}
