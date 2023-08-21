namespace NAuthAPI
{
    [AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
    public class TrustClientAttribute : Attribute
    {
        public TrustClientAttribute() 
        { 
            
        }
    }
}
