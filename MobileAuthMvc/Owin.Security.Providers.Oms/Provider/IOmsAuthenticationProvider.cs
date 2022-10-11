using System.Threading.Tasks;

namespace MobileAuthMvc.Owin.Security.Providers.Oms.Provider
{
    public interface IOmsAuthenticationProvider
    {
        Task Authenticated(OmsAuthenticatedContext context);
        Task ReturnEndpoint(OmsReturnEndpointContext context);
    }
}