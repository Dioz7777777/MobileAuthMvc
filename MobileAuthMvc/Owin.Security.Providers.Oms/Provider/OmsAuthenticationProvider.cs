using System;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using Microsoft.Owin.Security;

namespace MobileAuthMvc.Owin.Security.Providers.Oms.Provider
{
    public sealed class OmsAuthenticationProvider : IOmsAuthenticationProvider
    {
        public OmsAuthenticationProvider()
        {
            OnAuthenticated = context =>
            {
                var authenticationManager = context.OwinContext.Authentication;
                authenticationManager.SignOut(DefaultAuthenticationTypes.ExternalCookie);
                authenticationManager.SignIn(new AuthenticationProperties { IsPersistent = false }, context.Identity);
                return Task.FromResult<object>(null);
            };
            OnReturnEndpoint = context => Task.FromResult<object>(null);
        }

        public Func<OmsAuthenticatedContext, Task> OnAuthenticated { get; set; }
        public Func<OmsReturnEndpointContext, Task> OnReturnEndpoint { get; set; }

        public Task Authenticated(OmsAuthenticatedContext context) => OnAuthenticated(context);

        public Task ReturnEndpoint(OmsReturnEndpointContext context) => OnReturnEndpoint(context);
    }
}