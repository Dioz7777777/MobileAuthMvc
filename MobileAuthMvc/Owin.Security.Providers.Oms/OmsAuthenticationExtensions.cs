using System;
using Owin;

namespace MobileAuthMvc.Owin.Security.Providers.Oms
{
    public static class OmsAuthenticationExtensions
    {
        public static IAppBuilder UseOmsAuthentication(
            this IAppBuilder app,
            OmsAuthenticationOptions options)
        {
            if (app == null) throw new ArgumentNullException(nameof(app));
            if (options == null) throw new ArgumentNullException(nameof(options));

            app.Use(typeof(OmsAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UseOmsAuthentication(this IAppBuilder app, string clientId, string clientSecret)
        {
            return app.UseOmsAuthentication(new OmsAuthenticationOptions
            {
                AuthenticationType = "Oms",
                ClientId = clientId,
                ClientSecret = clientSecret
            });
        }
    }
}