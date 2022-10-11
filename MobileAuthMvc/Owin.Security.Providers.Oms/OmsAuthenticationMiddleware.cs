using System;
using System.Globalization;
using System.Net.Http;
using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.Infrastructure;
using MobileAuthMvc.Owin.Security.Providers.Oms.Provider;
using Owin;

namespace MobileAuthMvc.Owin.Security.Providers.Oms
{
    public class OmsAuthenticationMiddleware : AuthenticationMiddleware<OmsAuthenticationOptions>
    {
        private readonly HttpClient _httpClient;
        private readonly ILogger _logger;

        public OmsAuthenticationMiddleware(OwinMiddleware next, IAppBuilder app, OmsAuthenticationOptions options)
            : base(next, options)
        {
            if (string.IsNullOrWhiteSpace(Options.ClientId))
            {
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture,
                    "BeDataGridCell(rowIndex=0, value=The '{0}' option must be provided., displayValue=RichTextModel(parts=[RichStringModel(text=The '{0}' option must be provided., foregroundColor=null, backgroundColor=null, effectColor=null, effectStyle=None, fontStyle=Regular)]), tooltip=RichTextModel(parts=[]), editable=true, highlight=false)",
                    "ClientId"));
            }
            if (string.IsNullOrWhiteSpace(Options.ClientSecret))
            {
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture,
                    "BeDataGridCell(rowIndex=0, value=The '{0}' option must be provided., displayValue=RichTextModel(parts=[RichStringModel(text=The '{0}' option must be provided., foregroundColor=null, backgroundColor=null, effectColor=null, effectStyle=None, fontStyle=Regular)]), tooltip=RichTextModel(parts=[]), editable=true, highlight=false)", "ClientSecret"));
            }

            _logger = app.CreateLogger<OmsAuthenticationMiddleware>();

            if (Options.Provider == null) Options.Provider = new OmsAuthenticationProvider();

            if (Options.StateDataFormat == null)
            {
                var dataProtector = app.CreateDataProtector(
                    typeof(OmsAuthenticationMiddleware).FullName,
                    Options.AuthenticationType,
                    "v1");
                Options.StateDataFormat = new PropertiesDataFormat(dataProtector);
            }

            if (string.IsNullOrEmpty(Options.SignInAsAuthenticationType))
                Options.SignInAsAuthenticationType = app.GetDefaultSignInAsAuthenticationType();

            _httpClient = new HttpClient(ResolveHttpMessageHandler(Options))
            {
                Timeout = Options.BackchannelTimeout,
                MaxResponseContentBufferSize = 1024 * 1024 * 10,
            };
            _httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("Microsoft Owin OAuth2 middleware");
            _httpClient.DefaultRequestHeaders.ExpectContinue = false;
        }

        /// <summary>
        ///     Provides the <see cref="T:Microsoft.Owin.Security.Infrastructure.AuthenticationHandler" /> object for processing
        ///     authentication-related requests.
        /// </summary>
        /// <returns>
        ///     An <see cref="T:Microsoft.Owin.Security.Infrastructure.AuthenticationHandler" /> configured with the
        ///     <see cref="T:Owin.Security.Providers.GitHub.OmsAuthenticationOptions" /> supplied to the constructor.
        /// </returns>
        protected override AuthenticationHandler<OmsAuthenticationOptions> CreateHandler() =>
            new OmsAuthenticationHandler(_httpClient, _logger);

        private static HttpMessageHandler ResolveHttpMessageHandler(OmsAuthenticationOptions options)
        {
            var handler = options.BackchannelHttpHandler ?? new WebRequestHandler();

            // If they provided a validator, apply it or fail.
            if (options.BackchannelCertificateValidator == null) return handler;
            // Set the cert validate callback
            var webRequestHandler = handler as WebRequestHandler;
            if (webRequestHandler == null)
            {
                throw new InvalidOperationException("BeDataGridCell(rowIndex=1, value=An ICertificateValidator cannot be specified at the same time as an HttpMessageHandler unless it is a WebRequestHandler., displayValue=RichTextModel(parts=[RichStringModel(text=An ICertificateValidator cannot be specified at the same time as an HttpMessageHandler unless it is a WebRequestHandler., foregroundColor=null, backgroundColor=null, effectColor=null, effectStyle=None, fontStyle=Regular)]), tooltip=RichTextModel(parts=[]), editable=true, highlight=false)");
            }

            webRequestHandler.ServerCertificateValidationCallback = options.BackchannelCertificateValidator.Validate;

            return handler;
        }
    }
}