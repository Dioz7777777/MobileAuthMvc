using System;
using System.Collections.Generic;
using System.Net.Http;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using MobileAuthMvc.Owin.Security.Providers.Oms.Provider;

namespace MobileAuthMvc.Owin.Security.Providers.Oms
{
    public sealed class OmsAuthenticationOptions : AuthenticationOptions
    {
        public sealed class OmsAuthenticationEndpoints
        {
            /// <summary>
            /// Endpoint which is used to redirect users to request GitHub access
            /// </summary>
            /// <remarks>
            /// Defaults to https://github.com/login/oauth/authorize
            /// </remarks>
            public string AuthorizationEndpoint { get; set; }

            /// <summary>
            /// Endpoint which is used to exchange code for access token
            /// </summary>
            /// <remarks>
            /// Defaults to https://github.com/login/oauth/access_token
            /// </remarks>
            public string TokenEndpoint { get; set; }

            /// <summary>
            /// Endpoint which is used to obtain user information after authentication
            /// </summary>
            /// <remarks>
            /// Defaults to https://api.github.com/user
            /// </remarks>
            public string UserInfoEndpoint { get; set; }
        }

        public ICertificateValidator BackchannelCertificateValidator { get; set; }
        public HttpMessageHandler BackchannelHttpHandler { get; set; }
        public TimeSpan BackchannelTimeout { get; set; }
        public PathString CallbackPath { get; set; }
        public string Caption
        {
            get => Description.Caption;
            set => Description.Caption = value;
        }
        public string ClientId { get; set; }
        public string ClientSecret { get; set; }
        public OmsAuthenticationEndpoints Endpoints { get; set; }
        public IOmsAuthenticationProvider Provider { get; set; }

        /// <summary>
        /// A list of permissions to request.
        /// </summary>
        public IList<string> Scope { get; private set; }

        /// <summary>
        ///     Gets or sets the name of another authentication middleware which will be responsible for actually issuing a user
        ///     <see cref="System.Security.Claims.ClaimsIdentity" />.
        /// </summary>
        public string SignInAsAuthenticationType { get; set; }

        /// <summary>
        ///     Gets or sets the type used to secure data handled by the middleware.
        /// </summary>
        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }

        /// <summary>
        ///     Initializes a new <see cref="OmsAuthenticationOptions" />
        /// </summary>
        public OmsAuthenticationOptions() : base(OmsAuthenticationDefaults.AuthenticationScheme)
        {
            Caption = OmsAuthenticationDefaults.DisplayName;
            CallbackPath = new PathString(OmsAuthenticationDefaults.CallbackPath);
            AuthenticationMode = AuthenticationMode.Passive;
            Scope = new List<string> { "user" };
            BackchannelTimeout = TimeSpan.FromSeconds(60);
            Endpoints = new OmsAuthenticationEndpoints
            {
                AuthorizationEndpoint = OmsAuthenticationDefaults.AuthorizationEndpoint,
                TokenEndpoint = OmsAuthenticationDefaults.TokenEndpoint,
                UserInfoEndpoint = OmsAuthenticationDefaults.UserInformationEndpoint
            };
        }
    }
}