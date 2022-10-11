namespace MobileAuthMvc.Owin.Security.Providers.Oms
{
    internal static class OmsAuthenticationDefaults
    {
        public const string AuthenticationScheme = "Oms";
        public const string DisplayName = "Oms";
        public const string Issuer = "Oms";
        public const string CallbackPath = "/mobileauth";
        public const string AuthorizationEndpoint = "https://ssodev.compassmanager.com/oauth2.0/authorize";
        public const string TokenEndpoint = "https://ssodev.compassmanager.com/oauth2.0/accessToken";
        public const string UserInformationEndpoint = "https://ssodev.compassmanager.com/oauth2.0/profile";
    }
}