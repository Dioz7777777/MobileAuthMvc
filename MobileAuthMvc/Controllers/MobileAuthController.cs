using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;

namespace MobileAuthMvc.Controllers
{
    // [Authorize]
    public sealed class MobileAuthController : Controller
    {
        private const string CallbackScheme = "com.mobile.onevendmobile";
        private const string Scheme = "Oms";

        public async Task<ActionResult> Index()
        {
            var owinContext = ControllerContext.HttpContext.GetOwinContext().Authentication;
            var auth = await owinContext.AuthenticateAsync(Scheme);

            if (auth == null || !auth.Identity.IsAuthenticated)
            {
                // Not authenticated, challenge
                owinContext.Challenge( Scheme);
                return new EmptyResult();
            }
            else
            {
                var claims = auth.Identity.Claims;
                var email = string.Empty;
                email = claims?.FirstOrDefault(c => c.Type == System.Security.Claims.ClaimTypes.Email)?.Value;

                auth.Properties.Dictionary.TryGetValue("access_token", out var authToken);

                // Get parameters to send back to the callback
                var qs = new Dictionary<string, string>
                {
                    { "access_token", authToken },
                    // { "refresh_token", auth.Properties.GetTokenValue("refresh_token") ?? string.Empty },
                    { "expires", (auth.Properties.ExpiresUtc?.ToUnixTimeSeconds() ?? -1).ToString() },
                    { "email", email }
                };

                // Build the result url
                var url = CallbackScheme + "://#" + string.Join(
                    "&",
                    qs.Where(kvp => !string.IsNullOrEmpty(kvp.Value) && kvp.Value != "-1")
                        .Select(kvp => $"{WebUtility.UrlEncode(kvp.Key)}={WebUtility.UrlEncode(kvp.Value)}"));

                // Redirect to final url
                return new RedirectResult(url);
                // ControllerContext.HttpContext.Response.Redirect(url);
            }
        }
    }
}