using System.Web;
using System.Web.Mvc;

//The following libraries were added to this sample.
using System.Security.Claims;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;

//The following libraries were defined and added to this sample.
using WebAppGroupClaimsDotNet.Utils;

// MULTITENANT
using System.Globalization;
using System;

namespace WebAppGroupClaimsDotNet.Controllers
{
    public class AccountController : Controller
    {
        /// <summary>
        /// Sends an OpenIDConnect Sign-In Request.
        /// </summary>
        public void SignIn(string redirectUri)
        {
            if (redirectUri == null)
                redirectUri = "/";

            HttpContext.GetOwinContext()
                .Authentication.Challenge(new AuthenticationProperties {RedirectUri = redirectUri},
                    OpenIdConnectAuthenticationDefaults.AuthenticationType);
        }

        /// <summary>
        /// Sends an OpenIDConnect Sign-In Request that will trigger admin consent, so an admin can sign up for their whole organization.
        /// </summary>
        public void SignUp(string redirectUri)
        {
            if (redirectUri == null)
                redirectUri = "/";

            HttpContext.GetOwinContext()
                .Authentication.Challenge(new AuthenticationProperties { RedirectUri = redirectUri },
                    OpenIdConnectAuthenticationDefaults.AuthenticationType);
        }

        /// <summary>
        /// Signs the user out and clears the cache of access tokens.
        /// </summary>
        public void SignOut()
        {
            // Remove all cache entries for this user and send an OpenID Connect sign-out request.
            if (Request.IsAuthenticated)
            {
                string userObjectID =
                ClaimsPrincipal.Current.FindFirst("http://schemas.microsoft.com/identity/claims/objectidentifier").Value;

                // MULTITENANT - Since I've set Tenant=common, we can't use the regular Authority here, we need the user's tenant
                // var authContext = new AuthenticationContext(ConfigHelper.Authority, new TokenDbCache(userObjectID));
                string userAuthority = String.Format(CultureInfo.InvariantCulture,
                    ConfigHelper.AadInstance,
                    ClaimsPrincipal.Current.FindFirst(Globals.TenantIdClaimType).Value);
                var authContext = new AuthenticationContext(userAuthority, new TokenDbCache(userObjectID));
                
                authContext.TokenCache.Clear();

                HttpContext.GetOwinContext().Authentication.SignOut(
                    OpenIdConnectAuthenticationDefaults.AuthenticationType, CookieAuthenticationDefaults.AuthenticationType);
            }
        }
    }
}