﻿using System;
using System.Web;

//The following libraries were added to this sample.
using System.Threading.Tasks;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;

//The following libraries were defined and added to this sample.
using WebAppGroupClaimsDotNet.Utils;

// MULTITENANT
using System.Web.Mvc;

namespace WebAppGroupClaimsDotNet
{
    public partial class Startup
    {
        public void ConfigureAuth(IAppBuilder app)
        {
            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

            app.UseCookieAuthentication(new CookieAuthenticationOptions());

            //Configure OpenIDConnect, register callbacks for OpenIDConnect Notifications
            app.UseOpenIdConnectAuthentication(
                new OpenIdConnectAuthenticationOptions
                {
                    ClientId = ConfigHelper.ClientId,
                    Authority = ConfigHelper.Authority,
                    PostLogoutRedirectUri = ConfigHelper.PostLogoutRedirectUri,

                    //MULTITENANT - Disable issuer valiation
                    TokenValidationParameters = new System.IdentityModel.Tokens.TokenValidationParameters
                    {
                        ValidateIssuer = false,
                    },

                    Notifications = new OpenIdConnectAuthenticationNotifications
                    {
                        AuthorizationCodeReceived = context =>
                        {
                            ClientCredential credential = new ClientCredential(ConfigHelper.ClientId, ConfigHelper.AppKey);
                            string userObjectId = context.AuthenticationTicket.Identity.FindFirst(Globals.ObjectIdClaimType).Value;
                            AuthenticationContext authContext = new AuthenticationContext(ConfigHelper.Authority, new TokenDbCache(userObjectId));
                            AuthenticationResult result = authContext.AcquireTokenByAuthorizationCode(
                                context.Code, new Uri(HttpContext.Current.Request.Url.GetLeftPart(UriPartial.Path)), credential, ConfigHelper.GraphResourceId);

                            return Task.FromResult(0);
                        },

                        RedirectToIdentityProvider = context =>
                        {
                            // MULTITENANT - if the user has pressed the sign up button, add the admin_consent parameter
                            //
                            // UPDATE - try new permissions that don't require admin cadmin_consent, comment out this parameter
                            //
                            UrlHelper url = new UrlHelper(HttpContext.Current.Request.RequestContext);
                            //if (context.Request.Uri.AbsolutePath == url.Action("SignUp", "Account"))
                            //    context.ProtocolMessage.SetParameter("prompt", "admin_consent");

                            // MULTITENANT
                            //
                            // Override the post signout redirect URI to be the URL of the app determined on the fly.
                            // That way sign out works without config change regardless if running locally or running in the cloud.
                            if (context.Request.Uri.AbsolutePath == url.Action("SignOut", "Account"))
                                context.ProtocolMessage.PostLogoutRedirectUri = HttpContext.Current.Request.Url.GetLeftPart(UriPartial.Authority);

                            // MULTITENANT
                            // 
                            // Explicitly add the redirectUri to the request.
                            // This allows multiple redirect URIs to be registered in Azure AD, one for running locally and one for when running in the cloud.
                            context.ProtocolMessage.RedirectUri = HttpContext.Current.Request.Url.GetLeftPart(UriPartial.Path);

                            return Task.FromResult(0);
                        },

                        AuthenticationFailed = context =>
                        {
                            context.HandleResponse();
                            context.Response.Redirect("/Error/ShowError?signIn=true&errorMessage=" + context.Exception.Message);
                            return Task.FromResult(0);
                        }
                    }
                });
        }
    }
}