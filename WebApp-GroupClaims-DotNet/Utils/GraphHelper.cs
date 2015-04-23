﻿using Microsoft.Azure.ActiveDirectory.GraphClient;
using Microsoft.Azure.ActiveDirectory.GraphClient.Extensions;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

// MULTITENANT
using System.Globalization;

namespace WebAppGroupClaimsDotNet.Utils
{
    class GraphHelper
    {
        public static string AcquireToken(string userObjectId)
        {
            ClientCredential cred = new ClientCredential(ConfigHelper.ClientId, ConfigHelper.AppKey);

            // MULTITENANT - Since I've set Tenant=common, we can't use the regular Authority here, we need the user's tenant
            // AuthenticationContext authContext = new AuthenticationContext(ConfigHelper.Authority, new TokenDbCache(userObjectId));
            string userAuthority = String.Format(CultureInfo.InvariantCulture,
                ConfigHelper.AadInstance,
                ClaimsPrincipal.Current.FindFirst(Globals.TenantIdClaimType).Value);
            AuthenticationContext authContext = new AuthenticationContext(userAuthority, new TokenDbCache(userObjectId));

            AuthenticationResult result = authContext.AcquireTokenSilent(ConfigHelper.GraphResourceId, cred, new UserIdentifier(userObjectId, UserIdentifierType.UniqueId));
            return result.AccessToken;
        }

        public async static Task GetDirectoryObjects(List<string> objectIds, List<Group> groups, List<User> users)
        { 
            List<DirectoryRole> roles = new List<DirectoryRole>();
            await GetDirectoryObjects(objectIds, groups, roles, users);
        }

        public async static Task GetDirectoryObjects(List<string> objectIds, List<Group> groups, List<DirectoryRole> roles)
        {
            List<User> users = new List<User>();
            await GetDirectoryObjects(objectIds, groups, roles, users);
        }

        public async static Task GetDirectoryObjects(List<string> objectIds, List<Group> groups, List<DirectoryRole> roles, List<User> users)
        {
            string userObjectId = ClaimsPrincipal.Current.FindFirst(Globals.ObjectIdClaimType).Value;

            // MULTITENANT - need to formulate GraphServiceRoot from user's tenant instead of app's tenant
            Uri graphServiceRoot = new Uri(ConfigHelper.GraphResourceId + "/" + ClaimsPrincipal.Current.FindFirst(Globals.TenantIdClaimType).Value);

            ActiveDirectoryClient graphClient = new ActiveDirectoryClient(graphServiceRoot, async () => { return GraphHelper.AcquireToken(userObjectId); });

            int batchCount = 0;
            List<Task<IBatchElementResult[]>> requests = new List<Task<IBatchElementResult[]>>();
            List<IReadOnlyQueryableSetBase<IDirectoryObject>> batch = new List<IReadOnlyQueryableSetBase<IDirectoryObject>>();
            IEnumerator<string> idIndex = objectIds.GetEnumerator();
            IEnumerator<string> nextId = objectIds.GetEnumerator();
            nextId.MoveNext();
            while (idIndex.MoveNext())
            {
                string thisId = idIndex.Current; // for delegate capture
                batch.Add(graphClient.DirectoryObjects.Where(o => o.ObjectId.Equals(thisId)));
                batchCount++;
                if (!nextId.MoveNext() || batchCount == 5)
                {
                    requests.Add(graphClient.Context.ExecuteBatchAsync(batch.ToArray()));
                    batchCount = 0;
                    batch.Clear();
                }
            }

            IBatchElementResult[][] responses = await Task.WhenAll<IBatchElementResult[]>(requests);
            foreach (IBatchElementResult[] batchResult in responses)
            {
                foreach (IBatchElementResult query in batchResult)
                {
                    if (query.SuccessResult != null && query.FailureResult == null)
                    {
                        if (query.SuccessResult.CurrentPage.First() is Group)
                        {
                            Group group = query.SuccessResult.CurrentPage.First() as Group;
                            groups.Add(group);
                        }
                        if (query.SuccessResult.CurrentPage.First() is DirectoryRole)
                        {
                            DirectoryRole role = query.SuccessResult.CurrentPage.First() as DirectoryRole;
                            roles.Add(role);
                        }
                        if (query.SuccessResult.CurrentPage.First() is User)
                        {
                            User user = query.SuccessResult.CurrentPage.First() as User;
                            users.Add(user);
                        }
                    }
                    else
                    {
                        throw new Exception("Directory Object Not Found.");
                    }
                }
            }

            return;
        }
    }
}
