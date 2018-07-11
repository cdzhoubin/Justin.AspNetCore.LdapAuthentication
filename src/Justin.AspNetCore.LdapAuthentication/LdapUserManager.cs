using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Threading;

namespace Justin.AspNetCore.LdapAuthentication
{
    /// <summary>
    /// Provides a custom user store that overrides password related methods to valid the user's password against LDAP.
    /// </summary>
    /// <typeparam name="TUser"></typeparam>
    public class LdapUserManager<TUser> : Microsoft.AspNetCore.Identity.UserManager<TUser>
        where TUser : class
    {
        private readonly LdapAuthenticationOptions _ldapOptions;

        /// <summary>
        /// Initializes an instance.
        /// </summary>
        /// <param name="store"></param>
        /// <param name="optionsAccessor"></param>
        /// <param name="passwordHasher"></param>
        /// <param name="userValidators"></param>
        /// <param name="passwordValidators"></param>
        /// <param name="keyNormalizer"></param>
        /// <param name="errors"></param>
        /// <param name="services"></param>
        /// <param name="logger"></param>
        /// <param name="ldapOptions"></param>
        public LdapUserManager(
            IUserStore<TUser> store, IOptions<IdentityOptions> optionsAccessor, IPasswordHasher<TUser> passwordHasher, IEnumerable<IUserValidator<TUser>> userValidators, IEnumerable<IPasswordValidator<TUser>> passwordValidators, ILookupNormalizer keyNormalizer, IdentityErrorDescriber errors, IServiceProvider services, ILogger<UserManager<TUser>> logger, IOptions<LdapAuthenticationOptions> ldapOptions
        ) : base(
            store, optionsAccessor, passwordHasher, userValidators, passwordValidators, keyNormalizer, errors, services, logger
        )
        {
            _ldapOptions = ldapOptions.Value;
        }

        /// <summary>
        /// Checks the given password agains the configured LDAP server.
        /// </summary>
        /// <param name="user"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        public override async Task<bool> CheckPasswordAsync(TUser user, string password)
        {
            using (var auth = new LdapAuthentication(_ldapOptions))
            {
                string dn = await GetUserDn(user);
                if (auth.ValidatePassword(dn, password))
                {
                    return true;
                }
            }

            return false;
        }

        private async Task<string> GetUserDn(TUser user)
        {
            var store = Store as IUserLdapStore<TUser>;
            if (store != null)
            {
                return await store.GetDistinguishedNameAsync(user);
            }

            return await Store.GetNormalizedUserNameAsync(user, CancellationToken.None);
        }
        /// <summary>
        /// Throws a NotSupportedException.
        /// </summary>
        /// <param name="user"></param>
        /// <param name="currentPassword"></param>
        /// <param name="newPassword"></param>
        /// <returns></returns>
        public override Task<IdentityResult> ChangePasswordAsync(TUser user, string currentPassword, string newPassword)
        {
            using (var auth = new LdapAuthentication(_ldapOptions))
            {
                string dn = GetUserDn(user).Result;
                if (auth.ValidatePassword(dn, currentPassword))
                {
                    if (auth.ResetPassword(dn, newPassword))
                    {
                        return Task.FromResult(IdentityResult.Success);
                    }
                }
            }

            return Task.FromResult(IdentityResult.Failed());
        }

        /// <summary>
        /// Throws a NotSupportedException.
        /// </summary>
        /// <param name="user"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        public override Task<IdentityResult> AddPasswordAsync(TUser user, string password)
        {
            throw new NotSupportedException();
        }

        /// <summary>
        /// Always returns true.
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        public override Task<bool> HasPasswordAsync(TUser user)
        {
            return Task.FromResult(true);
        }

        /// <summary>
        /// Throws a NotSupportedException.
        /// </summary>
        /// <param name="store"></param>
        /// <param name="user"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        protected override Task<PasswordVerificationResult> VerifyPasswordAsync(IUserPasswordStore<TUser> store, TUser user, string password)
        {
            throw new NotSupportedException();
        }

        /// <summary>
        /// Throws a NotSupportedException.
        /// </summary>
        /// <param name="user"></param>
        /// <param name="token"></param>
        /// <param name="newPassword"></param>
        /// <returns></returns>
        public override Task<IdentityResult> ResetPasswordAsync(TUser user, string token, string newPassword)
        {
            using (var auth = new LdapAuthentication(_ldapOptions))
            {
                string dn = GetUserDn(user).Result;
                if (auth.ResetPassword(dn, newPassword))
                {
                    return Task.FromResult(IdentityResult.Success);
                }

            }

            return Task.FromResult(IdentityResult.Failed());
        }
    }

}
