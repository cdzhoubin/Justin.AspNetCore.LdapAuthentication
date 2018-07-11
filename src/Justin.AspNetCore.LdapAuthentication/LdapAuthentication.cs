using Microsoft.Extensions.Options;
using Novell.Directory.Ldap;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Justin.AspNetCore.LdapAuthentication
{
    /// <summary>
    /// A class that provides password verification against an LDAP store by attempting to bind.
    /// </summary>
    public class LdapAuthentication : IDisposable
    {
        private readonly LdapAuthenticationOptions _options;
        private readonly LdapConnection _connection;
        private bool _isDisposed = false;

        /// <summary>
        /// Initializes a new instance with the the given options.
        /// </summary>
        /// <param name="options"></param>
        public LdapAuthentication(LdapAuthenticationOptions options)
        {
            _options = options ?? throw new ArgumentNullException(nameof(options));
            if (string.IsNullOrEmpty(_options.Hostname))
            {
                throw new InvalidOperationException("The LDAP Hostname cannot be empty or null.");
            }

            _connection = new LdapConnection();
        }

        /// <summary>
        /// Cleans up any connections and other resources.
        /// </summary>
        public void Dispose()
        {
            if (_isDisposed)
            {
                return;
            }

            _connection.Dispose();
            _isDisposed = true;
        }

        /// <summary>
        /// Gets a value that indicates if the password for the user identified by the given DN is valid.
        /// </summary>
        /// <param name="distinguishedName"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        public bool ValidatePassword(string distinguishedName, string password)
        {
            if (_isDisposed)
            {
                throw new ObjectDisposedException(nameof(LdapConnection));
            }

            _connection.Connect(_options.Hostname, _options.Port);

            try
            {
                _connection.Bind(distinguishedName, password);
                return _connection.Bound;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine(ex.Message);
                return false;
            }
            finally
            {
                _connection.Disconnect();
            }
        }
        /// <summary>
        /// 修改用户密码
        /// </summary>
        /// <param name="distinguishedName"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        public bool ResetPassword(string distinguishedName, string password)
        {
            if (_isDisposed)
            {
                throw new ObjectDisposedException(nameof(LdapConnection));
            }
            if (string.IsNullOrEmpty(_options.ManagerDn))
            {
                throw new InvalidOperationException("The LDAP ManagerDn cannot be empty or null.");
            }

            _connection.Connect(_options.Hostname, _options.Port);

            try
            {
                _connection.Bind(_options.ManagerDn, _options.ManagerPassword);
                if (_connection.Bound)
                {
                    List<LdapModification> modifications = new List<LdapModification>();
                    LdapAttribute sPassword = new LdapAttribute("userPassword", CreatePasswrod(password));
                    
                    modifications.Add(new LdapModification(LdapModification.REPLACE, sPassword));
                    _connection.Modify(distinguishedName, modifications.ToArray());
                    return true;
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine(ex.Message);
            }
            finally
            {
                _connection.Disconnect();
            }
            return false;
        }
        /// <summary>
        /// 搜索DN中的用户
        /// </summary>
        /// <param name="dn"></param>
        /// <returns></returns>
        public Dictionary<string, string> Search(string dn)
        {

            if (_isDisposed)
            {
                throw new ObjectDisposedException(nameof(LdapConnection));
            }

            if (string.IsNullOrEmpty(_options.ManagerDn))
            {
                throw new InvalidOperationException("The LDAP ManagerDn cannot be empty or null.");
            }

            _connection.Connect(_options.Hostname, _options.Port);

            try
            {
                _connection.Bind(_options.ManagerDn, _options.ManagerPassword);
                if (_connection.Bound)
                {
                    Dictionary<string, string> list = new Dictionary<string, string>();
                    LdapSearchResults lsc = _connection.Search(dn, LdapConnection.SCOPE_SUB, _options.SearchFilter, new string[] { "uid" }, false);
                    while (lsc.hasMore())
                    {
                        LdapEntry nextEntry = lsc.next();
                        list.Add(nextEntry.getAttribute("uid").StringValue.ToLower(), nextEntry.DN);

                    }
                    return list;
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine(ex.Message);
            }
            finally
            {
                _connection.Disconnect();
            }
            return new Dictionary<string, string>();
        }

        private string CreatePasswrod(string password)
        {
            var algorithmName = _options.PasswordHash.ToString().ToUpper();
            using (var algorithm = HashAlgorithm.Create(algorithmName))
            {
                if (algorithm != null)
                {
                    return  string.Format("{{{1}}}{0}", Convert.ToBase64String(algorithm.ComputeHash(Encoding.ASCII.GetBytes(password))), algorithmName);
                }
            }
            return password;
        }
    }

}
