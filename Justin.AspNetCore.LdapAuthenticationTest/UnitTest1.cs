using System;
using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using Justin.AspNetCore.LdapAuthentication;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Justin.AspNetCore.LdapAuthenticationTest
{
    [TestClass]
    public class UnitTest1
    {
        private LdapAuthenticationOptions options = new LdapAuthenticationOptions
        {
            Hostname = "192.168.0.145",
            ManagerDn = "cn=Manager,dc=devitd,dc=com",
            ManagerPassword = "rD4uhyctQylzU1AveU5m"
        };

        [TestMethod]
        public void TestValidatePassword()
        {
            using (var service = new LdapAuthentication.LdapAuthentication(options))
            {
                string user = "uid=test,ou=Admin,ou=DevPart,dc=devitd,dc=com";
                string password = "123456";
                var result = service.ValidatePassword(user, password);
                Assert.AreEqual(true, result);
            }
        }

        [TestMethod]
        public void TestChangePassword()
        {
            using (var service = new LdapAuthentication.LdapAuthentication(options))
            {
                string user = "uid=test,ou=Admin,ou=DevPart,dc=devitd,dc=com";
                string newPassword = "1234567";
                var result = service.ResetPassword(user, newPassword);
                Assert.AreEqual(true, result);
                result = service.ValidatePassword(user, newPassword);
                Assert.AreEqual(true, result);
            }
        }
        [TestMethod]
        public void TestSearch()
        {
            using (var service = new LdapAuthentication.LdapAuthentication(options))
            {
                var result = service.Search("ou=DevPart,dc=devitd,dc=com");
                Assert.AreEqual(true, result.Count > 0);
            }
        }
    }
}
