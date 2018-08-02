using System;
using Justin.AspNetCore.LdapAuthentication;

namespace PasswordTest
{
    class Program
    {
        static void Main(string[] args)
        {
            PasswordTool.SetHashToolPath("d:\\OpenLDAP\\slappasswd.exe");
            var input = "123456";
            var result = PasswordTool.HashPasswrod(input, "sha512");
            Console.WriteLine(result);
            Console.ReadKey();
        }
    }
}
