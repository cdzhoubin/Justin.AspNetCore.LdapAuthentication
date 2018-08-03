﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Justin.AspNetCore.LdapAuthentication
{
    /// <summary>
    /// Represents options that configure LDAP authentication.
    /// </summary>
    public class LdapAuthenticationOptions
    {
        /// <summary>
        /// Gets or sets the LDAP server host name.
        /// </summary>
        public string Hostname { get; set; }

        /// <summary>
        /// Gets or sets the TCP port on which the LDAP server is running. 
        /// </summary>
        public int Port { get; set; } = 389;

        /// <summary>
        /// 管理员dn
        /// </summary>
        public  string ManagerDn { get; set; }
        /// <summary>
        /// 管理员密码
        /// </summary>
        public  string ManagerPassword { get; set; }

        /// <summary>
        /// 用户搜索过虑字符串
        /// </summary>
        public string SearchFilter { get; set; } = "(objectclass=inetOrgPerson)";
        /// <summary>
        /// 密码Hash算法
        /// </summary>
        public PasswordHash PasswordHash { get; set; } = PasswordHash.Ssha;
    }
}
