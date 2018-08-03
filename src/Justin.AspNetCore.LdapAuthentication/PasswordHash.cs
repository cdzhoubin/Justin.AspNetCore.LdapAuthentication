namespace Justin.AspNetCore.LdapAuthentication
{
    /// <summary>
    /// 密码Hash算法
    /// </summary>
    public enum PasswordHash
    {
        /// <summary>
        /// 
        /// </summary>
        Sha,
        /// <summary>
        /// 
        /// </summary>
        Sha256,
        /// <summary>
        /// 
        /// </summary>
        Sha384,
        /// <summary>
        /// 
        /// </summary>
        Sha512,
        /// <summary>
        /// 
        /// </summary>
        Ssha,
        /// <summary>
        /// 
        /// </summary>
        Ssha256,
        /// <summary>
        /// 
        /// </summary>
        Ssha384,
        /// <summary>
        /// 
        /// </summary>
        Ssha512,
        /// <summary>
        /// 
        /// </summary>
        Md5,
        /// <summary>
        /// 
        /// </summary>
        Smd5,
        /// <summary>
        /// 
        /// </summary>
        Pkcs5S2,
        /// <summary>
        /// 
        /// </summary>
        Crypt,
        ///// <summary>
        ///// 
        ///// </summary>
        //CRYPT_MD5,
        ///// <summary>
        ///// 
        ///// </summary>
        //CRYPT_SHA_256,
        ///// <summary>
        ///// 
        ///// </summary>
        //CRYPT_SHA_512
        
    }
}