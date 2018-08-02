using System;
using System.Diagnostics;
using System.IO;

namespace Justin.AspNetCore.LdapAuthentication
{
    /// <summary>
    /// 密码工具类
    /// </summary>
    public static class PasswordTool
    {
        /// <summary>
        /// slappasswd命令路径设置
        /// </summary>
        public static void SetHashToolPath(string path)
        {
            if (!File.Exists(path))
            {
                throw new FileNotFoundException("slappasswd命令文件不存在", path);
            }
            _hashPaswordToolsPath = path;
        }
        private static string _hashPaswordToolsPath = "E:\\OpenLDAP\\slappasswd.exe";
        /// <summary>
        /// 密码Hash计算方法
        /// </summary>
        /// <param name="password">原密码</param>
        /// <param name="hashMethod">hash算法</param>
        /// <returns>hash后密码</returns>
        public  static string HashPasswrod(string password,string hashMethod)
        {
            var hashPassword = "";
            var error = "";
            var process = new Process
            {
                StartInfo =
                {
                    FileName = _hashPaswordToolsPath,
                    Arguments = $"-h {{{hashMethod}}} -s {password}",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true
                }
            };

            process.OutputDataReceived += (sender, data) =>
            {
                Console.WriteLine(data.Data);
                hashPassword = data.Data;
            };
            process.StartInfo.RedirectStandardError = true;
            process.ErrorDataReceived += (sender, data) => { error = data.Data; Console.WriteLine(data.Data); };
            bool result = process.Start();
            if (result)
            {
                hashPassword = process.StandardOutput.ReadToEnd();
                process.WaitForExit();
                if (!string.IsNullOrEmpty(error))
                {
                    throw new Exception(error);
                }
                
            }
            else
            {
                throw new Exception("计算密码hash出错。");
            }
            return hashPassword.Trim(new []{'\r','\n'});
        }
    }
}

