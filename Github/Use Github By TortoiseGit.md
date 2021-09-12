# **通过TortoiseGet访问GitHub**

1. 下载并安装Git

   https://git-scm.com/download/win

2. 安装TortoiseGit和语言包

   https://tortoisegit.org/download/

3. 配置TortoiseGit

   1）配置用户名和密码

   ​	TortoiseGit -> Setting -> Git

   ​	输入用户名和Email并确认

   2）配置SSH客户端

   ​	TortoiseGit -> Setting -> Network

   ​	需将SSH客户端工具配置为C:\Program Files\Git\usr\bin\ssh.exe

   ​	然后应用并确认

4. 生成秘钥

   打开Git命令行工具

   打开~/.ssh并删除旧秘钥

   生成新秘钥，e.g

   ​	ssh-keygen.exe -t rea -C "{EmailAddress}"

5. 在GitHub中配置SSH秘钥

   打开GitHub配置网页以新增SSH秘钥

   ​	https://github.com/settings/keys

   将TortoiseGit的公钥粘贴到GitHub上，e.g

   ​	C:\Users\\{UserName}\\.ssh\id_rsa.pub

