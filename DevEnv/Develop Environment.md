目标：基于WSL2安装Ubuntu系统



1. 卸载原有App系统

   应用和功能 - Ubuntu X - 卸载

   Windows PowerShell

   wslconfig /l

   wslconfig /u Ubuntu

   

2. 下载WSL镜像

   Ubuntu 18.04

   https://aka.ms/wsl-ubuntu-1804

   Ubuntu 20.04

   http://221.1.23.13/Ubuntu_2004.2020.424.0_x64.appx.null?fid=osMWNjyQ7IIJta53RawmjYjRNf98MgAbAAAAAK16IjMDh3PFZlJUPmvGOkzsoyxa&mid=666&threshold=150&tid=8C2A3513FFA52E23B091E8DD0023064C&srcid=119&verno=1

   

3. 安装WSL版Ubuntu

   username：ubuntu

   password：admin

   

4. MobaXterm中连接Ubuntu

   section -> WSL

   sudo su

   

5. 更换国内源并更新

   cp -pP --remove-destination /etc/apt/sources.list /etc/apt/sources.list.bkp

   cat > /etc/apt/sources.list <<EOF

   deb http://mirrors.aliyun.com/ubuntu/ focal main restricted universe multiverse
   deb-src http://mirrors.aliyun.com/ubuntu/ focal main restricted universe multiverse

   deb http://mirrors.aliyun.com/ubuntu/ focal-security main restricted universe multiverse
   deb-src http://mirrors.aliyun.com/ubuntu/ focal-security main restricted universe multiverse

   deb http://mirrors.aliyun.com/ubuntu/ focal-updates main restricted universe multiverse
   deb-src http://mirrors.aliyun.com/ubuntu/ focal-updates main restricted universe multiverse

   deb http://mirrors.aliyun.com/ubuntu/ focal-proposed main restricted universe multiverse
   deb-src http://mirrors.aliyun.com/ubuntu/ focal-proposed main restricted universe multiverse

   deb http://mirrors.aliyun.com/ubuntu/ focal-backports main restricted universe multiverse
   deb-src http://mirrors.aliyun.com/ubuntu/ focal-backports main restricted universe multiverse

   EOF

   apt-get update && apt-get upgrade

   

6. 通过Windows资源管理器访问WSL文件系统

   C:\Users\HP\AppData\Local\Packages\CanonicalGroupLimited.UbuntuXX.XXonWindows_XXXX\LocalState\rootfs

   ReadOnly：\\\wsl$

   可建立桌面快捷方式

   

7. 安装C开发组件

   apt-get install build-essential gdb manpages-dev cmake git libcjson-dev python

   

8. 使用VSCode打开WSL中代码

   开始菜单中打开WSL对应的系统APP，如Ubuntu 20.04 LTS（其他SSH工具中无效）

   code . 使用VSCode打开当前目录（首次使用会自动安装VS Code Server）

   

9. 导入和导出

   导出：wsl --export Ubuntu-18.04 F:\WSL2_Ubuntu18.04.tar

   导入：wsl --import Ubuntu-18.04 F:\\Tmp F:\WSL2_Ubuntu18.04.tar
