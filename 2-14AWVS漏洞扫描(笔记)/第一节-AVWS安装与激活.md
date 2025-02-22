# 第一节-AWVS安装与激活

## 1.AWVS简介

AWVS（Acunetix Web Vulnerability Scanner）是一款知名的网络漏洞扫描工具，通过网络爬虫测试网站安全，检测流行的Web应用攻击，如跨站脚本、sql 注入等。据统计，75% 的互联网攻击目标是基于Web的应用程序。

## 2.为什么要用AWVS

在今天，网站的安全是容易被忽视的，黑客具备广泛的攻击手段，例SQL注入，XSS，文件包含，目录遍历，参数篡改，认证攻击等，虽然你配置了正确的防火墙和WAF，但是这些安全防御软件仍然存在策略性的绕过，因此，需要您定期的扫描你的web应用，但是手动检测你所有的web应用是否存在安全漏洞比较复杂和费时，所以您需要一款自动化的web漏洞扫描工具来检测您的web应用是否存在安全漏洞。

## 3.windows 安装

1.解压 awvs14补丁.zip

![image.png](https://fynotefile.oss-cn-zhangjiakou.aliyuncs.com/fynote/1762/1641348406000/81e865bc2d964e5992df154d068e9b00.png)

2.双击 acunetix_14.1.210316110.exe 安装

![image.png](https://fynotefile.oss-cn-zhangjiakou.aliyuncs.com/fynote/1762/1641348406000/2d71bb4195454a4694ce88dd6c3ff88e.png)

3.点击【是】

![image.png](https://fynotefile.oss-cn-zhangjiakou.aliyuncs.com/fynote/1762/1641348406000/0f9e40ee7a7f487199ebcbcbd829cccd.png)

4.点击【Next】

![image.png](https://fynotefile.oss-cn-zhangjiakou.aliyuncs.com/fynote/1762/1641348406000/4a57a401dc784646bb780f98ff4f5c44.png)

5.点击【I accept the agreement 】,点击【Next】

![image.png](https://fynotefile.oss-cn-zhangjiakou.aliyuncs.com/fynote/1762/1641348406000/bf133d8a4e0a4c82b83f777bb7b8aa69.png)

6.选择喜欢的位置安装，点击【Next】

![image.png](https://fynotefile.oss-cn-zhangjiakou.aliyuncs.com/fynote/1762/1641348406000/88b1d9decc53420f8e913d962bf9f0c0.png)

7.选择喜欢的位置保存 Data，点击【Next】

![image.png](https://fynotefile.oss-cn-zhangjiakou.aliyuncs.com/fynote/1762/1641348406000/0b33e0cefcb848b395a5414cb71afae4.png)

8.输入账号名：admin@msb.com,密码：m123456@，点击【Next】

![image.png](https://fynotefile.oss-cn-zhangjiakou.aliyuncs.com/fynote/1762/1641348406000/deb2586fac9942e68ecf8b0f848de948.png)

9.选择【Allow remote access to Acunetix】，选择IP，点击【Next】

![image.png](https://fynotefile.oss-cn-zhangjiakou.aliyuncs.com/fynote/1762/1641348406000/20d3c97cb28d407ba52d8ad48a9320ee.png)

10.点击【Next】

![image.png](https://fynotefile.oss-cn-zhangjiakou.aliyuncs.com/fynote/1762/1641348406000/9967226ab34146a0bfeab18109f1eb05.png)

11.点击【install】

![image.png](https://fynotefile.oss-cn-zhangjiakou.aliyuncs.com/fynote/1762/1641348406000/fd5c6d67cf7a4be19d5c1348d7e11252.png)

12.等待安装完成

![image.png](https://fynotefile.oss-cn-zhangjiakou.aliyuncs.com/fynote/1762/1641348406000/def992e831474a3b82acb84da82f5d0d.png)

13.点击【是】

![image.png](https://fynotefile.oss-cn-zhangjiakou.aliyuncs.com/fynote/1762/1641348406000/057f985ac8a34101aa55e2255c31519d.png)

14.点击【Finsh】

![image.png](https://fynotefile.oss-cn-zhangjiakou.aliyuncs.com/fynote/1762/1641348406000/41c819b1c8014895a7a808f75f888790.png)

![image.png](https://fynotefile.oss-cn-zhangjiakou.aliyuncs.com/fynote/1762/1641348406000/b47d1c4b81d448098ca2effdf805161f.png)

15.右键【我的电脑】，点击【管理】，选择【服务和应用成序】,点击【服务】

![image.png](https://fynotefile.oss-cn-zhangjiakou.aliyuncs.com/fynote/1762/1641348406000/a9bf3bb1a1b9418ab5567e2aa325bbe4.png)

16.右键【Acunetix】和【Acunetix Database】，停止Acunetix和Acunetix Database服务

![image.png](https://fynotefile.oss-cn-zhangjiakou.aliyuncs.com/fynote/1762/1641348406000/99b73f6746b74eb5aba49d0ae808e4e1.png)

![image.png](https://fynotefile.oss-cn-zhangjiakou.aliyuncs.com/fynote/1762/1641348406000/292cbd039b4c4e959650b79fc48c08ae.png)

17.将【awvs14补丁】里的【license_info.json】 复制到【D:\ProgramData\Acunetix\shared\license】，点击【替换】

![image.png](https://fynotefile.oss-cn-zhangjiakou.aliyuncs.com/fynote/1762/1641348406000/3b23edb624d34503ac1bc702ee4d0497.png)

18.将【awvs14补丁】里的【wa_data.dat】复制到【D:\ProgramData\Acunetix\shared\license】

![image.png](https://fynotefile.oss-cn-zhangjiakou.aliyuncs.com/fynote/1762/1641348406000/49338f031ce9493998c03de87ed9ccbc.png)

19.将【awvs14补丁】里的【wvsc.exe】复制到【D:\Program Files (x86)\Acunetix\14.1.210316110】

![image.png](https://fynotefile.oss-cn-zhangjiakou.aliyuncs.com/fynote/1762/1641348406000/8cafbb2374d54bbe85d296a8ca2f500b.png)

20.右键【Acunetix】和【Acunetix Database】，启动 Acunetix和Acunetix Database服务

![image.png](https://fynotefile.oss-cn-zhangjiakou.aliyuncs.com/fynote/1762/1641348406000/1e154e0b0ee54e6ea5f057bb25fb2dbc.png)

![image.png](https://fynotefile.oss-cn-zhangjiakou.aliyuncs.com/fynote/1762/1641348406000/0519547b40a34109be8693cb411089d3.png)

21.刷新浏览器的管理页面，点击【高级..】,点击【接受风险并继续】

![image.png](https://fynotefile.oss-cn-zhangjiakou.aliyuncs.com/fynote/1762/1641348406000/7bf0bc40416a4ef9995284f6b5bd9e2f.png)

22.登录管理员账号 admin@msb.com,密码：m123456@

![image.png](https://fynotefile.oss-cn-zhangjiakou.aliyuncs.com/fynote/1762/1641348406000/92cc8f0bd37f41348aef73b4e7a35655.png)

![image.png](https://fynotefile.oss-cn-zhangjiakou.aliyuncs.com/fynote/1762/1641348406000/ca33061b2639475e9291461f012c901d.png)

## 4. kali 安装AWVS

1.将acunetix_trial.sh 和 patch_awvs 复制到kali中

![image.png](https://fynotefile.oss-cn-zhangjiakou.aliyuncs.com/fynote/1762/1641348406000/2f852ac510d54e82bfac2e7cf3ac183a.png)

2.修改 acunetix_trial.sh 和 patch_awvs  权限

```
chmod 777 acunetix_trial.sh patch_awvs
```

3.执行安装命令

```
./acunetix_trial.sh
```

4.点击enter键继续

![image.png](https://fynotefile.oss-cn-zhangjiakou.aliyuncs.com/fynote/1762/1641348406000/de2f4d0b46ee421d896b08db9e016a80.png)

5.一直按住enter键继续

![image.png](https://fynotefile.oss-cn-zhangjiakou.aliyuncs.com/fynote/1762/1641348406000/047824864f324f0c89e6e37a7824fdb4.png)

6.输入yes，点击 【回车】

![image.png](https://fynotefile.oss-cn-zhangjiakou.aliyuncs.com/fynote/1762/1641348406000/aa3d4d4cb50d4e92af6685bc90a9108e.png)

7.输入主机名称，点击【回车】

![image.png](https://fynotefile.oss-cn-zhangjiakou.aliyuncs.com/fynote/1762/1641348406000/e91bc8a405054d6fadb58fbc76051884.png)

8.输入email ：【admin@msb.com】点击【回车】

![image.png](https://fynotefile.oss-cn-zhangjiakou.aliyuncs.com/fynote/1762/1641348406000/f3d402f52cdd46e59bdeda18fd704374.png)

9.输入Password：【m123456@】点击回车，输入【m123456@】，点击回车

![image.png](https://fynotefile.oss-cn-zhangjiakou.aliyuncs.com/fynote/1762/1641348406000/00b3b7c2c16a4a899c607e7aadde1aa0.png)

10.等待安装完成

![image.png](https://fynotefile.oss-cn-zhangjiakou.aliyuncs.com/fynote/1762/1641348406000/9431cda311874684ba3251424cf8b5a7.png)

11.把破解补丁复制到指定目录下，并设置好权限，直接运行即可

```
cp -a patch_awvs /home/acunetix/.acunetix_trial/v_190325161/scanner/
chmod 777 /home/acunetix/.acunetix_trial/v_190325161/scanner/patch_awvs
/home/acunetix/.acunetix_trial/v_190325161/scanner/patch_awvs
```

![image.png](https://fynotefile.oss-cn-zhangjiakou.aliyuncs.com/fynote/1762/1641348406000/db407d2b36ac498d8e47e079cf18de63.png)

12.为了保护原始license不失效，这里尽快执行如下的命令，不然license会被修改然后就无法破解成功。

```
chattr +i：chattr 是 Linux 系统中的一个命令，用于更改文件属性。+i 选项表示将文件设置为不可变（immutable）。不可变属性意味着即使是超级用户（root）也不能修改、删除或重命名这个文件。
```

```
chattr +i /home/acunetix/.acunetix_trial/data/license/license_info.json
rm -fr /home/acunetix/.acunetix_trial/data/license/wa_data.dat
touch /home/acunetix/.acunetix_trial/data/license/wa_data.dat
chattr +i /home/acunetix/.acunetix_trial/data/license/wa_data.dat
```

13.重新启动AWVS进程

```bash
systemctl restart acunetix_trial.service #重启进程
systemctl start acunetix_trial.service   #启动进程
systemctl stop acunetix_trial.service    #停止进程
systemctl status acunetix_trial.service  #查看进行状态 
```

14.访问：[https://127.0.0.1:13443/](https://127.0.0.1:13443/) 进入AWVS首页，点击【Advanced..】,点击【Accept the Risk and Continue】

![image.png](https://fynotefile.oss-cn-zhangjiakou.aliyuncs.com/fynote/1762/1641348406000/228eea4050e84c5bb1a2aa7dddee9c8b.png)

15.输入用户名：admin@msb.com,密码：m123456@ 进行登录

![image.png](https://fynotefile.oss-cn-zhangjiakou.aliyuncs.com/fynote/1762/1641348406000/5375b020a8184250b679aea740cb4c6e.png)

![image.png](https://fynotefile.oss-cn-zhangjiakou.aliyuncs.com/fynote/1762/1641348406000/24f077d4968a4f16be2c42d0ca473c9d.png)

![image.png](https://fynotefile.oss-cn-zhangjiakou.aliyuncs.com/fynote/1762/1641348406000/7de783bf900d46e581cbc78c26b9420c.png)
