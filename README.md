# ShellGenerate

## 简介

本工具是根据[那些牛马那些事儿](https://www.yuque.com/ni4n/blogs/wo2umt779c51re9v)中的本质马部分写的一个哥斯拉java类型webshell生成工具。

## 免责声明
- 本工具根据互联网已有思路进行编写，故而不保证当前免杀效果。
- 本工具仅用于研究与学习，请严格遵守当地法律法规，禁止使用本工具发起非法攻击等行为，基于非法攻击造成的后果由使用者负责。

## 使用说明
<br>
注意：需要将ShellGenerate.jar和templates目录放在同一文件夹下

<br>

完整参数
<br>

```
usage: ShellGenerate [-c <arg>] [-f <arg>] [-h] -k <arg> -p <arg> [-v <arg>]
 -c,--class <arg>     指定落地的类名称，默认为payload.class，建议修改为其他名称
 -f,--file <arg>      指定生成的脚本名称，默认为shell.jsp
 -h,--help            显示使用帮助
 -k,--key <arg>       指定shell的key
 -p,--pass <arg>      指定shell的pass
 -v,--version <arg>   指定生成shell的版本，默认为tomcat10以下，设为1则适配tomcat10

 ```


<br>

生成tomcat10以下的webshell，默认webshell文件名为shell.jsp，落地恶意类文件为payload.class

    java -jar .\ShellGenerate.jar -k [密钥] -p [密码]

指定落地恶意类文件，webshell为jsp文件

    java -jar .\ShellGenerate.jar -k [密钥] -p [密码] -c [落地的类名称]

指定生成适配tomcat10的webshell文件

    java -jar .\ShellGenerate.jar -k [密钥] -p [密码] -c [落地的类名称] -v 1 