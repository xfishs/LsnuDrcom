# LsnuDrcom
第三方乐山师范学院学生联网客户端drcom5.20（x）
# what's LsnuDrcom?
LsnuDrcom 是根据乐山师范学院校园网客户端Drcom5.20(x)编写的第三方客户端python版，基于python2.7，适用于乐山师范学院学生宿舍联网适用。可用于openWrt路由器（需要安装python2.7）。

如果师院的学弟学妹们有什么疑问，可以加qq群：348609229

# Configurate

## 配置文件 ( drcom.py ) ：
# [config]
### username='LSL*********'	# 账号
### password='************'	# 密码
### iface = 'eth0.2'  #路由网卡名称

配置好后 将源码利用winScp上传至路由器  /etc  目录下


拨号在putty执行 python /etc/drcom.py  后台执行则是在后面加 &   既是执行 python /etc/drcom.py &

通常因为首次拨号路由器中还没有ip 会拨号失败。 再次拨号即可

拨号成功 会呈现规律性的心跳包打印。

## Special Thanks

LsnuDrcom 的诞生很不容易， 看了很多大佬的源码，思路，具体参考了多少资料我自己也不知道了，但是还是感谢各位大佬，如果哪位大佬看到哪些代码片段与你的比较相似，那么很有可能我就是借鉴了你的代码片段，感谢。


## Special Attention

作者开源的初衷即是为了学习交流，严禁使用该源代码从事商业活动并从中谋取利益，如有违反，后果与作者无关。
