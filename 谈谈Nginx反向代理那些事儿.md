## 前期回顾

前几天在waf上配置一个策略，配置完之后策略怎么都不生效。找厂商售后排查了半天，对方各种抓包，日志追踪，最后还是没定位到问题。后面得出一个结论竟然是流量没走waf,于是我开启web访问记录，发现流量是有走waf的，于是就跟他们说了下网络架构。想到不应该考虑外面的流量是什么，应该考虑流量到waf上是什么样的。于是自己倒腾了一下，把问题解决了。期间提到了Nginx反向代理，他们一脸懵逼问我“Nginx是什么？反向代理是什么？”貌似不止一次有厂商的售后问我这个问题了，今天就大致整理一下吧。

## 反向代理

说到反向代理，那么究竟什么是反向代理呢？举个栗子吧。

对于移动通信来说，大家都比较熟悉，移动通信客户服务中心的客服电话是10086，它是一个统一的客服电话入口，当我们需要咨询或是投诉话费、账单相关问题时，只需要拨打10086电话，然后按0进入人工服务台即可，对面究竟是谁来接，我们不care，我们唯一需要确定的是，对面会有人来回应我们的电话（相当于服务器响应客户端请求），即使是很多人在同一时刻拨打10086（并发），也能得到响应。这个场景里面，拨打电话的我们，就是Client（客户端），而10086的客服就是Server（服务端），服务端采用了统一的入口，具体如何分发或转接，对于Client来说就类似一个黑盒。反向代理就是这个道理，如图所示，它代理的就是Server端。


![图片](https://uploader.shimo.im/f/ZZPk7TmmdH7Ch1We.png!thumbnail?fileGuid=Grg3rKQGJ99QDgdj)

**结论就是，反向代理服务器对于客户端而言它就像是原始服务器，并且客户端不需要进行任何特别的设置**。客户端向反向代理的命名空间(name-space)中的内容发送普通请求，接着反向代理服务器将判断向何处(原始服务器)转交请求，并将获得的内容返回给客户端，就像这些内容原本就是它自己的一样。

反向代理服务器通常有两种模型，它可以作为内容服务器的替身，也可以作为内容服务器集群的负载均衡器。

**一个典型的HTTP处理周期是这样的：**

客户端发送HTTP请求 –>Nginx基于配置文件中的位置选择一个合适的处理模块 ->(如果有)负载均衡模块选择一台后端服务器 –>处理模块进行处理并把输出缓冲放到第一个过滤模块上 –>第一个过滤模块处理后输出给第二个过滤模块 –>然后第二个过滤模块又到第三个 –>依此类推 –> 最后把响应发给客户端。

Nginx本身做的工作实际很少，当它接到一个HTTP请求时，它仅仅是通过查找配置文件将此次请求映射到一个location block，而此location中所配置的各个指令则会启动不同的模块去完成工作，因此模块可以看做Nginx真正的劳动工作者。`通常一个location中的指令会涉及一个handler模块和多个filter模块（当然，多个location可以复用同一个模块）。handler模块负责处理请求，完成响应内容的生成，而filter模块对响应内容进行处理。`

最简单的实例就是，nginx仅仅处理静态不处理动态内容，动态内容交给后台的apache server来处理，具体设置为：在nginx.conf中修改：`location ~ /.php$ { proxy_pass xx.xx.xx.xx:80 ; }`这样当客户端访问`localhost:8080/index.html`的时候，前端的nginx会自动进行响应；

当用户访问`localhost:8080/test.php`的时候(这个时候nginx目录下根本没有该文件)，但是通过上面的设置`location ~ /.php$`(表示正则表达式匹配以.php结尾的文件，详情参看location是如何定义和匹配的[http://wiki.nginx.org /NginxHttpCoreModule](http://wiki.nginx.org%20/NginxHttpCoreModule)) ，nginx服务器会自动pass给xx.xx.xx.xx的apache服务器了。该服务器下的test.php就会被自动解析，然后将html的 结果页面返回给nginx，然后nginx进行显示(如果nginx使用memcached模块或者squid还可以支持缓存)



**了解了什么是反向代理之后，现在我们来说说什么是正向代理。**

## 正向代理

**正向代理（Forward Proxy**）通常都被简称为代理，就是在用户无法正常访问外部资源，比方说受到GFW的影响无法访问twitter的时候，我们可以通过代理的方式，让用户绕过防火墙，从而连接到目标网络或者服务。

正向代理的工作原理就像一个跳板，比如：我访问不了google.com，但是我能访问一个代理服务器A，A能访问google.com，于是我先连上代理服务器A，告诉他我需要google.com的内容，A就去取回来，然后返回给我。从网站的角度，只在代理服务器来取内容的时候有一次记录，有时候并不知道是用户的请求，也隐藏了用户的资料，这取决于代理告不告诉网站。

**结论就是，正向代理是一个位于客户端和原始服务器(origin server)之间的服务器。**为了从原始服务器取得内容，客户端向代理发送一个请求并指定目标(原始服务器)，然后代理向原始服务器转交请求并将获得的内容返回给客户端。

了解了基本原理之后，下面来看个业务场景吧。

## 业务场景：反向代理至二级域名

**一级域名->云服务器(proxy)->二级域名（通过CNAME绑定到xxx.github.io）**

首先通过CNAME方式将xyz.xxx.com子域名绑定到xxx.github.io，然后我们将之前nginx配置的直接转发到github的地方改成xyz.xxx.com就OK了。具体的配置内容如下

```plain
server {
    listen 80;
    server_name xxx.com www.xxx.com;
    root html;
    location / {
        proxy_set_header Host xyz.xxx.com;
        proxy_pass http://xyz.xxx.com;        #转发到github
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
    location ^~/assets/ {
        proxy_pass http://xyz.xxx.com/assets/;
    }
}
```
在nginx中添加了https（证书目前用的tx云解析的），配置如下
```plain
server {
    listen 443 ssl;  
    server_name www.xxx.com xxx.com; #填写绑定证书的域名
    ssl_certificate /usr/local/nginx/conf/1_csuldw.com_bundle.crt;  # 指定证书的位置，绝对路径
    ssl_certificate_key /usr/local/nginx/conf/2_csuldw.com.key;  # 绝对路径，同上
    ssl_session_timeout 5m; 
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2; #按照这个协议配置
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:HIGH:!aNULL:!MD5:!RC4:!DHE;#按照这个套件配置
    ssl_prefer_server_ciphers on; 
    location / {
        proxy_set_header Host xyz.xxx.com;
        proxy_pass https://xyz.xxx.com;        #转发请求
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
    location ^~/assets/ {
        proxy_pass https://xyz.xxx.com/assets/;
    }
}
```
目前一级域名xxx.com绑定的是自己的tx云服务器，经过nginx路由之后，会将一级域名指向二级域名xyz.xxx.com，而二级域名绑定的是xxx.github.io，所以当我们直接访问一级域名的时候，实际上响应的页面就是xxx.github.io。
## 

