## 0x00 前言

都说渗透测试的本质是信息收集，而其作为最重要的阶段，占据整个测试过程中约60%的工作量，可见其重要性。

那么现在就让我们来认识下这么个词汇，即开源情报（Open source intelligence，简称OSINT），这项技术可以帮助我们有效收集目标在网路上所暴露的信息。根据收集的有用信息，可以大大提高我们渗透测试的成功率。

## 0x01 信息收集

### 1.1 Osintframework.com

在信息收集之前，如果没有一个好的思路，那收集信息的过程，将会感觉迷茫，效率也会较低。这时候具有清晰的思路框架来获取和使用开源网络情报，将会使你的工作效率大幅度提升。OSINT Framework这个情报框架，会以思维导图的方式教会你更高效得捕获情报。

![图片](https://uploader.shimo.im/f/bt9TTRGLoMdNhGha.gif?fileGuid=pQdRDvkx68gKVXTx)

当然，以上只是提供一种思路。

实践是检验真理的唯一标准。有了思路，接下来就是实践啦~ **secjuice.com** 将以实际案例的方式讲解一些信息收集的思路，相信你看完之后会收获满满~

### 1.2 [secjuice.com](http://www.secjuice.com/tag/osint/) 

这是一个综合性的osint应用博客，致力于以实际案例的方式提供各类情况的实际应对方法

![图片](https://uploader.shimo.im/f/KizfCQYyugHr01Nn.gif?fileGuid=pQdRDvkx68gKVXTx)



## 0x02 搜索子域名

### 2.1 [subdomains-enumeration-cheatsheet](https://pentester.land/cheatsheets/2018/11/14/subdomains-enumeration-cheatsheet.html)

这是一篇博文，里面讲了我们应该如何借助搜索引擎、公共数据及开源工具等来进行信息搜集。其以简单案例的方式来给我们讲述这些工具的作用及基础使用方法。

![图片](https://uploader.shimo.im/f/fBZdJphPwYTarN5A.png!thumbnail?fileGuid=pQdRDvkx68gKVXTx)

### 2.2 [crt.sh](https://crt.sh/)（推荐）

这是一款子域名收集器，只需在搜索框中键入所需查询的域名，即可获取到其子域名暴露历史。 

<img src="https://image-1302887441.cos.ap-nanjing.myqcloud.com/Screen%20Recording%202021-01-30%20at%2012.21.37.gif" alt="Screen Recording 2021-01-30 at 12.21.37" style="zoom:80%;" />

相关工具还有  **[Amass](https://github.com/OWASP/Amass)，[subfinder](https://github.com/projectdiscovery/subfinder)，[findomain](https://github.com/Edu4rdSHL/findomain/)，[OneForAll](https://github.com/shmilylty/OneForAll/blob/master/README.en.md)，[assetfinder](https://github.com/tomnomnom/assetfinder)，[Sudomy](https://github.com/Screetsec/Sudomy)**。 建议开始使用它们配置API密钥，然后开始测试其他工具或可能性。

另一个较为有趣的工具是 **[gau](https://github.com/lc/gau)**。它从 AlienVault 的 Open Threat Exchange，Wayback Machine 和 Common Crawl 中获取任何给定域的已知URL。

### 2.3 [chaos](https://chaos.projectdiscovery.io/#/)

![图片](https://uploader.shimo.im/f/JsCpZYiP65HskBDg.png!thumbnail?fileGuid=pQdRDvkx68gKVXTx)

该项目**免费提供**与漏洞赏金计划有关的所有子域。

[https://github.com/dr-0x0x/chaospy](https://github.com/dr-0x0x/chaospy)

[https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

以上两个项目可以帮你更快得找到子域，解析它们（包括JS文件）在搜索使用子域名[SubDomainizer](https://github.com/nsonaniya2010/SubDomainizer)或[subscraper](https://github.com/Cillian-Collins/subscraper)。

### 2.4 RapidDNS

该工具可通过用户提供的域名查询出其近乎所有的解析记录(A、MX记录)

<img src="https://image-1302887441.cos.ap-nanjing.myqcloud.com/Screen%20Recording%202021-01-30%20at%2012.17.19.gif" alt="Screen Recording 2021-01-30 at 12.17.19" style="zoom:80%;" />

并且我们还借助其强大的 [RapidDNS API接口](https://rapiddns.io/) 并配合bash脚本编写方法以用于快速查找子域

```bash
rapiddns(){
	curl -s "https://rapiddns.io/subdomain/$1?full=1" \
	| grep -oP '_blank">\K[^<]*' \
	| grep -v http \
	| sort -u 
}

>>> rapiddns baidu.com
0007735.com
000awi.whwitc.com
001.xx14.cn
001480.bzsww.cn
001e4m76.ztxweek.com
001k21kx2.newcampana.com
001o34l9.ztxweek.com
...
```
### 2.5 [shodan.io](https://www.shodan.io/home)

这是一款适用于安全从业者使用的搜索引擎，你可以在这里轻松得搜索暴露在互联网上的资产。 它以分布式的方式对整个Ipv4网段进行扫描，并探测每一个可以被访问到的主机。

例如我们现在希望在在shodan中查询所有开放了8088端口并暴露在公网上的主机，如下所示：

<img src="https://image-1302887441.cos.ap-nanjing.myqcloud.com/Screen%20Recording%202021-01-30%20at%2012.25.42.gif" alt="Screen Recording 2021-01-30 at 12.25.42" style="zoom:80%;" />

总共获取到约11w的结果，而这些内容都是可以被查看的

## 0x04 总结回顾

估计你也发现啦，一个个的网页打开太麻烦啦~这时候有个工具一键搜索就会简单快速很多，那就敬请期待吧
