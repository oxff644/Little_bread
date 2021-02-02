## 背景介绍

ossec的rootcheck模块出现IO占满引起存储延时，严重影响业务。之前尝试过**对IO进行限速**，但是指标不治本。

在Github上看了很多issue之后，发现没有好的解决方案。查看官方的文档结合源码分析之后，发现作者针对**rootcheck模块**，只能设置频率的值（default every 2 hours）。因此，靠更改频率并不能解决并发问题，为了避免此种问题再次发生，忍痛之下只能将其关闭掉了。（万能大法：关闭不用呼哈哈哈哈）

**解决方法：关闭rootcheck模块**

考虑到**syscheck模块**也有导致IO占满的问题，于是对其进行了优化。

**优化思路：将所有的client作业时间平均分配到1周的7天之内，每天所需作业的部分client都将随机分配任务开始时间，区间为0点到6点的任意一刻。**

## 代码实现

```plain
import subprocess
import re
import os
import sys
from random import choice
def success(_):
    print("\033[32m[+]{0}\033[0m".format(_))
def info(_):
    print("\033[36m[*]{0}\033[0m".format(_))
def warn(_):
    print("\033[33m[-]{0}\033[0m".format(_))
def error(_):
    print("\033[31m[x]{0}\033[0m".format(_))
def random_day():
    return choice(
        ("monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday")
    )
def random_time(start=0, end=6):
    hour = str(choice(range(start, end + 1)))
    minute = str(choice(range(0, 61))).rjust(2, "0")
    return "{0}:{1}".format(hour, minute)
def check_and_sub(item, T):
    k, v = item
    src, dst = [_() for _ in v]
    check_find = re.findall(src, T)
    info("({0})try match:\t{1}".format(k,src))
    if check_find:
        success("({0})ready for:\t{1}".format(k,dst))
        if k == "syscheck_time":
            T = re.sub(src, dst, T)
            k1, k2 = [_() for _ in regexs["syscheck_day"]]
            if not re.findall(k1, T):
                warn("no day, ready for:\t{0}".format(k2))
                T = T.replace(dst, "{0}\n\t{1}".format(dst, k2))
        else:
            T = re.sub(src, dst, T)
    return T
target = "/var/ossec/etc/ossec.conf"
if len(sys.argv) == 2 and sys.argv[1] == "test":
    target = "ossec.conf"
regexs = {
    # "syscheck": lambda text: re.sub(
    #     r"<syscheck>\s*<disabled>no<", "<syscheck>\n\t<disabled>yes<", text
    # ),
    "syscheck_time": (
        lambda: "<scan_time>[0-9apm:]{0,10}</scan_time>",
        lambda: "<scan_time>{0}</scan_time>".format(random_time()),
    ),
    "syscheck_day": (
        lambda: "<scan_day>.*?</scan_day>",
        lambda: "<scan_day>{0}</scan_day>".format(random_day()),
    ),
    "rootcheck": (
        lambda: r"<rootcheck>\s*<disabled>no<",
        lambda: "<rootcheck>\n\t<disabled>yes<",
    ),
}
if not os.path.exists(target):
    error("not exists:\t{0}".format(target))
    exit()
with open(target, "r") as f:
    datas = f.read()
with open(target, "w") as f:
    try:
        T = datas
        for _ in regexs.items():
            T = check_and_sub(_, T)
        f.write(T)
        subprocess.Popen("/var/ossec/bin/ossec-control restart",shell=True)
    except Exception as e:
        f.write(datas)
        error(str(e))
```
## 总结回顾

看到Github关于Ossec的rootcheck模块IO占满引起存储延时的issue有很多，也有一些解决方法避开根目录，只扫一些网站目录等。前期我也试了很多方法，比如错过业务高峰段，优化扫描规则，只扫描某些指定目录等。但是由于业务的特殊性，唯一可靠的解决方法就是关掉该模块并尽最大的可能避免这种问题出现。

## 相关延伸

* **Github：**[https://github.com/ossec/ossec-hids](https://github.com/ossec/ossec-hids)
* Ossec官网：[https://www.ossec.net/](https://www.ossec.net/)
