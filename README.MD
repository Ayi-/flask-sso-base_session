# SSO单点登录系统

基于`flask`，以及通过`session`识别用户

该方案通过跳转`sso`服务器地址来记录同一个用户的信息，通过设置一个用户`sid`（session），并将其绑定到子系统`web-1`生成的`token`，当用户通过该`token`进行请求时，就能对应上用户信息。

时序图：

![](https://raw.githubusercontent.com/Ayi-/flask-sso-base_session/master/flask-sso-1.png)

原理步骤：

![](https://raw.githubusercontent.com/Ayi-/flask-sso-base_session/master/flask-sso-2.png)

### 流程

第一次访问：

1. 用户首先访问`web-1子`系统，系统检查用户的`cookie`中是否已经有一个`token`，没有就另外生成一个（随意设置，或者通过随机算法生成）。
2. 将`token`设置到`cookie`，发起`GET`请求到`SSO`服务器，请求参数包含`token`，`web-1`识别标志（可选），`next_url`（请求完后跳转到某一个地址）。
3. `SSO`服务器验证请求的可靠性，生成用户`sid`，将其保存到`session（cookie）`中，以此对应一个用户的登录信息。将用户的`token`与`sid`绑定到一起，保存到数据库，以后可以通过该`token`查询`sid`对应的信息。`SSO`设置重定向到`next_url`。
4. 重定向到`web-1`子系统，`web-1`从`cookie`获取用户`token`，并以此发起请求用户信息到`SSO`，`SSO`通过`token`查询`sid`，获取用户信息（现在为空），返回给`web-1`，`web-1`进行用户信息处理，返回界面。
5. 用户请求`web-1`登录界面，提交登录信息。`web-1`向`SSO`发起登录请求，参数为用户登录信息，用户`token`，`SSO`验证登录信息，登录成功后将用户信息保存到`token`对应的`sid`对应的数据结构中，返回用户信息。
6. `web-1`对用户信息进行处理，返回界面。

至此用户信息创建，并保存到`SSO`服务器中，子系统`web-1`通过用户`token`就能获取到对应的`sid`，以此就能获取对应的用户信息。

而`web-2`子系统，通过**步骤1**生成一个`token-2`，设置到`cookie`，并重定向到`SSO`中，现在`SSO`通过`session`或者`cookie`发现该用户已经通过其他子系统生成了`sid`，然后将该用户在`web-2`子系统生成的用户`token-2`与`sid`绑定到一起，这样`web-2`子系统也能通过用户`token-2`来获取同一个用户`sid`对应的信息了。

### 环境

`python`依赖：`flask`，`PyJWT`(用于生成token)

`nginx`：本地hosts设置3个虚拟域名，`example-1.com`，`example-2.com`，`example-sso.com`，通过`nginx`转发。

