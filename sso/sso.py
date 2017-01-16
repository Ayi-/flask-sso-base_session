from flask import Flask,request,redirect,make_response,session
import utils,os
app = Flask(__name__)

user = 'test'
pw = 'test'

token_list={}
login_user={}

@app.route('/')
def hello_world():
    # 尝试从url中获取token
    cookie_token = request.args.get('cookie_token', None)
    next_url = request.args.get('next_url',None)

    if not cookie_token or not next_url:
        return 'not token or next_url'
    else:
        info = utils.getCookieTokenInfo(cookie_token)
        # 获取信息正确
        if info:
            # 尝试获取session_id，如果没有就创建一个，对应一个用户
            sid = session.get('id',info.get('user_token','test'))
            session['id']=sid
            # 将用户cookie_token及其对应的sid写入到list中，用于其他子系统匹配用户
            token_list[cookie_token]=sid
            #resp = make_response('example-sso')
            #resp.set_cookie(cookie_token)

            return redirect(next_url)

@app.route('/get_user_info')
def getUserInfo():
    # 获取用户信息
    sid = utils.checkCookieToken(request,token_list)
    if sid:
        user =  login_user.get(sid,None)
        if user:
            return json.dumps(user)
        return 'no user'

    return 'request failed'


import json
@app.route('/login',methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    sid = utils.checkCookieToken(request,token_list)
    if sid:
        if username and password:
            # 验证用户数据
            if username == user and password == pw:
                # 保存用户数据，key对应一个用户
                login_user[sid]={'username':'test'}
                return json.dumps(login_user[sid])

    return 'no user'

@app.route('/logout')
def logout():
    # 注销，将用户登录数据清除
    sid = utils.checkCookieToken(request, token_list)
    if sid:
        login_user[sid] = None
        return 'logout success'
    return 'logout failed'


if __name__ == '__main__':
    app.secret_key='you guess'
    app.run(debug = True, host='0.0.0.0',port=8090)
