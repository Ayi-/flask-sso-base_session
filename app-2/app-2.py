from flask import Flask,request,make_response,redirect,render_template
from base64 import b64encode
import os
import jwt
import requests
app = Flask(__name__)

app_name='app-2'

app_index = 'http://example-2.com'
sso_server = 'http://172.17.0.4:8090'
logout_html = """，<a href='/logout'>注销</a>"""
index_response = """<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">\n
        <title>首页</title>\n
        <h1>Welcome</h1>\n
        <p>{},{}</p>"""

login_html = """<a href='/login'>登录</a>"""

@app.route('/')
def hello_world():
    print(request.cookies)

    # 尝试获取token
    cookie_token = request.cookies.get('cookie_token', None)
    # 如果用户没有登陆过
    if not cookie_token:
        # 创建token
        user_token = b64encode(os.urandom(64)).decode('utf-8')
        cookie_token = jwt.encode({'web': app_name,'user_token':user_token}, 'sso', algorithm='HS256').decode('utf-8')

        # 设置其重定向到sso
        resp = make_response(
            redirect('http://example-sso.com/?cookie_token='+cookie_token+'&next_url='+app_index))
        # 设置token到本应用对应的网域的cookie中
        resp.set_cookie('cookie_token',cookie_token)
        return resp

    # 尝试获取用户信息
    headers = {'Authorization':cookie_token}

    try:
        r = requests.get(sso_server+'/get_user_info',headers=headers,timeout=10)
        if r.status_code == requests.codes.ok:
            if r.text != 'no user':
                return index_response.format(app_name, r.text+logout_html)

    except Exception as e:
        print(e)
    return index_response.format(app_name,login_html)

@app.route('/login',methods=['GET','POST'])
def login():
    method = request.method
    if method == 'GET':
        return render_template('login.html',app_name=app_name)
    else:
        username = request.form.get('username')
        password = request.form.get('password')
        # 尝试获取token
        cookie_token = request.cookies.get('cookie_token', None)
        print(cookie_token,password,username)
        if username and password and cookie_token:
            headers = {'Authorization': cookie_token}
            data = {'username':username,'password':password}
            # 发起验证请求
            try:
                r = requests.post(sso_server + '/login', headers=headers,data=data,timeout=10)
                if r.status_code == requests.codes.ok:
                    return redirect('/')

            except Exception as e:
                print(e)
    return 'login failed '

@app.route('/logout')
def logout():
    # 尝试获取token
    cookie_token = request.cookies.get('cookie_token', None)
    if cookie_token:
        headers = {'Authorization': cookie_token}
        # 发起注销请求
        try:
            r = requests.get(sso_server + '/logout', headers=headers, timeout=10)
            if r.status_code == requests.codes.ok:
                if r.text == 'logout success':
                    return redirect('/')
        except Exception as e:
            print(e)

    return redirect('/')


if __name__ == '__main__':
    app.run(debug = True, host='0.0.0.0',port=8081)
