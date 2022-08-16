from flask import Flask, render_template, request, redirect, url_for, flash, session
import json
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import sys
from HashManager import HashManager
from User import User
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta



with open("config.json", 'r') as f:
    data = json.load(f)
port = data['PORT']

myApp = Flask("/")
myApp.secret_key = data["SECRET_KEY"]
hash_manager = HashManager()
user_manager = User()


limiter = Limiter(myApp, key_func=get_remote_address, default_limits=["4 per minute"])

@limiter.request_filter
def existing_hash():
    return hash_manager.search_exists()

@limiter.request_filter
def get_req():
    return request.method == 'GET'


@myApp.route("/", methods=['POST', 'GET'])
def mainpage(input_hash_form=None):
    ip = "localhost:"+str(port)
    login_button = "Log In"
    login_button_route = "login"
    login_status = False
    name=""
    recent_searches=[""]
    if "user" in session:
        login_button = "Log Out"
        login_button_route = "logout"
        login_status = True
        name = session["user"].capitalize()
        time = datetime.now().timestamp()
        username = session["user"]
        user_manager.update_time(username, time)

    if request.method == "POST":
        form_input = str(request.form["input_hash_form"])
        return redirect(url_for('result'), code=307)
    else:
        #print("blank")
        return render_template("HomePage.html", ip=ip, login_button=login_button, 
            login_button_route=login_button_route, login_status=login_status, name=name)


@myApp.route("/result", methods=['POST', 'GET'])
@limiter.limit("4 per minute", exempt_when=lambda: (request.method == "GET"))
def result():
    print(request)
    ip = "localhost:"+str(port)

    login_button = "Log In"
    login_button_route = "login"
    login_status = False
    name=""
    if "user" in session:
        login_button = "Log Out"
        login_button_route = "logout"
        login_status = True
        name = session["user"].capitalize()

    if request.method == "POST":
        form_input = str(request.form["input_hash_form"])
        result = hash_manager.verifyMainForm(form_input)
        if result == -2:
            flash('ERROR: Not a valid hash!', category='error')
            return render_template("HomePage.html", ip=ip, login_button=login_button, 
            login_button_route=login_button_route, login_status=login_status, name=name)
        elif result == None:
            flash('ERROR: Id was blank!', category='error')
            return render_template("HomePage.html", ip=ip, login_button=login_button, 
            login_button_route=login_button_route, login_status=login_status, name=name)
        elif result == -1:
            flash('ERROR: Hash does not exist!', category='error')
            return render_template("HomePage.html", ip=ip, login_button=login_button, 
            login_button_route=login_button_route, login_status=login_status, name=name)
        else:
            if "user" in session:
                user_manager.insert_search(session["user"],form_input)
            page = hash_manager.hashpage(result)
            return render_template("ViewHash.html", hash_names=page['hash_names'], names=page['names'], list=page['list'],
            total=page['total'] , mal_count=page['mal_count'], ratio=page['ratio'], ip=['ip'], login_button=login_button, 
            login_button_route=login_button_route, login_status=login_status, name=name)
    else:
        print("returning to mainpage")
        return redirect(url_for('mainpage'))

@myApp.route('/history')
def history():
    ip = "localhost:"+str(port)
    login_button = "Log In"
    login_button_route = "login"
    login_status = False
    name=""
    recent_searches=[""]
    if "user" in session:
        login_button = "Log Out"
        login_button_route = "logout"
        login_status = True
        name = session["user"].capitalize()
        recent_searches=user_manager.get_history(session["user"])
        
        return render_template("History.html", ip=ip, login_button=login_button, 
            login_button_route=login_button_route, login_status=login_status, name=name, recent_searches=recent_searches)
    else:
        flash('You must be logged in to view your search history.', category='error')
        return redirect(url_for('mainpage'))


@myApp.route('/logout')
def logout():
    if "user" in session:
        time = datetime.now().timestamp()
        username = session["user"]
        user_manager.update_time(username, time)
        session.pop("user")
    return redirect(url_for('mainpage'), code=307)


@myApp.route("/login", methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        print("login")
        username = request.form.get('username')
        password = request.form.get('password')
        user = user_manager.get_user(username)
        time = datetime.now().timestamp()
        if user is None:
            if len(username) < 5:
                flash('Username must be greater than 4 characters', category='error')
                pass
            elif len(password) < 5:
                flash('Password must be longer than 4 characters', category='error')
                pass
            else:
                new_user = user_manager.create_user(username, generate_password_hash(password, method='sha256'), time)
                flash('Account created!', category='success')
                print(f"Account {username} created successfully.")
                session["user"] = username
                return redirect(url_for('mainpage'))
        elif check_password_hash(user['password'], password):
            #SUCCESS
            print(f"{username} logged in successfully.")
            user_manager.update_time(username, time)
            session["user"] = username
            return redirect(url_for('mainpage'))
        else:
            flash("Invalid Password!", category='error')
    
    return render_template("login.html")


    
@myApp.errorhandler(429)
def too_many_requests(e):
    ip = "localhost:"+str(port)
    login_button = "Log In"
    login_button_route = "login"
    login_status = False
    name=""
    recent_searches=[""]
    print(e)
    if "user" in session:
        login_button = "Log Out"
        login_button_route = "logout"
        login_status = True
        name = session["user"].capitalize()
        recent_searches=user_manager.get_user(session["user"])
        #print("blank")
    flash('You are going too quickly! Slow down!', category='error')
    return redirect(url_for('mainpage', input_hash_form=request.form['input_hash_form']), code=303)



if __name__ == "__main__":
    print(sys.version)
    myApp.run(debug=True, host="localhost", port=port)
