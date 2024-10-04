from flask import Flask,request,redirect,render_template,session,url_for,flash
from flask_mail import Mail,Message
from random import *
import secrets
import re
import bcrypt
import pymysql


app=Flask(__name__)
app.secret_key='ttdfxcdxdzsxxex'
app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT']=465
app.config['MAIL_USERNAME']='chegenelson641@gmail.com'

app.config['MAIL_USE_TSL']=False
app.config['MAIL_USE_SSL']=True

mail=Mail(app)

connection=pymysql.connect(
    host='localhost',
    user='root',
    password='',
    database='flask_mk'
)
cur=connection.cursor()

@app.route('/register',methods=['POST','GET'])
def register():
    if request.method=='POST':
        username=request.form['username']
        email=request.form['email']
        password=request.form['password']
        confirm=request.form['confirm']
        cur.execute('SELECT * FROM mick WHERE username=%s' ,(username))
        connection.commit()
        data=cur.fetchone()
        cur.execute('SELECT * FROM mick WHERE email=%s',(email))
        connection.commit()
        main=cur.fetchone()
        if username=='' or email=='' or password=='' or confirm=='':
            flash('All fields are required','warning')
            return render_template('register.html',username=username,email=email,password=password,confirm=confirm)
        elif data is not None:
            flash('Username already used create new one','warning')
            return render_template('register.html',username=username,email=email,password=password,confirm=confirm)
        elif main is not None:
            flash('Email already used create new one','warning')
            return render_template('register.html',username=username,email=email,password=password,confirm=confirm)
        elif username == password:
            flash('Username and your password should not be simillar','warning')
            return render_template('register.html',username=username,email=email,password=password,confirm=confirm)
        elif password != confirm:
            flash('Passwords are incorrect','warning')
            return render_template('register.html',username=username,email=email,password=password,confirm=confirm)
        elif not re.search('[A-Z]',password):
            flash('Password should have capital letters','warning')
            return render_template('register.html',username=username,email=email,password=password,confirm=confirm)
        elif not re.search('[a-z]',password):
            flash('Password should have small letters','warning')
            return render_template('register.html',username=username,email=email,password=password,confirm=confirm)
        else:
            hashed=bcrypt.hashpw(password.encode('utf-8'),bcrypt.gensalt())
            otp=randint(0000,9999)
            cur.execute('INSERT INTO mick(username,email,password,otp)VALUES(%s,%s,%s,%s)',(username,email,hashed,otp))
            connection.commit()
            subject='Account creation'
            body=f'Account created use this otp {otp} to verify your account'
            sendmail(subject,email,body)
            flash('Account has been created','success')
            return redirect(url_for('otp'))
        
        
    return render_template('register.html')

def sendmail(subject,email,body):
    try:
        msg=Message(subject=subject,sender='chegenelson641@gmail.com',recipients=[email],body=body)
        mail.send(msg)
    except Exception as a:
        print(a)


@app.route('/login',methods=['POST','GET'])
def login():
    if request.method=='POST':
        username=request.form['username']
        password=request.form['password']
        if username=='' or password=='':
            flash('All fields are required','warning')
            return render_template('login.html',username=username,password=password)
        else:
            cur.execute('SELECT * FROM mick WHERE username=%s',(username))
            connection.commit()
            data=cur.fetchone()
            if data is not None:
                if bcrypt.checkpw(password.encode('utf-8'),data[3].encode('utf-8')):
                    if data[7]==1:
                        session['username']=data[1]
                        session['user_id']=data[0]
                        session['role']=data[4]
                        if session['role']=='user':
                            return redirect(url_for('home'))
                        else:
                            return redirect(url_for('home'))
                    else:
                        flash('Please verify your account','warning')
                        return redirect(url_for('otp'))
                else:
                    flash('Incorrect password','warning')
                    return render_template('login.html',username=username,password=password)
            else:
                flash('Incorrect username','warning')
                return render_template('login.html',username=username,password=password)
    return render_template('login.html')

@app.route('/otp',methods=['POST','GET'])
def otp():
    if request.method=='POST':
        otp=request.form['otp']
        cur.execute('SELECT * FROM mick WHERE otp=%s',(otp))
        connection.commit()
        data=cur.fetchone()
        if data is not None:
            cur.execute('UPDATE mick SET is_verified=1 WHERE otp=%s',(otp))
            connection.commit()
            subject='Account Verification'
            body='Your account has been verified'
            sendmail(subject,data[2],body)
            flash('Account has been verified','success')
            return redirect(url_for('login'))
        else:
            flash('Incorrect otp','warning')
            return redirect(url_for('otp'))
    
    return render_template('otp.html')

@app.route('/forgot',methods=['POST','GET'])
def forgot():
    if request.method=='POST':
        email=request.form['email']
        cur.execute('SELECT * FROM mick WHERE email=%s',(email))
        connection.commit()
        data=cur.fetchone()
        if data is not None:
            token=secrets.token_hex(50)
            reset_link=url_for('reset',token=token,_external=True)
            cur.execute('UPDATE mick SET token=%s WHERE email=%s',(token,email))
            connection.commit()
            subject='Forgot password'
            body=f'Your reset link is {reset_link}'
            sendmail(subject,email,body)
            flash('A reset link has been sent to your email ','success')
            return redirect(url_for('forgot'))
        else:
            flash('Incorrect email ','warning')
            return redirect(url_for('forgot'))
        
    return render_template('forgot.html')


@app.route('/reset',methods=['POST','GET'])
def reset():
    token=request.args.get('token')
    if request.method=='POST':
        password=request.form['password']
        confirm=request.form['confirm']
        if password=='' or confirm=='':
            flash('All fields are required','warning')
            return render_template('reset.html',password=password,confirm=confirm)
        elif password != confirm:
            flash('Passwords are incorrect','warning')
            return render_template('reset.html',password=password,confirm=confirm)
        elif not re.search('[A-Z]',password):
            flash('Password should have capital letters','warning')
            return render_template('reset.html',password=password,confirm=confirm)
        elif not re.search('[a-z]',password):
            flash('Password should have small letters','warning')
            return render_template('reset.html',password=password,confirm=confirm)
        else:
            cur.execute('SELECT * FROM mick WHERE token=%s',(token))
            connection.commit()
            data=cur.fetchone()
            if data is not None:
                hashed=bcrypt.hashpw(password.encode('utf-8'),bcrypt.gensalt())
                cur.execute('UPDATE mick SET password=%s,token="token" WHERE token=%s',(hashed,token))
                connection.commit()
                subject='Password reset'
                body=f'Password has been chandes succesfully.\nYour current password is {password}'
                sendmail(subject,data[2],body)
                flash('Password changed','success')
                return redirect(url_for('login'))
            else:
                flash('Token already used','warning')
                return redirect(url_for('forgot'))
            
    return render_template('reset.html')


@app.route('/home')
def home():
    user_id=session['user_id']
    cur.execute('SELECT * FROM jim WHERE user_id=%s',(user_id))
    connection.commit()
    data=cur.fetchall()
    return render_template('home.html',data=data)


@app.route('/create' ,methods=['POST','GET'])
def create():
    if request.method=='POST':
        todos = request.form['todos']
        user_id=session['user_id']
        cur.execute('INSERT INTO jim(user_id,todos)VALUES(%s,%s)',(user_id,todos))
        connection.commit()
        return redirect(url_for('home'))
    return render_template('create.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ in '__main__':
    app.run(debug=True)