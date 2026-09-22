from django.shortcuts import render
from django.template import RequestContext
from django.contrib import messages
from django.http import HttpResponse
from django.core.files.storage import FileSystemStorage
import os
import random
from datetime import date
import ecdsa
from hashlib import sha256
import pickle
import re
import pyaes, pbkdf2, binascii, os, secrets
import pymysql
import smtplib
import hashlib
import pandas as pd

global username, otp, email

def log(activity):
    if os.path.exists("log.csv"):
        data = pd.read_csv("log.csv")
        data = data.values.tolist()
        data.append([activity])
        data = pd.DataFrame(data, columns = ['Activity'])
        data.to_csv("log.csv", index=False, quotechar='"')
    else:
        data = []
        data.append([activity])
        data = pd.DataFrame(data, columns = ['Activity'])
        data.to_csv("log.csv", index=False, quotechar='"')

def generateKeys():
    if os.path.exists("StorageApp/static/keys/key.pckl"):
        f = open("StorageApp/static/keys/key.pckl", 'rb')
        keys = pickle.load(f)
        f.close()
        secret_key = keys[0]
        private_key = keys[1]
    else:
        secret_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1, hashfunc=sha256) # The default is sha1
        private_key = secret_key.get_verifying_key()
        keys = [secret_key, private_key]
        f = open("StorageApp/static/keys/key.pckl", 'wb')
        pickle.dump(keys, f)
        f.close()
    private_key = private_key.to_string()[0:32]    
    return private_key

def encryptAES(plaintext, key): #AES data encryption
    aes = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(31129547035000047302952433967654195398124239844566322884172163637846056248223))
    ciphertext = aes.encrypt(plaintext)
    return ciphertext

def decryptAES(enc, key): #AES data decryption
    aes = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(31129547035000047302952433967654195398124239844566322884172163637846056248223))
    decrypted = aes.decrypt(enc)
    return decrypted

def Download(request):
    if request.method == 'GET':
        global fileList
        name = request.GET.get('requester', False)
        log(username+' decrypting & downloading file '+name+' at '+str(date.today())) 
        private_key = generateKeys()
        with open("StorageApp/static/files/"+name, "rb") as file:
            data = file.read()
        file.close()        
        aes_decrypt = decryptAES(data, private_key)
        response = HttpResponse(aes_decrypt,content_type='application/force-download')
        response['Content-Disposition'] = 'attachment; filename='+name
        return response          

def DownloadFile(request):
    if request.method == 'GET':
        global username
        output = '<table border=1 align=center width=100%><tr><th><font size="3" color="black">File Owner Name</th><th><font size="3" color="black">Filename</th>'
        output+='<th><font size="3" color="black">Upload Date</th><th><font size="3" color="black">SHA256 Hashcode</th><th><font size="3" color="black">Download File</th></tr>'
        con = pymysql.connect(host='127.0.0.1',port = 3306,user = 'root', password = '', database = 'filestorage',charset='utf8')
        with con:    
            cur = con.cursor()
            cur.execute("select * FROM files")
            rows = cur.fetchall()
            for row in rows:
                name = row[0]
                fname = row[1]
                share = row[2].split(",")
                upload_date = row[3]
                key = row[4]+str(random.randint(100000, 10000000))
                output += '<tr><td><font size="3" color="black">'+str(name)+'</td><td><font size="3" color="black">'+str(fname)+'</td>'
                output+='<td><font size="3" color="black">'+upload_date+'</td>'
                output+='<td><font size="3" color="black">'+key+'</td>'
                output +='<td><a href=\'Download?requester='+fname+'\'><font size=3 color=black>Download</font></a></td></tr>'
        output += "</table><br/><br/><br/><br/>"    
        context= {'data':output}
        return render(request, 'UserScreen.html', context)    

def UploadFileAction(request):
    if request.method == 'POST':
        global username       
        myfile = request.FILES['t1'].read()
        fname = request.FILES['t1'].name
        shares = request.POST.getlist('t2')
        dd = str(date.today())
        #get IBE key for file encryption
        private_key = generateKeys()
        encrypted_data = encryptAES(myfile, private_key)
        log(username+' encrypting & uploading file '+fname+' at '+str(date.today())) 
        with open("StorageApp/static/files/"+fname, "wb") as file:
            file.write(encrypted_data)
        file.close()
        share = ""
        for i in range(len(shares)):
            share += shares[i]+","
        share += username
        print(share)
        private_key = hashlib.sha256(private_key)
        private_key = private_key.hexdigest()
        db_connection = pymysql.connect(host='127.0.0.1',port = 3306,user = 'root', password = '', database = 'filestorage',charset='utf8')
        db_cursor = db_connection.cursor()
        student_sql_query = "INSERT INTO files VALUES('"+username+"','"+fname+"','"+share+"','"+dd+"','"+str(private_key)+"')"
        db_cursor.execute(student_sql_query)
        db_connection.commit()
        context= {'data':'Encrypted file successfully saved to cloud'}
        return render(request, 'UploadFile.html', context)

def UploadFile(request):
    if request.method == 'GET':
        global username
        output = '<tr><td><font size="" color="black">Access&nbsp;Control&nbsp;List</b></td><td><select name="t2" multiple>'
        con = pymysql.connect(host='127.0.0.1',port = 3306,user = 'root', password = '', database = 'filestorage',charset='utf8')
        with con:    
            cur = con.cursor()
            cur.execute("select username FROM register")
            rows = cur.fetchall()
            for row in rows:
                if row[0] != username:
                    output += '<option value="'+row[0]+'">'+row[0]+'</option>'
        output += '</select></td></tr>'
        context= {'data1': output}
        return render(request, 'UploadFile.html', context)

def UserLogin(request):
    if request.method == 'GET':
        return render(request, 'UserLogin.html', {})

def index(request):
    if request.method == 'GET':
        return render(request, 'index.html', {})

def Register(request):
    if request.method == 'GET':
       return render(request, 'Register.html', {})

def RegisterAction(request):
    if request.method == 'POST':
        username = request.POST.get('t1', False)
        password = request.POST.get('t2', False)
        contact = request.POST.get('t3', False)
        email = request.POST.get('t4', False)
        address = request.POST.get('t5', False)
        log('new user '+username+' sign up at '+str(date.today())) 
        status = "none"
        con = pymysql.connect(host='127.0.0.1',port = 3306,user = 'root', password = '', database = 'filestorage',charset='utf8')
        with con:    
            cur = con.cursor()
            cur.execute("select username FROM register")
            rows = cur.fetchall()
            for row in rows:
                if row[0] == username:
                    status = "Username already exists"
                    break
        if status == "none":
            db_connection = pymysql.connect(host='127.0.0.1',port = 3306,user = 'root', password = '', database = 'filestorage',charset='utf8')
            db_cursor = db_connection.cursor()
            student_sql_query = "INSERT INTO register VALUES('"+username+"','"+password+"','"+contact+"','"+email+"','"+address+"')"
            db_cursor.execute(student_sql_query)
            db_connection.commit()
            print(db_cursor.rowcount, "Record Inserted")
            if db_cursor.rowcount == 1:
                status = "Signup process completed"
        context= {'data': status}
        return render(request, 'Register.html', context)

def sendOTP(email, otp_value):
    em = []
    em.append(email)
    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as connection:
        email_address = 'koushikreddy1817@gmail.com'
        email_password = 'oerzwodsjsosnpam'
        connection.login(email_address, email_password)
        connection.sendmail(from_addr="koushikreddy1817@gmail.com", to_addrs=em, msg="Subject : Your OTP : "+otp_value)    

def UserLoginAction(request):
    if request.method == 'POST':
        global username, otp, email
        uname = request.POST.get('username', False)
        password = request.POST.get('password', False)
        log('user '+uname+' login at '+str(date.today())) 
        index = 0
        con = pymysql.connect(host='127.0.0.1',port = 3306,user = 'root', password = '', database = 'filestorage',charset='utf8')
        with con:    
            cur = con.cursor()
            cur.execute("select username, password, email FROM register")
            rows = cur.fetchall()
            for row in rows:
                if row[0] == uname and password == row[1]:
                    email = row[2]
                    username = uname
                    index = 1
                    break		
        if index == 1:
            otp = str(random.randint(1000, 9999))
            sendOTP(email, otp)
            context= {'data':'OTP sent to your mail'}
            return render(request, 'OTP.html', context)
        else:
            context= {'data':'login failed'}
            return render(request, 'UserLogin.html', context)

def OTPAction(request):
    if request.method == 'POST':
        global username, otp
        user_otp = request.POST.get('t1', False)
        if otp == user_otp:
            context= {'data':'OTP Succesfully Validated<br/>welcome '+username}
            return render(request, 'UserScreen.html', context)
        else:
            context= {'data':'login failed'}
            return render(request, 'OTP.html', context)         

