import pymysql
from flask import Flask, request, jsonify, render_template
from flaskext.mysql import MySQL 
from werkzeug.security import generate_password_hash,check_password_hash
#from flask_jwt_extended import JWTManager
#from flask_jwt_extended import (create_access_token, create_refresh_token, jwt_required, jwt_refresh_token_required, get_jwt_identity, get_raw_jwt)
from flask_cors import CORS
import json
import datetime
import jwt
from functools import wraps

app = Flask(__name__)
app.config['MYSQL_DATABASE_USER'] = 'root'
app.config['MYSQL_DATABASE_PASSWORD'] = ''
app.config['MYSQL_DATABASE_DB'] = 'lib'
app.config['MYSQL_DATABASE_HOST'] = 'localhost'
app.config['SECRET_KEY']='thisisthesecretkey'
#app.config['JWT_SECRET_KEY'] = 'jwt-secret-string'
#jwt = JWTManager(app)
mysql = MySQL(app)
CORS(app, supports_credentials = True)

def token_required(f):
	@wraps(f)
	def decorated(*args, **kwargs):
                data=request.get_json();
		token = data["token"]

		if not token:
			return jsonify({‘valid’ : 0}), 403

		try:
			data = jwt.decode(token, app.config['SECRET_KEY'])
		except:
			return jsonify({'valid' :0}), 403

		return f(*args, **kwargs)

	return decorated

def get_uid(token):
    mydb = mysql.connect()
    mycursor = mydb.cursor(pymysql.cursors.DictCursor)
    mycursor.execute("SELECT UserID FROM users WHERE Token=%s",(token))
    user = mycursor.fetchall()
    if(len(user)==0):
        return -1
    else:
        return user[0][‘UserID’]
    
    
#--------------------------------------------------Logic---------------------------------------------------#
@app.route('/library/users/v1/booklist', methods=['GET'])
@token_required
def users():
	try:
            di={}
            mydb = mysql.connect()
            mycursor = mydb.cursor(pymysql.cursors.DictCursor)
            mycursor.execute("SELECT * FROM Book")
            rows = mycursor.fetchall()
            for row in rows:
                di[row["BookID"]]=row
            print(jsonify(di))
            return jsonify(di)
	except Exception as e:
		print(e)
	finally:
		mycursor.close() 
		mydb.close()

@app.route('/library/users/v1/notify', methods=['POST'])
@token_required
def notify():
	try:
            data=request.get_json();
            bid=data["bid"]
            uid=get_uid(data[‘token’])
	if uid==-1:
		return jsonify(“{valid:0}”)
            mydb = mysql.connect()
            mycursor = mydb.cursor()
            mycursor.execute("INSERT INTO Records(UserID, BookID,Status) VALUES(%s, %s,'3')",(uid, bid))
            mydb.commit()
            return "done"
	except Exception as e:
		print(e)
	finally:
		mycursor.close() 
		mydb.close()



@app.route('/library/admin/v1/waitlist', methods=['GET'])
@token_required
def wait():
    try:
        mydb = mysql.connect()
        mycursor = mydb.cursor(pymysql.cursors.DictCursor)
        mycursor.execute("SELECT BookID, BookName FROM book")
        books = mycursor.fetchall()
        
        final={}
        d={}
        mycursor.execute("SELECT UserID, Name from users")
        users = mycursor.fetchall()

        for u in users:
            d.update({u['UserID']:u['Name']})
        
        for b in books:
            bid = b['BookID']
            bname = b['BookName']
            
            names = []
            mycursor.execute("SELECT UserID from records where BookID = %s and Status = 3", (bid))
            uids = mycursor.fetchall()
            if(len(uids)>0):
                for u in uids:
                    ud={u['UserID']:d[u['UserID']]}
                    names.append(ud)
                final.update({bname:names})
    
        #return json.dumps(final)
        return jsonify(final)
        
    except Exception as e:
        print(e)
    finally:
        mycursor.close()
        mydb.close()

@app.route('/library/admin/v1/bookhistory', methods=['GET','POST'])
@token_required
def book():
    try:
        mydb = mysql.connect()
        mycursor = mydb.cursor(pymysql.cursors.DictCursor)
        
        data = request.get_json()
        bid = data["bid"]
        
        final={}
        d={}
        mycursor.execute("SELECT UserID, Name from users")
        users = mycursor.fetchall()
        for u in users:
            d.update({u['UserID']:u['Name']})
        names = []
        mycursor.execute("SELECT UserID, Status from records where BookID = %s", (bid))
        uids = mycursor.fetchall()
        if(len(uids)>0):
            for u in uids:
                names=[]
                names.append(d[u['UserID']])
                names.append(u['Status'])
                final.update({u['UserID']:names})
        return jsonify(final)
        
    except Exception as e:
        print(e)
    finally:
        mycursor.close()
        mydb.close()

@app.route('/library/users/v1/book', methods=['GET','POST'])
@token_required
def user():
    try:
        data = request.get_json()
        bid = data['ID']
        mydb = mysql.connect()
        mycursor = mydb.cursor(pymysql.cursors.DictCursor)
        mycursor.execute("SELECT * FROM book WHERE BookID=%s", bid)
        row = mycursor.fetchall()
        for r in row:
            d=r
        resp = jsonify(d)
        resp.status_code = 200
        return resp
    except Exception as e:
        print(e)
    finally:
        mycursor.close() 
        mydb.close()

@app.route('/library/admin/v1/addbook', methods=['POST'])
@token_required
def add_user():
    try:
        _json = request.json
        _name = _json['BookName']
        _author = _json['Author']
        _isbn = _json['ISBN']
        _rate = _json['Rate']
        _available = _json['Available']
        if _name and _author and _isbn and _rate and _available and request.method == 'POST':
            sql = "INSERT INTO Book(BookName, Author, ISBN, Rate, Available) VALUES(%s, %s, %s, %s, %s)"
            data = (_name, _author, _isbn, _rate, _available)
            mydb = mysql.connect()
            mycursor = mydb.cursor()
            mycursor.execute(sql, data)
            mydb.commit()
            resp = jsonify('Book added successfully!')
            resp.status_code = 200
            return resp
        else:
            return not_found()
    except Exception as e:
        print(e)
    finally:
        mycursor.close() 
        mydb.close()

@app.route('/library/admin/v1/updatebook', methods=['PUT','POST'])
@token_required
def update():
    print("try")
    try:
        print("DGFsdg")
        mydb = mysql.connect()
        mycursor = mydb.cursor()
        _json = request.get_json()
        _id = _json['ID']
        _name = _json['BookName']
        _author = _json['Author']
        _isbn = _json['ISBN']
        _rate = _json['Rate']
        _available = _json['Available']
        print("dfhdfah")
        if _name and _author and _isbn and _rate and _available:
            mycursor.execute("UPDATE book SET BookName=%s, Author=%s, ISBN=%s, Rate=%s, Available=%s WHERE BookID=%s",[_name, _author, _isbn, _rate, _available, _id])
            mydb.commit()
            resp = jsonify('book updated successfully!')
            resp.status_code = 200
            return resp
        else:
            return not_found()
    except Exception as e:
        print(e)
    finally:
        mycursor.close() 
        mydb.close()

@app.route('/library/admin/v1/removebook', methods=['DELETE','POST'])
@token_required
def delete_user():
    try:
        mydb = mysql.connect()
        mycursor = mydb.cursor()
        data = request.get_json()
        ID = data['ID']
        mycursor.execute("DELETE FROM book WHERE BookID=%s", ID)
        mydb.commit()
        resp = jsonify('Book deleted successfully!')
        resp.status_code = 200
        return resp
    except Exception as e:
        print(e)
    finally:
        mycursor.close() 
        mydb.close()

@app.route('/library/admin/v1/userslist', methods=['GET'])
@token_required
def usrs():
        try:
                di={}
                mydb = mysql.connect()
                mycursor = mydb.cursor(pymysql.cursors.DictCursor)
                mycursor.execute("SELECT * FROM Users")
                rows = mycursor.fetchall()
                for row in rows:
                        di[row["UserID"]]=row
                print(jsonify(di))
                return jsonify(di)

        except Exception as e:
                print(e)
        finally:
                mycursor.close() 
                mydb.close()


@app.route('/library/admin/v1/addusers', methods=['POST'])
@token_required
def ad_user():
	try:
		json = request.get_json()
		name = json['Name']
		email = json['Email']
		mobile = json['Mobileno']
		password = json['Password']
		
		if name and email and mobile :
                        mydb = mysql.connect()
                        mycursor = mydb.cursor()
                        sql = "INSERT INTO Users(Name, Email, MobileNo,Password) VALUES(%s, %s, %s,%s)"
                        data = (name, email, mobile,password)
                        mycursor.execute(sql, data)
                        mydb.commit()
                        print("hello")
                        resp = jsonify('User added successfully!')
                        resp.status_code = 200
                        return resp
		else:
			return not_found()
	except Exception as e:
		print(e)
	finally:
		mycursor.close() 
		mydb.close()

@app.route('/library/admin/v1/updateusers', methods=['POST'])
@token_required
def updt():
        try:
                json = request.get_json()
                name = json['Name']
                email = json['Email']
                mobile = json['Mobileno']
                id1 = json['uid']
                
                if name and email and mobile :
                        mydb = mysql.connect()
                        mycursor = mydb.cursor()
                        sql = "UPDATE Users set Name=%s ,Email=%s ,MobileNo=%s where UserID=%s"
                        data = (name, email, mobile,id1)
                        mycursor.execute(sql, data)
                        mydb.commit()
                        resp = jsonify('User added successfully!')
                        resp.status_code = 200
                        return resp
                else:
                        return not_found()
        except Exception as e:
                print(e)
        finally:
                mycursor.close() 
                mydb.close()

@app.route('/library/admin/v1/removeusers', methods=['POST'])
@token_required
def del_user():
        try:
                json = request.get_json()
                id1 = json['uid']
                mydb = mysql.connect()
                mycursor = mydb.cursor()
                mycursor.execute("DELETE FROM Users WHERE UserID=%s", id1)
                mydb.commit()
                resp = jsonify('User deleted successfully!')
                resp.status_code = 200
                return resp
        except Exception as e:
                print(e)
        finally:
                mycursor.close() 
                mydb.close()


@app.route('/library/admin/v1/allrecords', methods=['GET'])
@token_required
def uussrrss():
    try:
        mydb = mysql.connect()
        mycursor = mydb.cursor(pymysql.cursors.DictCursor)
        mycursor.execute("SELECT * FROM Records")
        rows = mycursor.fetchall()
        d={}
        for row in rows:
            d[str(row['RecordID'])]=row
        resp = jsonify(d)
        resp.status_code = 200
        return resp
    except Exception as e:
        print(e)
    finally:
        mycursor.close() 
        mydb.close()

@app.route('/library/admin/v1/userrecords', methods=['GET','POST'])
@token_required
def uqaser():
    try:
        mydb = mysql.connect()
        mycursor = mydb.cursor(pymysql.cursors.DictCursor)

        data = request.get_json()
        uid = data["uid"]
        
        mycursor.execute("SELECT * FROM Records WHERE UserID=%s", uid)
        rows = mycursor.fetchall()
        bd={}
        mycursor.execute("SELECT BookID, BookName from book")
        books = mycursor.fetchall()
        for b in books:
            bd.update({b['BookID']:b['BookName']})
        d={}
        for row in rows:
            row["BookName"]=bd[row['BookID']]
            d.update({str(row["RecordID"]):row})
        return jsonify(d)
    except Exception as e:
        print(e)
    finally:
        mycursor.close() 
        mydb.close()

#-------------------------Book Issue------------------------------------		
@app.route('/library/user/v1/issue', methods=['PUT','POST'])
@token_required
def update():
	mydb = mysql.connect()
	
	try:
            print("hi")
            data=request.get_json();
            print(data)
            bids=data["bid"]
                        uid=get_uid(data[‘token’])
	if uid==-1:
		return jsonify(“{valid:0}”)
            isds=data["isd"]
            mycursor = mydb.cursor(pymysql.cursors.DictCursor)
            mycursor.execute("SELECT BookID,Available FROM book")
            rows = mycursor.fetchall()
            d={}
            nonissue=[]
            print(rows)
            for row in rows:
                    d[row["BookID"]]=row["Available"]
            print(d)
            for bid in bids:
                if(d[bid]==0):
                        nonissue.append(bid)
            if len(nonissue)>0:
                    d={}
                    d["nonissue"]=nonissue
                    return(jsonify(d))
            mycursor = mydb.cursor()
            
            for bid,isd in bids,isds:
                print(isd)
                mycursor.execute("UPDATE book SET Available = 0  WHERE BookID=%s",[bid])
                mydb.commit()
                mycursor.execute("INSERT INTO Records(UserID, BookID, IssueDays, I_DATETIME, Status) VALUES(%s, %s, %s, CURRENT_TIMESTAMP(), '1')",(uid, bid, isd))
                mydb.commit()
            
            d={}
            d["issue"]=1
            resp = jsonify(d)
            resp.status_code = 200
            return resp
	except Exception as e:
		print(e)
	finally:
		mycursor.close() 
		mydb.close()

#-------------------------------------------Book Submit--------------------------------#
@app.route('/library/admin/v1/sub', methods=['PUT'])
@token_required
def updtees():
	mydb = mysql.connect()
	mycursor = mydb.cursor()
	data = request.get_json()
	bid=data[‘bid’]
	rid=data[‘rid’]
	try:
		if request.method == 'PUT':
			mycursor.execute("UPDATE Book SET Available = 1 WHERE BookID=%s",[bid])
			mycursor.execute("UPDATE Records SET Status = '0', S_DATETIME = CURRENT_TIMESTAMP() WHERE RecordID=%s",[rid])
			mydb.commit()
			resp = jsonify('Book has been returned')
			resp.status_code = 200
			return resp
		else:
			return not_found()
	except Exception as e:
		print(e)
	finally:
		mycursor.close() 
		mydb.close()

@app.route('/library/users/v1/profile', methods=['GET'])
@token_required
def profile():
    try:
        mydb = mysql.connect()
        mycursor = mydb.cursor()
            uid=get_uid(data[‘token’])
	if uid==-1:
		return jsonify(“{valid:0}”)
        mycursor.execute("SELECT * from users where UserID=%s",(uid))
            
        rows = mycursor.fetchall()
        user={}
        user["name"] = rows[0][1]
        user["email"] = rows[0][2]
        user["mobileno"] = rows[0][3]
        user["image"] = rows[0][5]
        return jsonify(user)

    except Exception as e:
        print(e)

    finally:
        mycursor.close()
        mydb.close()



@app.route('/library/user/register',methods=['POST']) #Line 48
@token_required
def register():
    try:
        print("Ho")
        name=request.form["name"]
        email=request.form["email"]
        password=request.form["password"]
        hash_pass=generate_password_hash(password,method='sha256')
        phone=request.form["phone"]
        print(name)
        print(len(hash_pass))
        mydb = mysql.connect()
        mycursor = mydb.cursor()
        mycursor.execute("SELECT Email from users where Email=%s",(email))
        temp=mycursor.fetchall()
        if(len(temp)!=0):
            return json.dumps("User Exits")
        else:
            mycursor.execute("INSERT INTO users (Name,Email,MobileNo,Password) values(%s,%s,%s,%s)",(name,email,phone,hash_pass))
            mydb.commit()
        
    except Exception as e:
        print(e)
    finally:
        mycursor.close()
        mydb.close()

@app.route('/library/admin/register2',methods=['POST']) #line 76
@token_required
def register2():
    try:
        print("Hi Admin")
        name=request.form["name"]
        email=request.form["email"]
        password=request.form["password"]
        hash_pass=generate_password_hash(password,method='sha256')
        phone=request.form["phone"]
        print(name,email,password,phone)
        print(len(hash_pass))
        mydb = mysql.connect()
        mycursor = mydb.cursor()
        mycursor.execute("SELECT Email from admin where Email=%s",(email))
        temp=mycursor.fetchall()
        print(temp)
        if(len(temp)!=0):
            return json.dumps("Admin Exits")
        else:
            mycursor.execute("INSERT INTO admin (Name,Email,Phone,Password) values(%s,%s,%s,%s)",(name,email,phone,hash_pass))
            mydb.commit()
        
    except Exception as e:
        print(e)
    finally:
        mycursor.close()
        mydb.close()

        
@app.route('/library/user/v1/login',methods=['POST'])
@token_required
def login():
    try:
        #name=request.form["name"]
        #email=request.form["email"]
        #password=request.form["password"]
        #password2=generate_password_hash(password,method='sha256')
        #phone=request.form["phone"]
        
        data=request.get_json()
        email=data['email']
        password=data['password']
        print(email,password)
        #print(password)
        #print(password2)
        mydb = mysql.connect()
        mycursor = mydb.cursor()
        mycursor.execute("SELECT Password from users where Email=%s",(email))
        temp=mycursor.fetchall()
        print(temp)
        print( temp[0][0])
        
        if(len(temp)==0):
            print("len == 0")
            return json.dumps("User Not Exists")
        elif(check_password_hash(temp[0][0],password)):
            print("hi")
            token=jwt.encode({'user':email,'exp':datetime.datetime.utcnow()+datetime.timedelta(minutes=30 )},app.config['SECRET_KEY'])
            print("Token = ",token)
            mycursor.execute("UPDATE  users set Token=%s where Email=%s",(token,email))
            mydb.commit()
            return jsonify({'token':token.decode('UTF-8')})
        
    except Exception as e:
        print(e)
    finally:
        mydb.commit()
        mycursor.close()
        mydb.close()

@app.route('/library/admin/login2',methods=['POST'])
@token_required
def login2():
    try:
        #name=request.form["name"]
        email=request.form["email"]
        password=request.form["password"]
        #password2=generate_password_hash(password,method='sha256')
        #phone=request.form["phone"]
        print(email)
        print(password)
        #print(password2)
        mydb = mysql.connect()
        mycursor = mydb.cursor()
        mycursor.execute("SELECT Password from admin where Email=%s",(email))
        temp=mycursor.fetchall()
        print(temp)
        print(len(temp))
        print(check_password_hash(temp[0][0],password))
        if(len(temp)==0):
            return json.dumps("Admin Not Exists")
        
        elif(check_password_hash(temp[0][0],password)):
            #print("ELIF")
            token=jwt.encode({'user':email,'exp':datetime.datetime.utcnow()+datetime.timedelta(minutes=30 )},app.config['SECRET_KEY'])
            return jsonify({'token':token.decode('UTF-8')})
        
    except Exception as e:
        print(e)
    finally:
        mydb.commit()
        mycursor.close()
        mydb.close()

if __name__ == "__main__":
    app.run(debug=True, port=5500)



