import os
import random
import re

import wikipediaapi
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy

from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
from flask_cors import CORS


app = Flask(__name__)
app.config['CORS_HEADERS'] = '*'

CORS(app, origins="*", allow_headers="*")
app.config['SECRET_KEY'] = 'cle-pour-id-user'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['CORS_HEADERS'] = 'Content-Type'

db = SQLAlchemy(app)
#rover = Rover()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))
    rank = db.Column(db.Integer)

class Stats(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    id_user = db.Column(db.Integer)
    good_answer = db.Column(db.Integer)
    mistake = db.Column(db.Integer)
    streak = db.Column(db.Integer)
    score = db.Column(db.Integer)

class Indice(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    id_question = db.Column(db.Integer)
    indice = db.Column(db.String(128))
    def serialize(self):
        """Return object data in easily serializable format"""
        return {
            'id': self.id,
            'id_question': self.id_question,
            'indice': self.indice

        }

class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date_question = db.Column(db.Integer)
    answer = db.Column(db.String(128))


    def serialize(self):
        """Return object data in easily serializable format"""
        return {
            'id': self.id,
            'date_question': self.date_question,
            'answer': self.answer

        }



def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message' : 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated




def getBref(sections, level=0):
    txt =""
    for s in sections:
        if s.title=="En bref" or s.title == "Événements":
            txt+= s.text
    if txt == "":
        return False,""
    else:
        return True,txt


def get_Question_Wiki():
    valide = False
    while valide==False:
        annee=random.randint(1,2020)
        wiki_wiki = wikipediaapi.Wikipedia('fr',extract_format=wikipediaapi.ExtractFormat.HTML)
        page_py = wiki_wiki.page(annee)
        valide,t=getBref(page_py.sections)

        t=t.replace(str(annee-1),"____")
        t=t.replace(str(annee),"____")
        t=t.replace(str(annee+1),"____")
        t=t.replace(u'\xa0', u' ')
        res = re.findall('(?<=>)([^<]+)(?=[^<]*</li)', t, re.S)

        if len(res)<5:
            valide = False
    return res,annee

@app.route('/', methods=['GET'])
def get_home():
    return jsonify({'Title':{'message':'API Éphémérides QCM'}})


#----------------------------------------- SECURITY ------------------------------
@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    user = User.query.filter_by(name=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])

        return jsonify({'token' : token.decode('UTF-8')})

    return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})


#----------------------------------------- Question --------------------------
def get_wiki_ephemerides(d):
    indice,annee = get_Question_Wiki()
    question = Question()
    question.date_question=d
    question.answer=annee
    db.session.add(question)
    db.session.commit()

    q = question.serialize()
    q["indices"]=[]
    for i in indice:
        var = Indice()
        var.id_question = question.id
        var.indice = i
        db.session.add(var)
        db.session.commit()
        q["indices"].append(var.serialize())



    return q



@app.route('/question', methods=['GET'])
def get_question():
    today = datetime.date.today()
    id_date = datetime.datetime.timestamp(datetime.datetime.strptime(today.strftime("%d/%m/%Y"), "%d/%m/%Y"))
    question = Question.query.filter_by(date_question=id_date).first()
    if question == None:
        q = get_wiki_ephemerides(id_date)
    else:
        q = question.serialize()
        q["indices"] = []
        indices = Indice.query.filter_by(id_question=question.id).all()
        for i in indices:
            q["indices"].append(i.serialize())

    return jsonify(q)





if __name__ == '__main__':

    if not os.path.exists('db.sqlite'):
        db.create_all()
        u = User(name="admin")
        u.password = generate_password_hash("azerty")
        u.rank = 0
        db.session.add(u)
        db.session.commit()
    app.run(host="0.0.0.0",port=8123,debug=True)