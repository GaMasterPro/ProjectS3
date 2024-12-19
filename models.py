from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=False, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    card = db.Column(db.String(16), nullable = False, unique = True)
    cvv = db.Column(db.String(4), nullable = False)
    edate = db.Column(db.Date, nullable = False)
    email = db.Column(db.String(80), unique=True, nullable=False)
    total_balance = db.Column(db.Integer)
    income = db.Column(db.Integer)
    expenses = db.Column(db.Integer)
    savings = db.Column(db.Integer)
    houseBills = db.Column(db.Integer)
    taxes = db.Column(db.Integer)
    car_loan = db.Column(db.Integer)
    education_loan = db.Column(db.Integer)
    medical_loan = db.Column(db.Integer)
    personal_loan = db.Column(db.Integer)


class Transactions(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer)
    receiver_id = db.Column(db.Integer)
    money = db.Column(db.Integer, nullable = False)
    def __repr__(self):
        return f"Transaction({self.sender_id}, {self.receiver_id}, {self.money})"
    
