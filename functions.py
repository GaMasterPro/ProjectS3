from models import db, User
import bcrypt
import random
from datetime import datetime

def process_payment(user, input_money, bill_type):
    try:
        input_money = int(input_money)
        if input_money <= 0:
            return "Amount must be greater than zero", None
    except ValueError:
        return "Invalid amount", None

    if user.total_balance < input_money:
        return "Insufficient funds", None

    # Process different types of loans
    if bill_type == 'carLoan':
        user.car_loan -= input_money
        user.total_balance -= input_money
        if user.car_loan <= 0:
            user.car_loan = 0
            return "You have fully paid off your car loan!", True

    elif bill_type == 'educationLoan':
        user.education_loan -= input_money
        user.total_balance -= input_money
        if user.education_loan <= 0:
            user.education_loan = 0
            return "You have fully paid off your education loan!", True

    elif bill_type == 'personalLoan':
        user.personal_loan -= input_money
        user.total_balance -= input_money
        if user.personal_loan <= 0:
            user.personal_loan = 0
            return "You have fully paid off your personal loan!", True

    elif bill_type == 'medicalLoan':
        user.medical_loan -= input_money
        user.total_balance -= input_money
        if user.medical_loan <= 0:
            user.medical_loan = 0
            return "You have fully paid off your medical loan!", True

    elif bill_type == 'houseBills':
        user.houseBills -= input_money
        user.total_balance -= input_money
        if user.houseBills <= 0:
            user.houseBills = 0
            return "You have fully paid off your house bills!", True

    elif bill_type == 'taxes':
        user.taxes -= input_money
        user.total_balance -= input_money
        if user.taxes <= 0:
            user.taxes = 0
            return "You have fully paid off your taxes!", True

    return "Payment successful", False



def handling_transactions(sender_id, receiver_id, money):
    try:
        user1 = User.query.get(sender_id)
        user2 = User.query.get(receiver_id)
        if not user1 or not user2:
            return False, "Invalid user ID(s)"
        if user1.total_balance < money:
            return False, "Insufficient funds"
        
        user1.total_balance -= money
        user2.total_balance += money
        
        db.session.commit()
        return True, "Transaction successful"
    except Exception as e:
        db.session.rollback()
        return False, f"An error occurred: {e}"
    



def signup_user(username, email, password, credit_card, cvv, edate):
    # Check if the username already exists
    if User.query.filter_by(username=username).first():
        return None, "User already exists"
    
    # Hash the password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    
    # Validate the expiration date
    try:
        current_year = datetime.now().year
        edate = datetime.strptime(f"{edate}/{current_year}", "%d/%m/%Y").date()
    except ValueError:
        return None, "Invalid date format. Use DD/MM."
    
    # Generate random money for the new user
    random_money = random.randint(20000, 50000)
    income = random.randint(20000, 50000)
    expenses = random.randint(20000, 50000)
    savings = random.randint(20000, 50000)
    houseBills = random.randint(20000, 50000)
    taxes = random.randint(20000, 50000)
    car_loan = random.randint(20000, 50000)
    education_loan = random.randint(20000, 50000)
    medical_loan = random.randint(20000, 50000)
    personal_loan = random.randint(20000, 50000)
    
    # Check for unique card and email
    if User.query.filter_by(card=credit_card).first():
        return None, "User with the same card exists"
    if User.query.filter_by(email=email).first():
        return None, "User with the same email exists"

    # Create a new user instance
    new_user = User(
        username=username, 
        password=hashed_password,
        total_balance=random_money, 
        email=email, 
        card=credit_card,
        edate=edate,
        cvv=cvv,
        income=income,
        expenses=expenses,
        houseBills=houseBills,
        car_loan=car_loan,
        personal_loan=personal_loan,
        medical_loan=medical_loan,
        taxes=taxes,
        savings=savings,
        education_loan=education_loan
    )
    
    # Save the new user to the database
    db.session.add(new_user)
    db.session.commit()
    
    return new_user, None

def checkPass(password, confirm_password):
    return password == confirm_password


def format_credit_card(card_number):
    # Ensure the card number is a string
    card_number = str(card_number)
    
    # Replace the first 12 digits with asterisks
    formatted_number = "**** **** **** " + card_number[-4:]
    
    return formatted_number
