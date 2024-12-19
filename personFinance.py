from flask import Flask, redirect, url_for, render_template, request, session, flash
from flask_limiter import Limiter 
from flask_limiter.util import get_remote_address
from itsdangerous import URLSafeTimedSerializer
from functools import wraps
from models import db, User, Transactions
import os
import logging
logging.basicConfig(level = logging.DEBUG)
from dotenv import load_dotenv
from configurations import Config
from redis import Redis
from flask_mail import Mail, Message
import bcrypt
from functions import process_payment, handling_transactions, signup_user, checkPass, format_credit_card
app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)
context = (
    os.path.join('./ssl', 'cert.pem'),
    os.path.join('./ssl', 'key.pem')
)
load_dotenv()
redis_client = Redis(host='localhost', port=6379)
mail = Mail(app)
# Initialize Limiter with Redis storage
limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri="redis://localhost:6379"
)
serializer = URLSafeTimedSerializer("your_secret_key")

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def sending_email(amount, type, user_id):
    user = db.session.get(User, user_id)
    email = user.email
    try:
        if user:
            msg = Message('Confirming Payment', recipients = [email])
            msg.body = f"You paid ${amount} for your {type} loan"
            mail.send(msg)
            logging.debug("Email sent")
    except Exception as e:
        logging.error(f"{e}")        

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Query the user by username
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
            session['user_id'] = user.id
            return redirect(url_for('main'))
        else:
            return render_template('login.html', error="Invalid username or password")

    return render_template('login.html')

@app.route('/signfirst', methods=['GET', 'POST'])
def signing():
    if request.method == 'POST':
        try:
            # Get data from the first form
            username = request.form.get('name')
            email = request.form.get('email')
            password = str(request.form.get('password'))
            confirm = str(request.form.get('confirmPassword'))

            # Log form data for debugging
            logging.debug(f"Received data - username: {username}, email: {email}, password: {password}, confirmPassword: {confirm}")
            
            if not username or not email or not password or not confirm:
                logging.error("Missing required fields.")
                flash("Please fill out all fields.")
                return render_template('signfirst.html')

            # Store data in session for use in the next step
            session['username'] = username
            session['email'] = email
            session['password'] = password
            session['confirm'] = confirm
            
            # Validate passwords match
            if checkPass(password, confirm):
                logging.debug("passwords match")
                return redirect(url_for('signing2'))  # Redirect to the next step
            else:
                logging.error("Passwords do not match.")
                flash("Passwords don't match.")
                return render_template('signfirst.html')

        except Exception as e:
            logging.error(f"Error processing form: {e}")
            flash("An error occurred. Please try again.")
            return render_template('signfirst.html')

    return render_template('signfirst.html')

@app.route('/signthecard', methods=['GET', 'POST'])
def signing2():
    if request.method == 'POST':    
        try:
            # Get the data from the second form (card details)
            fullname = request.form.get('fullname')
            card_number = request.form.get('cardnumber')
            edate = request.form.get('edate')
            cvv = request.form.get('cvv')

            logging.debug(f"Form data received: {request.form}")

            if not fullname or not card_number or not edate or not cvv:
                logging.error("Missing card details.")
                flash("Please fill out all card details.")
                return render_template('signthecard.html')

            # Get the data from the session
            username = session.get('username')
            email = session.get('email')
            password = str(session.get('password'))
            confirm = str(session.get('confirm'))

            # Log session data for debugging
            logging.debug(f"Session data - username: {username}, email: {email}, password: {password}, confirm: {confirm}")

            # Check if the passwords match before proceeding
            if not checkPass(password, confirm):
                logging.error("Passwords don't match at the second step.")
                flash("Passwords don't match.")
                return redirect(url_for('signing'))  # Redirect back to the first step if passwords don't match

            user, error = signup_user(username, email, password, card_number, cvv, edate)
            if error:
                logging.error(f"Error during signup: {error}")
                return render_template('signthecard.html', error=error)

            user_id = user.id
            session['user_id'] = user_id
            # Confirm that user is signed up and redirect
            logging.debug("User successfully signed up, redirecting to reservation.")
            return redirect(url_for('main'))  # Ensure 'reservation' is the correct route

        except Exception as e:
            logging.error(f"Error during sign-up process: {e}")
            flash("An error occurred during sign-up. Please try again.")
            return render_template('signthecard.html')

    return render_template('signthecard.html')

@app.route('/main', methods=['GET'])
@login_required
def main():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    user = User.query.get(user_id)
    if not user:
        return redirect(url_for('login'))

    # Mask the card number
    card_number = user.card
    masked_card_number = '*' * (len(card_number) - 4) + card_number[-4:]

    return render_template('index.html', user=user, masked_card_number=masked_card_number)

@app.route('/transactions', methods = ['GET', 'POST'])
@login_required
def transactions():
    # Assuming the user is already logged in and user_id is available in session
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))
    user = User.query.get(user_id)

    # Fetch last 5 transactions for the user
    transactions = Transactions.query.filter(
        (Transactions.sender_id == user_id) | (Transactions.receiver_id == user_id)
    ).order_by(Transactions.id.desc()).limit(5).all()
    return render_template('transactions.html', transactions=transactions, user = user)

@app.route('/makingTransactions', methods=['GET', 'POST'])
@login_required
def makingTransactions():
    if request.method == 'POST':
        sender_id = session.get('user_id')
        receiver_id = request.form.get('receiver_id')
        money = request.form.get('money')
        
        if not sender_id or not receiver_id or not money:
            return render_template('makingTransactions.html', error="All fields are required")
        
        try:
            money = int(money)  
            if money <= 0:
                return render_template('makingTransactions.html', error="Amount must be greater than zero")
        except ValueError:
            return render_template('makingTransactions.html', error="Invalid amount")

        result, message = handling_transactions(sender_id, receiver_id, money)
        if result:
            new_transaction = Transactions(sender_id=sender_id, receiver_id=receiver_id, money=money)
            try:
                db.session.add(new_transaction)
                db.session.commit()
                return render_template('makingTransactions.html', success="Transaction has been made")
            except Exception as e:
                db.session.rollback()
                return render_template('makingTransactions.html', error="Transaction failed: " + str(e))
        else:
            return render_template('makingTransactions.html', error=message)

    return render_template('makingTransactions.html')

@app.route('/redirect-to-payment', methods=['POST'])
@login_required
def redirect_to_payment():
    bill_type = request.form['bill-type']
    
    # Redirect to the corresponding page based on the selected bill type
    if bill_type == 'house-bills':
        return redirect(url_for('houseBills'))
    elif bill_type == 'taxes':
        return redirect(url_for('taxes'))
    elif bill_type == 'car-loan':
        return redirect(url_for('carLoan'))
    elif bill_type == 'education-loan':
        return redirect(url_for('educationLoan'))
    elif bill_type == 'personal-loan':
        return redirect(url_for('personalLoan'))
    elif bill_type == 'medical-loan':
        return redirect(url_for('medicalLoan'))
    else:
        return redirect(url_for('main'))
    

@app.route('/houseBills', methods=['GET', 'POST'])
@login_required
def houseBills():
    if request.method == 'POST':
        input_money = request.form.get('loan-amount')
        user_id = session['user_id']

        user = User.query.get(user_id)
        if not user:
            return render_template('pay-house-bills.html', error="User not found")

        message, complete = process_payment(user, input_money, 'houseBills')
        if complete is None:
            return render_template('pay-house-bills.html', error=message)

        try:
            db.session.commit()
            input_money = float(input_money)
            sending_email(input_money, "House Bills", user_id)
            return redirect(url_for('main'))
        except Exception as e:
            db.session.rollback()
            return render_template('pay-house-bills.html', error="Transaction failed: " + str(e))
    
    return render_template('pay-house-bills.html')


@app.route('/taxes', methods=['GET', 'POST'])
@login_required
def taxes():
    if request.method == 'POST':
        input_money = request.form.get('loan-amount')
        user_id = session['user_id']

        user = User.query.get(user_id)
        if not user:
            return render_template('taxes.html', error="User not found")

        message, complete = process_payment(user, input_money, 'taxes')
        if complete is None:
            return render_template('taxes.html', error=message)

        try:
            db.session.commit()
            logging.debug("Sending the email message")
            input_money = float(input_money)
            sending_email(input_money, "Taxes", user_id)

            if complete:
                return redirect(url_for('main'))
        except Exception as e:
            db.session.rollback()
            return render_template('taxes.html', error="Transaction failed: " + str(e))
    
    return render_template('taxes.html')


@app.route('/carLoan', methods=['GET', 'POST'])
@login_required
def carLoan():
    if request.method == 'POST':
        input_money = request.form.get('loan-amount')
        user_id = session['user_id']

        user = User.query.get(user_id)
        if not user:
            flash("User not found", 'error')
            return render_template('carLoan.html')

        message, complete = process_payment(user, input_money, 'carLoan')
        if complete is None:
            flash(message, 'error')
            return render_template('carLoan.html')
        try:
            db.session.commit()
            flash(message, 'success')
            return redirect(url_for('main'))
        except Exception as e:
            db.session.rollback()
            flash("Transaction failed: " + str(e), 'error')
            return render_template('carLoan.html')
    
    return render_template('carLoan.html')



@app.route('/educationLoan', methods=['GET', 'POST'])
@login_required
def educationLoan():
    if request.method == 'POST':
        input_money = request.form.get('loan-amount')
        user_id = session['user_id']

        user = User.query.get(user_id)
        if not user:
            return render_template('educationLoan.html', error="User not found")

        message, complete = process_payment(user, input_money, 'educationLoan')
        if complete is None:
            return render_template('educationLoan.html', error=message)

        try:
            db.session.commit()
            input_money = float(input_money)
            sending_email(input_money, "Educational Loan", user_id)
            flash(message, 'success')

            if complete:
                return redirect(url_for('main'))
        except Exception as e:
            db.session.rollback()
            return render_template('educationLoan.html', error="Transaction failed: " + str(e))
    
    return render_template('educationLoan.html')


@app.route('/personalLoan', methods=['GET', 'POST'])
@login_required
def personalLoan():
    if request.method == 'POST':
        input_money = request.form.get('loan-amount')
        user_id = session['user_id']

        user = User.query.get(user_id)
        if not user:
            return render_template('personalLoan.html', error="User not found")

        message, complete = process_payment(user, input_money, 'personalLoan')
        if complete is None:
            return render_template('personalLoan.html', error=message)

        try:
            db.session.commit()
            input_money = float(input_money)
            sending_email(input_money, "Personal Loan", user_id)
            
            if complete:
                return redirect(url_for('main'))
        except Exception as e:
            db.session.rollback()
            return render_template('personalLoan.html', error="Transaction failed: " + str(e))
    
    return render_template('personalLoan.html')


@app.route('/medicalLoan', methods=['GET', 'POST'])
@login_required
def medicalLoan():
    if request.method == 'POST':
        input_money = request.form.get('loan-amount')
        user_id = session['user_id']

        user = User.query.get(user_id)
        if not user:
            return render_template('medicalLoan.html', error="User not found")

        message, complete = process_payment(user, input_money, 'medicalLoan')
        if complete is None:
            return render_template('medicalLoan.html', error=message)

        try:
            db.session.commit()
            input_money = float(input_money)
            sending_email(input_money, "Medical Loan", user_id)

            if complete:
                return redirect(url_for('main'))
        except Exception as e:
            db.session.rollback()
            return render_template('medicalLoan.html', error="Transaction failed: " + str(e))
    
    return render_template('medicalLoan.html')


@app.route('/loans', methods=['GET', 'POST'])
@login_required
def loans():
    return render_template('loans.html')

@app.route('/showingcard', methods = ['GET', 'POST'])
@login_required
def showingcard():
    user_id = session['user_id']
    user = User.query.get(user_id)
    card__number = user.card
    result = format_credit_card(card__number)
    return render_template('showingcard.html', user = user, card = result)

@app.route('/about', methods = ['GET', 'POST'])
@login_required
def about():
    user_id = session['user_id']
    user = User.query.get(user_id)
    return render_template('about.html', user = user)

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('username', None)
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        try:
            app.run(host='0.0.0.0', port=443, ssl_context=context)
        except (KeyboardInterrupt, SystemExit):
            pass