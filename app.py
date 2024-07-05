from flask import Flask, render_template, session, redirect, request, url_for, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from flask_sqlalchemy import SQLAlchemy
from langchain_openai import ChatOpenAI
import os
import json
from flask_migrate import Migrate
import random
import smtplib
import requests
from langchain_core.prompts import ChatPromptTemplate
from langchain.chains import LLMChain
# import nest_asyncio
from scrapegraphai.graphs import SmartScraperGraph
from langchain_core.output_parsers import StrOutputParser
from sqlalchemy.orm import Session
from bs4 import BeautifulSoup
from dotenv import load_dotenv
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
# nest_asyncio.apply()
load_dotenv()
app = Flask(__name__, static_url_path='/static', static_folder='static')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
# Set your OpenAI API key
api_key = os.getenv('OPENAI_API_KEY')
client = ChatOpenAI(api_key=api_key)

# Your fine-tuned model ID
fine_tuned_model = os.getenv('FINE_TUNED_MODEL_ID')

db = SQLAlchemy(app)

# Configuration for email
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'igatajohn15@gmail.com'
app.config['MAIL_PASSWORD'] = 'vqvq zdef tweu nytn'
app.config['MAIL_DEFAULT_SENDER'] = 'igatajohn15@gmail.com'
app.config['SECURITY_PASSWORD_SALT'] = 'e33f8aa37685ca765b9d5613c0e41c0b'
mail = Mail(app)
# Secret key for generating reset tokens
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
migrate = Migrate(app, db)
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(150), nullable=False)
    last_name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class CourseRecommendation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    skill = db.Column(db.String(100), nullable=False)
    course_title = db.Column(db.String(200), nullable=False)
    course_description = db.Column(db.Text, nullable=False)
    course_url = db.Column(db.String(500), nullable=False)
    user = db.relationship('User', backref=db.backref('recommendations', lazy=True))
class SkillRecommendation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    skill_title = db.Column(db.String(100), nullable=False)
    skill_description = db.Column(db.Text, nullable=False)
    user = db.relationship('User', backref=db.backref('skills', lazy=True))
class CommunityRecommendation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    community_name = db.Column(db.String(100), nullable=False)
    community_description = db.Column(db.Text, nullable=False)
    community_url = db.Column(db.String(500), nullable=False)
    user = db.relationship('User', backref=db.backref('communities', lazy=True))

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
with app.app_context():
    db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            # Fetch form data using request.form.get() to avoid KeyError
            first_name = request.form.get('first_name')
            last_name = request.form.get('last_name')
            email = request.form.get('email')
            password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')

            # Validate form data
            if not all([first_name, last_name, email, password, confirm_password]):
                flash('Please fill in all fields.', 'error')
                return redirect(url_for('register'))

            existing_user = User.query.filter_by(email=email).first()
            if existing_user:
                flash('Email already exists. Please use a different email.', 'error')
                return redirect(url_for('register'))

            if password != confirm_password:
                flash('Password and Confirm Password do not match.', 'error')
                return redirect(url_for('register'))

            # Hash password
            password_hash = generate_password_hash(password)

            # Create new user object and add to database
            new_user = User(first_name=first_name, last_name=last_name, email=email, password=password_hash)
            db.session.add(new_user)
            db.session.commit()

            flash('You have successfully registered!', 'success')
            return redirect(url_for('successful_register'))

        except Exception as e:
            flash('An error occurred while processing your request.', 'error')
            print(str(e))
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            # Generate OTP
            otp = random.randint(1000, 9999)
            session['otp'] = otp
            session['user_id'] = user.id

            # Send OTP to user's email
            send_otp_email(user.email, otp)

            flash('OTP sent to your email. Please verify.', 'info')
            return redirect(url_for('otp_verify'))
        else:
            flash('Invalid email or password. Please try again.', 'error')

    return render_template('login.html')
@app.route('/otp_verify', methods=['GET', 'POST'])
def otp_verify():
    if request.method == 'POST':
        otp_input = request.form['otp']
        if otp_input == str(session.get('otp')):
            user = User.query.get(session['user_id'])
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('chat'))
        else:
            flash('Invalid OTP. Please try again.', 'error')
    return render_template('otp.html')
def send_otp_email(to_email, otp):
    from_email = app.config['MAIL_USERNAME']
    from_password = app.config['MAIL_PASSWORD']
    smtp_server = app.config['MAIL_SERVER']
    smtp_port = app.config['MAIL_PORT']

    subject = 'Your OTP Code'
    body = f'Your OTP code is {otp}.'

    msg = MIMEMultipart()
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'plain'))

    try:
        with smtplib.SMTP_SSL(smtp_server, smtp_port) as server:
            server.login(from_email, from_password)
            server.sendmail(from_email, to_email, msg.as_string())
        print("OTP email sent successfully!")
    except smtplib.SMTPException as e:
        print(f"SMTP error occurred: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")
@app.route('/')
@app.route('/login-page')
def login_page():
    return render_template('login.html')
@app.route('/otp-page')
def otp_page():
    return render_template('otp.html')
@app.route('/get-response', methods=['POST'])
@login_required
def get_response():
    try:
        if 'voice_data' in request.files:
            # Handle voice data from frontend, assuming it's a file upload
            voice_file = request.files['voice_data']
            user_input = transcribe_voice(voice_file)  # Function to transcribe voice to text
        else:
            user_input = request.json.get('input')

        response = generate_response(user_input)
        return jsonify({'response': response})
    except Exception as e:
        return jsonify({'error': str(e)})
# OTP generation
def generate_otp():
    return str(random.randint(1000, 9999))
@app.route('/otp')
def otp():
    return render_template('otp.html')
@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    otp = request.json.get('otp')
    if otp == session.get('otp'):
        session.pop('otp', None)  # Clear the OTP from session
        return jsonify({'success': True, 'redirect_url': url_for('dashboard')})
    else:
        return jsonify({'success': False, 'error': 'Invalid OTP'})
@app.route('/chat')
@login_required
def chat():
    return render_template('chat.html')

@app.route('/chatbot', methods=['POST'])
def chatbot():
    data = request.json
    user_input = data.get('message', '')

    response = generate_response(user_input)
    
    return jsonify({'reply': response})
    # Define the prompt template
template = """
Dathway is an engaging and friendly chatbot, providing guidance and counseling to folks who wants to get into technology.
- lead the conversation and ask questions to get to know them, start by asking the user for their name, their social life, their hobbies, what they love
- encourage users to share more about their interests and experiences
- whether a user is experienced or not, you have to assume he or she does not know their career path and treat them like novices
- offer encouragement and show understanding of user's interests and concerns
- Guide users to additional resources on the platform as needed, for instance, users should click on courses to get the recommended courses,
- provide summary of your discovery about the users passion from the preceding conversation
- after the summary, instruct the user to click on the skills for the next line of action and that ends your conversation with that user
- maintain a balance between conversational and professional

User: {user_input}
Dathway:
"""

# Create the prompt template
prompt = ChatPromptTemplate.from_messages(
    [
        ('system', template),
        ('user','{user_input}')
    ]
)
parser=StrOutputParser()
# Initialize the chat model
chat_model = ChatOpenAI(model_name=fine_tuned_model)

# Create the LLMChain
llm_chain = prompt | chat_model | parser
def generate_response(user_input):
    try:
        # Generate the response using the LLMChain
        response = llm_chain.invoke({"user_input":user_input})
        return response
    except Exception as e:
        return str(e)

@app.route('/skills')
@login_required
def skills():
    recommended_skills = SkillRecommendation.query.filter_by(user_id=current_user.id).all()
    return render_template('skills.html', skills=recommended_skills)
def send_password_reset_email(user):
    token = generate_reset_token(user)
    reset_url = url_for('reset_password', token=token, _external=True)
    msg = Message(
        subject="Password Reset Request",
        recipients=[user.email],
        body=f"To reset your password, visit the following link: {reset_url}\n\n"
             "If you did not make this request, please ignore this email."
    )
    try:
        mail.send(msg)
        print(f"Sent email to {user.email}")
    except Exception as e:
        print(f"Failed to send email: {e}")

def generate_reset_token(user):
    return serializer.dumps(user.email, salt=app.config['SECURITY_PASSWORD_SALT'])
def confirm_reset_token(token, expiration=3600):
    try:
        email = serializer.loads(
            token,
            salt=app.config['SECURITY_PASSWORD_SALT'],
            max_age=expiration
        )
    except:
        return False
    return email
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    email = confirm_reset_token(token)
    if not email:
        flash('The reset link is invalid or has expired.', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('reset_password', token=token))

        user = User.query.filter_by(email=email).first()
        if user:
            user.password = generate_password_hash(password)
            db.session.commit()
            flash('Your password has been updated!', 'success')
            return redirect(url_for('new_password_set'))

    return render_template('reset_password.html', token=token)
@app.route('/password_reset_mail_sent')
def password_reset_mail_sent():
    return render_template('password_reset_mail_sent.html')

@app.route('/new_password_set')
def new_password_set():
    return render_template('new_password_set.html')
@app.errorhandler(401)
def unauthorized(error):
    return render_template('unauthorize.html'), 401

@app.route('/community')
@login_required
def community():
    recommended_communities = CommunityRecommendation.query.filter_by(user_id=current_user.id).all()
    return render_template('community.html', communities=recommended_communities)

@app.route('/courses')
@login_required
def courses():
    user_id = current_user.id
    recommended_courses = CourseRecommendation.query.filter_by(user_id=user_id).all()
    
    # Debug: Print recommended courses
    for course in recommended_courses:
        print(f"Course: {course.course_title}, URL: {course.course_url}")

    return render_template('courses.html', courses=recommended_courses)


@app.route('/recommend-skills', methods=['POST'])
@login_required
def recommend_skills():
    try:
        user_input = request.json.get('input')
        
        prompt = f"I want to begin machine learning. Recommend necessary skillsets for: {user_input}"
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": prompt}
            ]
        )

        # Extract the assistant's message content
        message_content = response.choices[0].message.content

        # Split the message content into skills and descriptions
        recommended_skills = []
        for line in message_content.strip().split('\n'):
            if line and ':' in line:
                skill, description = line.split(':', 1)
                recommended_skills.append({"title": skill.strip(), "description": description.strip()})

        # Save recommended skills to the database
        for skill in recommended_skills:
            new_skill = SkillRecommendation(
                user_id=current_user.id,
                skill_title=skill['title'],
                skill_description=skill['description']
            )
            db.session.add(new_skill)
        db.session.commit()
        
        return jsonify({'skills': recommended_skills})
    except Exception as e:
        return jsonify({'error': str(e)})



@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')
@app.route('/account')
def account():
    return render_template('account.html')
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('login'))
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            send_password_reset_email(user)
            flash('A password reset email has been sent.', 'info')
        else:
            flash('No account associated with this email.', 'error')
        return redirect(url_for('password_reset_mail_sent'))
    return render_template('forgot_password.html')
if __name__ == '__main__':
    app.run(debug=True,host='0.0.0.0',port='5000')
