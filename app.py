from flask import Flask, render_template, session, redirect, request, url_for, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from flask_sqlalchemy import SQLAlchemy
from openai import OpenAI
import os
import json
from flask_migrate import Migrate
import requests
# import nest_asyncio
from scrapegraphai.graphs import SmartScraperGraph
from sqlalchemy.orm import Session
from bs4 import BeautifulSoup
from dotenv import load_dotenv
# nest_asyncio.apply()
load_dotenv()
app = Flask(__name__, static_url_path='/static', static_folder='static')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
# Set your OpenAI API key
api_key = os.getenv('OPENAI_API_KEY')
client = OpenAI(api_key=api_key)

# Your fine-tuned model ID
fine_tuned_model = os.getenv('FINE_TUNED_MODEL_ID')

db = SQLAlchemy(app)
migrate = Migrate(app, db)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fullname = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

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
        fullname = request.form['fullname']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Check if email already exists in the database
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already exists. Please use a different email.', 'error')
            return redirect(url_for('register'))

        # Check if password matches confirmation
        if password != confirm_password:
            flash('Password and Confirm Password do not match.', 'error')
            return redirect(url_for('register'))

        # Hash password
        password_hash = generate_password_hash(password)

        # Insert new user into the database
        new_user = User(fullname=fullname, email=email, password=password_hash)
        db.session.add(new_user)
        db.session.commit()

        flash('You have successfully registered!', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('chat'))
        else:
            flash('Invalid email or password. Please try again.', 'error')
    
    return render_template('login.html')

@app.route('/chat')
@login_required
def chat():
    return render_template('chat.html')
@app.route('/get-response', methods=['POST'])
@login_required
def get_response():
    try:
        user_input = request.json.get('input')
        response = generate_response(user_input)
        return jsonify({'response': response})
    except Exception as e:
        return jsonify({'error': str(e)})

def generate_response(user_input):
    try:
        # Create a chat completion using the fine-tuned GPT-3.5 Turbo model
        completion = client.chat.completions.create(
            model=fine_tuned_model,
            messages=[
                {"role": "system", "content": "Dathway is an engaging and friendly chatbot."},
                {"role": "user", "content": user_input}
            ]
        )

        # Extract the model's response content
        model_response = completion.choices[0].message.content.strip()

        return model_response
    except Exception as e:
        return str(e)

@app.route('/skills')
@login_required
def skills():
    recommended_skills = SkillRecommendation.query.filter_by(user_id=current_user.id).all()
    return render_template('skills.html', skills=recommended_skills)

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



@app.route('/recommend-courses', methods=['POST'])
def recommend_courses():
    data = request.json
    user_input = data.get('input')

    if not user_input:
        return jsonify({'courses': []})

    # Define the query for ScrapeGraphAI
    query = f"Find courses on Coursera for {user_input}"
    graph_config = {
    "llm": {
        "api_key": api_key,
        "model": "gpt-3.5-turbo",
    },
    "browser":{
        "headless":False
    }
    }
    scraper = SmartScraperGraph(
        prompt=query,
        source="https://www.coursera.org/search?query=query",
        config=graph_config
    )

    try:

        # Perform the scraping
        result = scraper.run()

        # Extract the relevant information from the result
        courses = []
        for item in result.get('results', []):
            title = item.get('title')
            description = item.get('description')
            url = item.get('url')
            courses.append({
                'title': title,
                'description': description,
                'url': url
            })

        return jsonify({'courses': courses})
    except Exception as e:
        print(f"Error occurred: {e}")
        return jsonify({'courses': []})
@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True,host='0.0.0.0',port='5000')
