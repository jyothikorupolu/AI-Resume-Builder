

from flask import Flask, redirect, render_template, request, session,flash, url_for 
import sqlite3
import fitz 
import pytesseract
pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'
from pdf2image import convert_from_bytes
import json
from docx import Document  # PyMuPDF
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash  
from authlib.integrations.flask_client import OAuth
import smtplib
import random
from email.mime.text import MIMEText
import os
import re
from dotenv import load_dotenv
load_dotenv()
from groq import Groq


GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
app = Flask(__name__)
oauth = OAuth(app)
oauth.register(
    name='google',
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile'
    }
)
app.secret_key = os.getenv('secret_key')
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  email TEXT NOT NULL UNIQUE,
                  password TEXT NOT NULL,
                  provider TEXT NOT NULL,
                  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
    conn.commit()
    conn.close()
init_db()
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        password_pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$'
        if not re.match(password_pattern, password):
            return render_template('register.html', error="Password must be at least 8 characters long and include uppercase, lowercase, number, and special character")    
        conn= sqlite3.connect('users.db')
        c = conn.cursor()   
        c.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = c.fetchone()
        if user:
            return render_template('register.html', error="User already exists")
        else:
            hashed_password = generate_password_hash(password)
            c.execute("INSERT INTO users (email, password, provider, timestamp) VALUES (?, ?, ?, ?)", (email, hashed_password, 'local', sqlite3.datetime.datetime.now()))
            conn.commit()
            return render_template('login.html', success="Registration successful")

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        conn= sqlite3.connect('users.db')
        c = conn.cursor()   
        c.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = c.fetchone()
        conn.close()
        if user and check_password_hash(user[2], password):
            session['user']= user[1]  # Store email in session
            return redirect('/dashboard')
        else:
            return render_template('login.html', error="Invalid credentials")

    return render_template('login.html')


@app.route('/google_callback')
def google_callback():

    if 'error' in request.args:
        return render_template('login.html', error="Google login failed: " )
    token = oauth.google.authorize_access_token()
    user_info = oauth.google.get('https://www.googleapis.com/oauth2/v3/userinfo').json()
    email = user_info['email']
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = c.fetchone()
    conn.close()
    if not user:
        session['reset_email'] = email
        print("Reset email session:", session.get('reset_email'))
        return redirect('/reset')
    
    session['user'] = email
    return redirect('/dashboard')

@app.route('/login/google')
def google_login():
    redirect_uri = os.getenv('Redirect_uri')
    return oauth.google.authorize_redirect(redirect_uri)


@app.route('/dashboard')
def dashboard():

    if 'user' in session:
        return render_template('/dashboard.html')
    else:
        return redirect('/login')

@app.route('/logout')
def logout():
    session.pop('user', None)
    return render_template('index.html')

@app.route('/delete_account', methods=['POST'])
def delete_account():  
    if 'user' in session:
        email = session['user']
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("DELETE FROM users WHERE email = ?", (email,))
        conn.commit()
        conn.close()
        session.pop('user', None)
        return redirect('/register')
    else:
        return redirect('/login')
    return render_template('dashboard.html')  

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email'].strip()
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = c.fetchone()
        conn.close()
        if user:
            session['reset_email'] = email
            otp= random.randint(100000, 999999)
            session['otp'] = otp
            send_otp_email(email, otp)
            return redirect('/verify_otp')
        else:
            return render_template('forgot.html', error="Email not found")
    return render_template('forgot.html')

def send_otp_email(email, otp):
    sender_email = os.getenv('EMAIL_USER')
    sender_password = os.getenv('EMAIL_PASS')
    msg = MIMEText(f"Your OTP for password reset is: {otp}")
    msg['Subject'] = "Password Reset OTP"
    msg['From'] = sender_email
    msg['To'] = email
    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.send_message(msg)
    except Exception as e:
        print("Failed to send email:", e)

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():   
    if request.method == 'POST':
        user_otp = request.form['otp']  
        if 'otp' in session and str(session['otp']) == user_otp:
            return redirect('/reset')
        else:
            return render_template('otpverify.html', error="Invalid OTP")       
    return render_template('otpverify.html')   

@app.route('/resend_otp', methods=['POST'])
def resend_otp():
    if 'reset_email' in session:
        email = session['reset_email']
        otp = random.randint(100000, 999999)
        session['otp'] = otp
        send_otp_email(email, otp)
    return redirect('/verify_otp')

@app.route('/reset', methods=['GET', 'POST'])
def reset():
    if 'reset_email' not in session:
        return redirect('/forgot_password')
    if request.method == 'POST':
        email = session.get('reset_email')
        new_password = request.form['password']
        confirm_password = request.form['confirm_password']
        password_pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$'
        if not re.match(password_pattern, new_password):
            return render_template('reset.html', error="New password must be at least 8 characters long and include uppercase, lowercase, number, and special character")
        if new_password != confirm_password:
            return render_template('reset.html', error="Passwords do not match")
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        hashed_password = generate_password_hash(new_password)
        c.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = c.fetchone()
        if user:
           c.execute("UPDATE users SET password = ? WHERE email = ?", (hashed_password, email))
        else:
            c.execute("INSERT INTO users (email, password, provider, timestamp) VALUES (?, ?, ?, ?)", (email, hashed_password, 'google', sqlite3.datetime.datetime.now()))
        conn.commit()
        conn.close()
        session.pop('reset_email', None)
        session['user'] = email
        return redirect('/dashboard')
    return render_template('reset.html')

def extract_text_from_docx(file):
    text = ""
    try:
        document = Document(file)
        for para in document.paragraphs:
            text += para.text + "\n"
    except Exception as e:
        print("Error extracting DOCX text:", e)
    return text

def extract_text(file):
    filename=file.filename.lower()
    if filename.endswith('.pdf'):
        text= extract_text_from_pdf(file)
        if len(text.strip())<50:
            file.seek(0)
            text=extract_text_using_ocr(file)
    elif filename.endswith('.docx'):
        text=extract_text_from_docx(file)
    else:
        return "Unsupported file type"
    return text
def extract_text_from_pdf(file):
    text = ""
    try:
        pdf = fitz.open(stream=file.read(), filetype="pdf")

        for page in pdf:
            text += page.get_text()

    except Exception as e:
        print("Error extracting PDF text:", e)

    return text

def extract_text_using_ocr(file):
    text = ""
    try:
        images = convert_from_bytes(file.read())
        for image in images:
            text += pytesseract.image_to_string(image)
    except Exception as e:
        print("Error extracting text using OCR:", e)
    return text

def clean_text(text):
    text = re.sub(r'[^\w\s@.]', '', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text

def create_prompt(text):
    cleaned_text = clean_text(text)

    return f"""
Resume:
{cleaned_text}

You are an expert Technical Recruiter, ATS Scanner, and Career Coach.

Analyze the provided resume in detail as if you are reviewing a candidate for Software Development Engineer (SDE), AI/ML Engineer, and Python Developer roles.

Provide the analysis in the following JSON format:

{{
  "ats_score_estimate": 0,

  "ats_breakdown": {{
    "contact_information": 0,
    "education": 0,
    "technical_skills": 0,
    "projects": 0,
    "experience": 0,
    "achievements": 0,
    "ats_keywords": 0,
    "formatting": 0
  }},

  "whats_good": [
    ""
  ],

  "strengths": [
    ""
  ],

  "weaknesses": [
    ""
  ],

  "improvements_to_reach_90_plus": [
    ""
  ],

  "missing_keywords": [
    ""
  ],

  "recommended_job_roles": [
    ""
  ],

  "overall_feedback": "",

  "job_description_match": {{
    "sde_role": 0,
    "python_developer": 0,
    "ai_ml_engineer": 0
  }}
}}

Scoring Guidelines:

- Education: 15%
- Technical Skills: 20%
- Projects: 25%
- Experience/Internships: 15%
- ATS Keywords: 15%
- Formatting & Readability: 10%

For improvements, provide specific actionable suggestions that can increase the ATS score above 90.

Return ONLY valid JSON.
Do not include markdown, explanations, or code blocks.
Ensure the JSON is valid and parseable by Python json.loads().
"""

groq_client = Groq(api_key=os.getenv('GROQ_API_KEY'))

def analyze_resume_with_groq(text):

    prompt = create_prompt(text)

    try:
        response = groq_client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.2,
            max_tokens=3000
        )

        result = response.choices[0].message.content.strip()

        # Remove markdown if Groq returns ```json ... ```
        if result.startswith("```"):
            result = result.replace("```json", "")
            result = result.replace("```", "")
            result = result.strip()

        analysis = json.loads(result)

        return analysis

    except json.JSONDecodeError:
        return {
            "error": "Invalid JSON returned by LLM",
            "raw_response": result
        }

    except Exception as e:
        return {
            "error": str(e)
        }
@app.route('/upload_resume', methods=['GET', 'POST'])
def upload_resume():
    if request.method == 'POST':
        if 'resume' not in request.files:
            return render_template('resumeUpload.html', error="No file selected")
        file = request.files['resume']
        if file.filename == '':
            return render_template('resumeUpload.html', error="No file selected")
        if file:
            text = extract_text(file)
            filename = secure_filename(file.filename)
            os.makedirs('resumes', exist_ok=True)
            file.save(os.path.join('resumes', filename))
            text=clean_text(text)
            text=text[:3000]
            prompt=create_prompt(text)
            result=analyze_resume_with_groq(text)
            print("Final Result:", result)
            print("Type of Result:", type(result))
            return render_template('result.html', result=result)
    return render_template('resumeUpload.html')

if __name__ == '__main__':
    app.run(debug=True)