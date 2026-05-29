
from flask import Flask, render_template, request, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
    current_user
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from transformers import (
    DistilBertTokenizerFast,
    DistilBertForSequenceClassification
)

import torch
import requests
import pytesseract
import os

from PIL import Image
from datetime import datetime

# =========================================
# APP INIT
# =========================================

app = Flask(__name__)

app.secret_key = "change_this_to_secure_key"

# =========================================
# NEWS API
# =========================================

NEWS_API_KEY = "38dd3d1b255c4b1a9e117cb9732ebd88"

# =========================================
# UPLOAD CONFIG
# =========================================

UPLOAD_FOLDER = "uploads"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# =========================================
# DATABASE
# =========================================

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///history.db"

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

DB = SQLAlchemy(app)

# =========================================
# LOGIN MANAGER
# =========================================

login_manager = LoginManager()

login_manager.init_app(app)

login_manager.login_view = "login"

login_manager.login_message = "Please login first"

# =========================================
# DATABASE MODELS
# =========================================

class DetectionHistory(DB.Model):

    id = DB.Column(DB.Integer, primary_key=True)

    input_text = DB.Column(DB.Text)

    prediction = DB.Column(DB.String(100))

    confidence = DB.Column(DB.Float)

    timestamp = DB.Column(
        DB.DateTime,
        default=datetime.utcnow
    )


class User(UserMixin, DB.Model):

    id = DB.Column(DB.Integer, primary_key=True)

    username = DB.Column(
        DB.String(100),
        unique=True
    )

    password = DB.Column(DB.String(200))


@login_manager.user_loader
def load_user(user_id):

    return User.query.get(int(user_id))

# =========================================
# LOAD AI MODEL
# =========================================

model_path = "bert_model"

tokenizer = DistilBertTokenizerFast.from_pretrained(
    model_path
)

model = DistilBertForSequenceClassification.from_pretrained(
    model_path
)

model.eval()

# =========================================
# LABELS
# =========================================

labels = {

    0: "Fake News",
    1: "Real News",
    2: "Scam Message"

}

# =========================================
# TRUSTED SOURCES
# =========================================

trusted_sources = [
    "BBC News",
    "CNN",
    "Reuters",
    "The Verge",
    "IGN",
    "TechCrunch",
    "Android Central",
    "Nature.com",
    "Ars Technica",
    "Mashable",
    "Nintendo Life",
    "The Drive"
]
# =========================================
# HOME
# =========================================

@app.route("/")
def home():

    return render_template("index.html")

# =========================================
# SIGNUP
# =========================================

@app.route("/signup", methods=["GET", "POST"])
def signup():

    if request.method == "POST":

        username = request.form["username"]

        password = request.form["password"]

        existing_user = User.query.filter_by(
            username=username
        ).first()

        if existing_user:

            return "User already exists"

        user = User(

            username=username,

            password=generate_password_hash(password)

        )

        DB.session.add(user)

        DB.session.commit()

        return redirect("/login")

    return render_template("signup.html")

# =========================================
# LOGIN
# =========================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]

        password = request.form["password"]

        user = User.query.filter_by(
            username=username
        ).first()

        if user and check_password_hash(
            user.password,
            password
        ):

            login_user(user)

            return redirect("/")

        return "Invalid Credentials"

    return render_template("login.html")

# =========================================
# LOGOUT
# =========================================

@app.route("/logout")
@login_required
def logout():

    logout_user()

    return redirect("/login")

# =========================================
# TEXT PREDICTION
# =========================================

@app.route("/predict", methods=["POST"])
def predict():

    news = request.form["news"]

    lower = news.lower()

    scam_keywords = [

        "otp",
        "click now",
        "bank account",
        "reward",
        "claim",
        "lottery",
        "urgent",
        "upi",
        "winner"

    ]

    suspicious_domains = [

        ".xyz",
        ".ru",
        ".tk",
        "bit.ly",
        "tinyurl",
        "free-money"

    ]

    reasons = []

    for word in scam_keywords:

        if word in lower:

            reasons.append(word)

    for domain in suspicious_domains:

        if domain in lower:

            reasons.append(domain)

    inputs = tokenizer(

        news,

        return_tensors="pt",

        truncation=True,

        padding=True

    )

    with torch.no_grad():

        outputs = model(**inputs)

    probs = torch.softmax(outputs.logits, dim=1)

    pred = torch.argmax(probs, dim=1).item()

    confidence = probs[0][pred].item() * 100

    result = labels[pred]

    explanation = "AI-based NLP classification."

    if reasons:

        result = "Scam Message"

        confidence = 99.0

        explanation = (
            f"Detected suspicious patterns: "
            f"{', '.join(reasons)}"
        )

    threat_score = 10

    if result == "Fake News":

        threat_score = 60

    elif result == "Scam Message":

        threat_score = 95

    if current_user.is_authenticated:

        DB.session.add(

            DetectionHistory(

                input_text=news,

                prediction=result,

                confidence=round(confidence, 2)

            )

        )

        DB.session.commit()

    return render_template(

        "index.html",

        prediction=result,

        confidence=round(confidence, 2),

        explanation=explanation,

        reasons=reasons,

        threat_score=threat_score

    )

# =========================================
# IMAGE SCAN
# =========================================

@app.route("/scan-image", methods=["GET", "POST"])
def scan_image():

    if request.method == "POST":

        file = request.files["image"]

        path = os.path.join(

            app.config["UPLOAD_FOLDER"],
            file.filename

        )

        file.save(path)

        text = pytesseract.image_to_string(
            Image.open(path)
        )

        lower = text.lower()

        scam_keywords = [

            "otp",
            "bank",
            "urgent",
            "winner",
            "lottery",
            "upi"

        ]

        detected = [

            word
            for word in scam_keywords
            if word in lower

        ]

        if detected:

            result = "Scam Message"

            confidence = 99

            explanation = (
                f"Detected keywords: "
                f"{', '.join(detected)}"
            )

        else:

            result = "No Scam Detected"

            confidence = 85

            explanation = (
                "No suspicious content found."
            )

        if current_user.is_authenticated:

            DB.session.add(

                DetectionHistory(

                    input_text=text,

                    prediction=result,

                    confidence=confidence

                )

            )

            DB.session.commit()

        return render_template(

            "image_scan.html",

            prediction=result,

            confidence=confidence,

            extracted_text=text,

            reasons=detected,

            explanation=explanation

        )

    return render_template("image_scan.html")

# =========================================
# HISTORY
# =========================================

@app.route("/history")
@login_required
def history():

    records = DetectionHistory.query.order_by(

        DetectionHistory.timestamp.desc()

    ).all()

    return render_template(

        "history.html",

        records=records

    )

# =========================================
# DASHBOARD
# =========================================

@app.route("/dashboard")
@login_required
def dashboard():

    total = DetectionHistory.query.count()

    scam = DetectionHistory.query.filter_by(
        prediction="Scam Message"
    ).count()

    fake = DetectionHistory.query.filter_by(
        prediction="Fake News"
    ).count()

    real = DetectionHistory.query.filter_by(
        prediction="Real News"
    ).count()

    return render_template(

        "dashboard.html",

        total_scans=total,

        scam_count=scam,

        fake_count=fake,

        real_count=real

    )

# =========================================
# LIVE NEWS
# =========================================

@app.route("/live-news")
@login_required
def live_news():

    url = (

        "https://newsapi.org/v2/top-headlines?"

        f"country=us&category=technology&apiKey={NEWS_API_KEY}"

    )

    try:

        response = requests.get(
            url,
            timeout=10
        )

        data = response.json()

        articles = data.get("articles", [])

        output = []

        for a in articles[:10]:

            title = a.get("title", "No title")

            source = a.get(
                "source",
                {}
            ).get("name", "Unknown")

            article_url = a.get("url", "#")

            inputs = tokenizer(

                title,

                return_tensors="pt",

                truncation=True,

                padding=True

            )

            with torch.no_grad():

                out = model(**inputs)

            probs = torch.softmax(
                out.logits,
                dim=1
            )

            pred = torch.argmax(
                probs,
                dim=1
            ).item()

            conf = probs[0][pred].item() * 100

            result = labels[pred]

            # =========================================
            # TRUSTED SOURCE FILTER
            # =========================================

            if source in trusted_sources:

                result = "Real News"

                conf = max(conf, 90)

            # =========================================
            # SCAM KEYWORD FILTER
            # =========================================

            scam_words = [

                "winner",
                "lottery",
                "claim",
                "urgent",
                "free money",
                "click now",
                "bank",
                "otp"

            ]

            title_lower = title.lower()

            if any(
                word in title_lower
                for word in scam_words
            ):

                result = "Scam Message"

                conf = 99.99

            # =========================================
            # REDUCE FALSE POSITIVES
            # =========================================

            tech_words = [

                "google",
                "nintendo",
                "ai",
                "tech",
                "science",
                "research",
                "gaming",
                "android",
                "apple",
                "microsoft"

            ]

            if any(
                word in title_lower
                for word in tech_words
            ):

                if result == "Fake News":

                    result = "Real News"

                    conf = 82

            output.append({

                "title": title,

                "source": source,

                "url": article_url,

                "prediction": result,

                "confidence": round(conf, 2)

            })

        return render_template(

            "live_news.html",

            articles=output

        )

    except Exception as e:

        return render_template(

            "live_news.html",

            articles=[],

            error=str(e)

        )

# =========================================
# INIT DATABASE
# =========================================

with app.app_context():

    DB.create_all()

# =========================================
# RUN APP
# =========================================

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)

