from flask import Flask, request, render_template, redirect, url_for, session, flash, jsonify
import numpy as np
import warnings
import pickle
import os
import datetime
from feature import FeatureExtraction

warnings.filterwarnings('ignore')

app = Flask(__name__)

# Read the secret key from the environment variable (or use a default if not set)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'your_default_key')
app.permanent_session_lifetime = datetime.timedelta(days=7)  # Set session lifetime

# Load model
with open("pickle/model.pkl", "rb") as file:
    gbc = pickle.load(file)

# Statistics for dashboard
stats = {
    'urls_checked': 0,
    'phishing_detected': 0,
    'safe_sites': 0
}

# Middleware to check if user is logged in
def login_required(route_function):
    def wrapper(*args, **kwargs):
        if 'email' not in session:
            return redirect(url_for('login'))
        return route_function(*args, **kwargs)
    wrapper.__name__ = route_function.__name__
    return wrapper

# Login route
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        if email:
            session.permanent = True  # Use permanent session
            session['email'] = email
            session['history'] = []  # Initialize history for the user
            session['last_login'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            flash('Login successful! Welcome to PhishAway.', 'success')
            return redirect(url_for("index"))
    return render_template("login.html")

# URL checker route (Index)
@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    if request.method == "POST":
        url = request.form["url"]
        
        try:
            obj = FeatureExtraction(url)
            x = np.array(obj.getFeaturesList()).reshape(1, 30)
            y_pred = gbc.predict(x)[0]
            y_pro_phishing = gbc.predict_proba(x)[0, 0]
            y_pro_non_phishing = gbc.predict_proba(x)[0, 1]
            
            # Update global stats
            stats['urls_checked'] += 1
            if y_pro_non_phishing >= 0.5:
                stats['safe_sites'] += 1
            else:
                stats['phishing_detected'] += 1
            
            # Store the URL and its result in the session
            if 'history' not in session:
                session['history'] = []
            
            # Calculate consistent values for display
            is_safe = y_pro_non_phishing >= 0.5
            safety_score = round(y_pro_non_phishing * 100, 2)
                
            # Add timestamp to history
            session['history'].append({
                'url': url,
                'prediction': 'Safe' if is_safe else 'Unsafe',
                'confidence': safety_score,
                'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })
            
            # Keep only the most recent 20 entries
            session['history'] = session['history'][-20:]
            session.modified = True  # Ensure the session is saved
            
            return render_template("index.html", 
                                  xx=round(y_pro_non_phishing, 2),
                                  is_safe=is_safe,
                                  safety_score=safety_score,
                                  # Adding display_score for consistency
                                  display_score=safety_score,
                                  url=url, 
                                  history=session.get('history', []))
                                  
        except Exception as e:
            error_message = f"An error occurred: {str(e)}"
            return render_template("index.html", 
                                  error=error_message, 
                                  history=session.get('history', []))

    return render_template("index.html", xx=-1, history=session.get('history', []))

# Dashboard route
@app.route("/dashboard")
@login_required
def dashboard():
    user_stats = {
        'total_checks': len(session.get('history', [])),
        'safe_count': sum(1 for item in session.get('history', []) if item['prediction'] == 'Safe'),
        'unsafe_count': sum(1 for item in session.get('history', []) if item['prediction'] == 'Unsafe'),
        'last_login': session.get('last_login', 'N/A')
    }
    
    return render_template("dashboard.html", 
                          user_stats=user_stats, 
                          global_stats=stats, 
                          history=session.get('history', []))

# API endpoint for checking URLs (for AJAX requests)
@app.route("/api/check", methods=["POST"])
@login_required
def api_check():
    data = request.get_json()
    url = data.get('url', '')
    
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    
    try:
        obj = FeatureExtraction(url)
        x = np.array(obj.getFeaturesList()).reshape(1, 30)
        y_pro_non_phishing = gbc.predict_proba(x)[0, 1]
        
        result = {
            'url': url,
            'is_safe': y_pro_non_phishing >= 0.5,
            'safety_score': round(y_pro_non_phishing * 100, 2)
        }
        
        return jsonify(result), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Clear history
@app.route("/clear-history")
@login_required
def clear_history():
    if 'history' in session:
        session['history'] = []
        session.modified = True
    return redirect(url_for('index'))

# Logout route
@app.route("/logout")
def logout():
    session.pop('email', None)
    session.pop('history', None)
    session.pop('last_login', None)
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for("login"))

if __name__ == "__main__":
    # Create a directory for static images if it doesn't exist
    os.makedirs('static/images', exist_ok=True)
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))