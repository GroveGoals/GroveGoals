# GroveGoals

A website made to track your goals any type of goals.

## Project Structure

```
├── README.md              # This file
├── app.py                 # Flask backend (authentication, APIs, database)
├── requirements.txt       # Python dependencies
├── Procfile               # Deployment configuration (Heroku)
├── .env.example           # Environment variables template
├── templates/             # Frontend HTML files
│   └── grovegoals.html    # Main application page
└── .gitignore            # Git ignore rules
```

## Setup

### Prerequisites
- Python 3.8+
- PostgreSQL (Neon.tech recommended for free tier)

### Installation

1. Clone the repository
```bash
git clone https://github.com/GroveGoals/GroveGoals.git
cd GroveGoals
```

2. Create a virtual environment
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies
```bash
pip install -r requirements.txt
```

4. Setup environment variables
```bash
cp .env.example .env
# Edit .env with your configuration
```

5. Initialize the database
```bash
flask --app app init-db
```

6. Run the application
```bash
flask --app app run --debug
```

## Features

✨ **AI-Guided Goal Planning** - Personalized roadmaps with milestones and tasks

🔐 **Secure Authentication** - Password hashing with bcrypt, CSRF protection

📊 **Progress Tracking** - XP system, streaks, achievements

🎯 **Goal Templates** - Pre-built roadmaps for popular goals

🤖 **AI Coach** - Powered by Gemini or Anthropic APIs

📚 **Learning Resources** - YouTube video search integration

## Environment Variables

Create a `.env` file based on `.env.example` with:

- `SECRET_KEY` - Flask secret key (generate a random string)
- `DATABASE_URL` - PostgreSQL connection string
- `FLASK_ENV` - Set to `production` or `development`
- `GEMINI_API_KEY` - (Optional) Google Gemini API key for AI Coach
- `ANTHROPIC_API_KEY` - (Optional) Anthropic API key for AI Coach
- `YOUTUBE_API_KEY` - (Optional) YouTube API key for video search

## Security

- ✅ Password storage: bcrypt hashing
- ✅ HTTPS enforcement in production
- ✅ Session security: HttpOnly + Secure + SameSite cookies
- ✅ Rate limiting: 5 attempts/min on auth routes
- ✅ SQL injection protection: Parameterized queries
- ✅ CSRF protection: Flask-WTF CSRFProtect
- ✅ Password reset: Single-use, time-limited tokens

## Deployment

The app is configured for Heroku with the provided `Procfile`. Ensure your environment variables are set in your hosting platform.

## License

MIT License
