# GroveGoals Deployment Guide

This guide covers deploying GroveGoals to production.

## Quick Deploy to Render.com (Recommended - Free Tier)

### Prerequisites
- GitHub account (already have it ✓)
- Render.com account (free)

### Steps

1. **Sign up at [render.com](https://render.com)**

2. **Connect your GitHub repository**
   - Click "New" → "Web Service"
   - Select "GitHub"
   - Authorize and select `GroveGoals/GroveGoals`
   - Choose branch: `deploy`

3. **Configure the service**
   - **Name**: `grovegoals`
   - **Runtime**: Python 3
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn app:app`
   - **Plan**: Free (or Starter for reliability)

4. **Set environment variables**
   - Click "Environment"
   - Add these variables:
     ```
     FLASK_ENV=production
     SECRET_KEY=<generate a 50+ character random string>
     ```
   - Optional:
     - `ANTHROPIC_API_KEY=` (for AI Coach)
     - `YOUTUBE_API_KEY=` (for video search)

5. **Deploy**
   - Click "Create Web Service"
   - Render deploys automatically (takes 2-3 min)
   - Your app will be live at `https://grovegoals.onrender.com`

---

## Deploy to Heroku (Alternative)

### Prerequisites
- Heroku CLI: https://devcenter.heroku.com/articles/heroku-cli
- Heroku account (free tier available)

### Steps

```bash
# 1. Login to Heroku
heroku login

# 2. Create a new app
heroku create grovegoals

# 3. Set environment variables
heroku config:set FLASK_ENV=production
heroku config:set SECRET_KEY=$(openssl rand -base64 32)
heroku config:set ANTHROPIC_API_KEY=your-key-here  # optional
heroku config:set YOUTUBE_API_KEY=your-key-here    # optional

# 4. Deploy this branch
git push heroku deploy:main

# 5. Initialize the database
heroku run flask --app app init-db

# 6. View your app
heroku open
```

Your app will be live at `https://grovegoals.herokuapp.com`

---

## Deploy to Railway.app (Modern Alternative)

### Steps

1. Go to [railway.app](https://railway.app)
2. Click "New Project"
3. Select "Deploy from GitHub"
4. Authorize and select `GroveGoals/GroveGoals`
5. Choose branch: `deploy`
6. Add these environment variables:
   ```
   FLASK_ENV=production
   SECRET_KEY=<50+ char random string>
   ```
7. Railway auto-detects Flask and deploys
8. Your URL appears in the dashboard

---

## Generate a Secure SECRET_KEY

Run this in your terminal:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(50))"
```

Copy the output and use it as your SECRET_KEY.

---

## Database & Persistence

- **SQLite (current)**: Works on Render/Heroku but **data is lost when app restarts**
- **For production**, upgrade to PostgreSQL:
  - Render: Add PostgreSQL service (free tier available)
  - Heroku: `heroku addons:create heroku-postgresql:hobby-dev`
  - Update code to use PostgreSQL connection string

---

## First Time Setup After Deploy

Once deployed, the release command in `Procfile` runs automatically:
```
flask --app app init-db
```

This creates the SQLite database with all necessary tables.

---

## Monitoring

- **Render**: View logs in dashboard
- **Heroku**: `heroku logs --tail`
- **Railway**: Real-time logs in dashboard

---

## Next Steps

1. ✅ Choose a platform above
2. ✅ Deploy (2-5 minutes)
3. ✅ Test signup/login
4. ✅ Add optional APIs (AI Coach, YouTube)
5. ✅ Buy a custom domain (optional)

**Your website will be LIVE in minutes!**
