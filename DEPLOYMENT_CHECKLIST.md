# Deployment Checklist for CyHub

## ✅ Changes Made

### Backend Changes:
1. ✅ Added `/stats` endpoint to return:
   - `total_scanned`: Total number of requests analyzed
   - `normal_count`: Number of benign requests
   - `suspicious_count`: Number of suspicious requests
   - `model_status`: Model loading status

### Frontend Changes:
1. ✅ Updated `stats-overview.tsx` to fetch real data from backend
2. ✅ Added auto-refresh (every 30 seconds) for live updates
3. ✅ Added `StatsResponse` type definition
4. ✅ Added `fetchStats()` function to API client

---

## 🚀 Deployment Steps

### 1. Fix Google OAuth (Most Important)

#### A. Supabase Configuration:
1. Go to your [Supabase Dashboard](https://app.supabase.com)
2. Navigate to **Authentication → URL Configuration**
3. Set **Site URL** to:
   ```
   https://cyper-pox-cy-hub-hack-nova-cyber-te-two.vercel.app
   ```
4. Add to **Redirect URLs**:
   ```
   https://cyper-pox-cy-hub-hack-nova-cyber-te-two.vercel.app/**
   https://cyper-pox-cy-hub-hack-nova-cyber-te-two.vercel.app/
   ```

#### B. Google Cloud Console:
1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Navigate to **APIs & Services → Credentials**
3. Edit your OAuth 2.0 Client ID
4. Under **Authorized JavaScript origins**, add:
   ```
   https://cyper-pox-cy-hub-hack-nova-cyber-te-two.vercel.app
   ```
5. Under **Authorized redirect URIs**, ensure you have:
   ```
   https://YOUR-PROJECT-ID.supabase.co/auth/v1/callback
   ```
   (Get exact URL from Supabase → Authentication → Providers → Google)

### 2. Update Frontend Environment Variables

#### For Vercel Deployment:
1. Go to **Vercel Dashboard → Your Project → Settings → Environment Variables**
2. Add/Update these variables:
   ```env
   NEXT_PUBLIC_API_URL=https://cyperpox-cyhub-hacknova-cybertech-track.onrender.com
   NEXT_PUBLIC_SUPABASE_URL=your-supabase-project-url
   NEXT_PUBLIC_SUPABASE_ANON_KEY=your-supabase-anon-key
   ```

#### Local `.env.production` file:
Update `frontend/.env.production` with your actual Supabase credentials:
```env
NEXT_PUBLIC_API_URL=https://cyperpox-cyhub-hacknova-cybertech-track.onrender.com
NEXT_PUBLIC_SUPABASE_URL=https://YOUR-PROJECT.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=your-anon-key-here
```

### 3. Update Backend Environment Variables

#### For Render Deployment:
1. Go to **Render Dashboard → cyhub-backend → Environment**
2. Ensure these variables are set:
   ```env
   CORS_ORIGINS=https://cyper-pox-cy-hub-hack-nova-cyber-te-two.vercel.app
   MODEL_PATH=models/isolation_forest.pkl
   SUPABASE_URL=your-supabase-url
   SUPABASE_KEY=your-supabase-service-role-key
   ```

### 4. Deploy Changes

#### Backend (Render):
```bash
cd backend
git add .
git commit -m "Add stats endpoint for dashboard"
git push origin main
```
- Render will auto-deploy from your GitHub repo

#### Frontend (Vercel):
```bash
cd frontend
git add .
git commit -m "Update stats to fetch real data and fix OAuth redirects"
git push origin main
```
- Vercel will auto-deploy from your GitHub repo

### 5. Create Supabase Table (if not exists)

Run this SQL in **Supabase → SQL Editor**:

```sql
-- Create request_logs table
CREATE TABLE IF NOT EXISTS request_logs (
    id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ DEFAULT NOW(),
    raw_request TEXT NOT NULL,
    anomaly_score FLOAT NOT NULL,
    prediction TEXT NOT NULL
);

-- Create index for faster queries
CREATE INDEX IF NOT EXISTS idx_request_logs_timestamp ON request_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_request_logs_prediction ON request_logs(prediction);
```

---

## 🧪 Testing After Deployment

### 1. Test Google Sign-In:
- Go to: `https://cyper-pox-cy-hub-hack-nova-cyber-te-two.vercel.app/login`
- Click "Sign in with Google"
- Should redirect to Google, then back to your app (NOT localhost)

### 2. Test Stats Display:
- Go to dashboard home page
- Stats should show "0" instead of "—" if no data yet
- After analyzing requests, stats should update

### 3. Test Request Analyzer:
- Paste a sample HTTP request:
  ```
  GET /admin?id=1' OR '1'='1 HTTP/1.1
  Host: example.com
  ```
- Click "Analyze Request"
- Check if stats update immediately

### 4. Test Logs:
- Click "Load Logs" button
- Logs should appear from Supabase database

---

## 🔍 Troubleshooting

### Stats Still Show "—":
1. Check browser console for API errors
2. Verify `NEXT_PUBLIC_API_URL` is correct in Vercel
3. Test backend endpoint directly: 
   ```
   https://cyperpox-cyhub-hacknova-cybertech-track.onrender.com/stats
   ```

### Google OAuth Still Redirects to Localhost:
1. Clear browser cache and cookies
2. Wait 5-10 minutes for Google OAuth cache to clear
3. Try in incognito/private mode
4. Verify all redirect URLs are HTTPS (not HTTP)

### CORS Errors:
1. Check Render environment variable `CORS_ORIGINS`
2. Ensure it matches your Vercel domain exactly
3. Restart backend service on Render

### No Model Loaded:
1. Check Render build logs
2. Ensure `train_model.py` runs during build
3. Verify model file exists at `models/isolation_forest.pkl`

---

## 📝 Verification Commands

Test backend endpoints:
```bash
# Health check
curl https://cyperpox-cyhub-hacknova-cybertech-track.onrender.com/health

# Stats endpoint (new)
curl https://cyperpox-cyhub-hacknova-cybertech-track.onrender.com/stats

# Logs endpoint
curl https://cyperpox-cyhub-hacknova-cybertech-track.onrender.com/logs
```

---

## ✨ What's Fixed

1. ✅ **Dashboard Stats**: Now displays real data from backend
2. ✅ **Live Updates**: Stats auto-refresh every 30 seconds
3. ✅ **Google OAuth**: Instructions to fix localhost redirect
4. ✅ **Environment Setup**: Complete env variable configuration
5. ✅ **API Integration**: `/stats` endpoint for aggregated metrics

---

## 🎯 Expected Results

After deployment:
- **Total Scanned**: Shows 0 (or actual count if data exists)
- **Normal**: Shows count of benign requests
- **Suspicious**: Shows count of flagged requests
- **Model Status**: Shows "Ready" when model is loaded
- **Google Sign-In**: Redirects to production URL, not localhost
