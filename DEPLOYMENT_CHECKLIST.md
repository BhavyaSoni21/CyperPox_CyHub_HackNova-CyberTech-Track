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

### 1. Configure Firebase Authentication

1. In [Firebase Console](https://console.firebase.google.com), go to **Authentication → Sign-in method**
2. Enable **Email/Password** and **Google**
3. Go to **Authentication → Settings → Authorized domains** and add:
   ```
   cyper-pox-cy-hub-hack-nova-cyber-te-two.vercel.app
   ```

### 2. Update Frontend Environment Variables

#### For Vercel Deployment:
1. Go to **Vercel Dashboard → Your Project → Settings → Environment Variables**
2. Add/Update these variables:
   ```env
   NEXT_PUBLIC_API_URL=https://cyperpox-cyhub-hacknova-cybertech-track.onrender.com
   NEXT_PUBLIC_FIREBASE_API_KEY=your-firebase-api-key
   NEXT_PUBLIC_FIREBASE_AUTH_DOMAIN=your-project.firebaseapp.com
   NEXT_PUBLIC_FIREBASE_PROJECT_ID=your-project-id
   NEXT_PUBLIC_FIREBASE_STORAGE_BUCKET=your-project.appspot.com
   NEXT_PUBLIC_FIREBASE_MESSAGING_SENDER_ID=your-sender-id
   NEXT_PUBLIC_FIREBASE_APP_ID=your-app-id
   ```

#### Local `.env.local` file:
Create `frontend/.env.local` with your Firebase credentials (see [Firebase_Setup.md](Firebase_Setup.md)).

### 3. Update Backend Environment Variables

#### For Render Deployment:
1. Go to **Render Dashboard → cyhub-backend → Environment**
2. Ensure these variables are set:
   ```env
   CORS_ORIGINS=https://cyper-pox-cy-hub-hack-nova-cyber-te-two.vercel.app
   MODEL_PATH=models/isolation_forest.pkl
   MONGODB_URI=mongodb+srv://<user>:<pass>@cluster.mongodb.net/?retryWrites=true&w=majority
   MONGODB_DB=cyhub
   ```

### 4. Deploy Changes

#### Backend (Render):
```bash
cd backend
git add .
git commit -m "Migrate from Supabase to MongoDB"
git push origin main
```
- Render will auto-deploy from your GitHub repo

#### Frontend (Vercel):
```bash
cd frontend
git add .
git commit -m "Migrate from Supabase to Firebase Auth"
git push origin main
```
- Vercel will auto-deploy from your GitHub repo

### 5. MongoDB — Collection Setup

The `request_logs` collection is created automatically by the backend on first insert.
No manual setup required. Ensure your `MONGODB_URI` points to an Atlas cluster (or any MongoDB instance) and the database name matches `MONGODB_DB` (default: `cyhub`).

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
- Logs should appear from MongoDB

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
