# 🚀 CyHub Deployment Environment Variables Guide

Complete environment variable configuration for both backend and frontend when hosted.

---

## 🔧 Backend Environment Variables (Render/Railway/etc.)

### Required Variables

```bash
# ── CRITICAL: CORS Configuration ──
# Add your deployed frontend URL(s) - comma separated
CORS_ORIGINS=https://your-frontend.vercel.app,https://cyhub.yourdomain.com

# ── Server Port (usually auto-set by hosting platform) ──
PORT=8000

# ── Model Path ──
MODEL_PATH=models/isolation_forest.pkl

# ── HuggingFace Model Endpoints ──
HF_MODEL1_URL=https://bhavyasoni21-model1.hf.space/predict
HF_MODEL1_TIMEOUT=8.0

HF_MODEL2_URL=https://bhavyasoni21-model2.hf.space/predict
HF_MODEL2_TIMEOUT=8.0

HF_MODEL3_URL=https://bhavyasoni21-model3.hf.space/predict
HF_MODEL3_TIMEOUT=8.0

HF_MODEL4_URL=https://bhavyasoni21-model4.hf.space/predict
HF_MODEL4_TIMEOUT=8.0
```

### Optional Variables

```bash
# ── MongoDB (Optional - Falls back to disk storage if not set) ──
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/?retryWrites=true&w=majority
MONGODB_DB=cyhub

# ── HuggingFace API Token (if using private spaces) ──
HF_API_TOKEN=hf_xxxxxxxxxxxxxxxxxxxx

# ── Threat Intelligence ──
LOAD_BLOCKLISTS_ON_STARTUP=true
WHITELIST_DOMAINS=example.com,trusted-site.com
DOMAIN_CACHE_TTL=2592000

# ── Logging ──
LOGS_FILE=data/request_logs.json

# ── DNS Configuration ──
DNS_VALIDATION_TIMEOUT=5.0
```

---

## 🎨 Frontend Environment Variables (Vercel/Netlify/etc.)

### Required Variables

```bash
# ── Backend API URL (CRITICAL!) ──
# Point to your deployed backend
NEXT_PUBLIC_API_URL=https://your-backend.onrender.com

# ── Firebase Authentication ──
NEXT_PUBLIC_FIREBASE_API_KEY=AIzaSyXxxxxxxxxxxxxxxxxxxxxx
NEXT_PUBLIC_FIREBASE_AUTH_DOMAIN=your-project.firebaseapp.com
NEXT_PUBLIC_FIREBASE_PROJECT_ID=your-project-id
NEXT_PUBLIC_FIREBASE_STORAGE_BUCKET=your-project.appspot.com
NEXT_PUBLIC_FIREBASE_MESSAGING_SENDER_ID=123456789012
NEXT_PUBLIC_FIREBASE_APP_ID=1:123456789012:web:abcdefghijklmnop
```

### Optional Variables

```bash
# ── Node Environment ──
NODE_ENV=production

# ── Next.js Configuration ──
NEXT_PUBLIC_APP_NAME=CyHub
NEXT_PUBLIC_VERSION=1.0.0
```

---

## 📋 Platform-Specific Setup Instructions

### Backend Deployment (Render)

1. **Go to Render Dashboard** → New → Web Service
2. Connect your GitHub repository
3. **Build Command:** `cd backend && pip install -r requirements.txt`
4. **Start Command:** `cd backend && uvicorn main:app --host 0.0.0.0 --port $PORT`
5. **Environment Variables:** Add all backend variables from above
   - ⚠️ **CRITICAL:** Set `CORS_ORIGINS` to your frontend URL
   - Example: `https://cyhub.vercel.app`

### Frontend Deployment (Vercel)

1. **Go to Vercel Dashboard** → New Project
2. Import your GitHub repository
3. **Framework Preset:** Next.js
4. **Root Directory:** `frontend`
5. **Build Command:** `npm run build` (auto-detected)
6. **Environment Variables:** Add all frontend variables
   - ⚠️ **CRITICAL:** Set `NEXT_PUBLIC_API_URL` to your backend URL
   - Example: `https://cyhub-backend.onrender.com`

---

## 🔍 Connection Issues Checklist

### ❌ Backend Not Connecting to Frontend?

**Check these in order:**

1. **CORS Configuration**
   ```bash
   # Backend .env - MUST include frontend URL
   CORS_ORIGINS=https://your-frontend.vercel.app
   ```

2. **Frontend API URL**
   ```bash
   # Frontend .env - MUST point to backend
   NEXT_PUBLIC_API_URL=https://your-backend.onrender.com
   ```

3. **Health Check**
   - Visit: `https://your-backend.onrender.com/health`
   - Should return: `{"status":"healthy",...}`

4. **Browser Console**
   - Open DevTools → Console
   - Look for CORS errors like:
     ```
     Access to fetch at 'https://backend...' from origin 'https://frontend...'
     has been blocked by CORS policy
     ```

5. **Network Tab**
   - Check if requests are going to the correct backend URL
   - Verify response status codes (200 = OK, 404 = wrong URL, 500 = server error)

### Common Mistakes

❌ **WRONG:** `CORS_ORIGINS=http://localhost:3000` (in production)
✅ **RIGHT:** `CORS_ORIGINS=https://your-frontend.vercel.app`

❌ **WRONG:** `NEXT_PUBLIC_API_URL=http://localhost:8000` (in production)
✅ **RIGHT:** `NEXT_PUBLIC_API_URL=https://your-backend.onrender.com`

❌ **WRONG:** Forgetting `https://` in URLs
✅ **RIGHT:** Always include protocol: `https://...`

---

## 🧪 Testing Deployment

### 1. Test Backend Independently
```bash
# Check root endpoint
curl https://your-backend.onrender.com/

# Expected response:
{
  "service": "CyHub API",
  "status": "online",
  "version": "1.0.0",
  ...
}

# Check health
curl https://your-backend.onrender.com/health

# Expected response:
{
  "status": "healthy",
  "model_loaded": true,
  "version": "1.0.0"
}
```

### 2. Test Frontend API Connection
```bash
# Open browser console on your deployed frontend
# Run this command:
fetch('/api/health')
  .then(r => r.json())
  .then(d => console.log(d))

# Should log the health response
```

### 3. Check CORS Headers
```bash
# From your frontend domain, check OPTIONS request
curl -X OPTIONS https://your-backend.onrender.com/health \
  -H "Origin: https://your-frontend.vercel.app" \
  -H "Access-Control-Request-Method: GET" \
  -v

# Look for these headers in response:
# Access-Control-Allow-Origin: https://your-frontend.vercel.app
# Access-Control-Allow-Methods: GET, POST, OPTIONS
```

---

## 📝 Quick Copy Templates

### Backend .env (Render)
```bash
CORS_ORIGINS=https://YOUR-FRONTEND.vercel.app
MODEL_PATH=models/isolation_forest.pkl
HF_MODEL1_URL=https://bhavyasoni21-model1.hf.space/predict
HF_MODEL2_URL=https://bhavyasoni21-model2.hf.space/predict
HF_MODEL3_URL=https://bhavyasoni21-model3.hf.space/predict
HF_MODEL4_URL=https://bhavyasoni21-model4.hf.space/predict
HF_MODEL1_TIMEOUT=8.0
HF_MODEL2_TIMEOUT=8.0
HF_MODEL3_TIMEOUT=8.0
HF_MODEL4_TIMEOUT=8.0
LOAD_BLOCKLISTS_ON_STARTUP=false
LOGS_FILE=data/request_logs.json
```

### Frontend .env (Vercel)
```bash
NEXT_PUBLIC_API_URL=https://YOUR-BACKEND.onrender.com
NEXT_PUBLIC_FIREBASE_API_KEY=YOUR_FIREBASE_API_KEY
NEXT_PUBLIC_FIREBASE_AUTH_DOMAIN=YOUR_PROJECT.firebaseapp.com
NEXT_PUBLIC_FIREBASE_PROJECT_ID=YOUR_PROJECT_ID
NEXT_PUBLIC_FIREBASE_STORAGE_BUCKET=YOUR_PROJECT.appspot.com
NEXT_PUBLIC_FIREBASE_MESSAGING_SENDER_ID=YOUR_SENDER_ID
NEXT_PUBLIC_FIREBASE_APP_ID=YOUR_APP_ID
```

---

## 🆘 Still Not Working?

1. **Check Backend Logs:**
   - Render: Dashboard → Logs tab
   - Look for CORS warnings or startup errors

2. **Check Frontend Build Logs:**
   - Vercel: Deployment → Build Logs
   - Ensure environment variables are being read

3. **Verify Environment Variables:**
   - Backend: Check Render Dashboard → Environment
   - Frontend: Check Vercel → Settings → Environment Variables

4. **Redeploy:**
   - After changing environment variables, trigger a new deployment
   - Vercel: Deployments → Redeploy
   - Render: Manual Deploy → Deploy latest commit

5. **Check Browser DevTools:**
   - Network tab: See actual request URLs
   - Console tab: See JavaScript errors
   - Application tab: Check if env vars are loaded

---

## 📚 Additional Resources

- [FastAPI CORS Documentation](https://fastapi.tiangolo.com/tutorial/cors/)
- [Next.js Environment Variables](https://nextjs.org/docs/basic-features/environment-variables)
- [Render Environment Variables](https://render.com/docs/configure-environment-variables)
- [Vercel Environment Variables](https://vercel.com/docs/concepts/projects/environment-variables)

---

**Note:** After updating any environment variable, always redeploy your application for changes to take effect!
