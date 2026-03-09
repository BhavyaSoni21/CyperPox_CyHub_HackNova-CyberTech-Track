# Firebase Authentication Setup Guide

This guide covers setting up Firebase Authentication for CyHub.

## Step 1: Create a Firebase Project

1. Go to [https://console.firebase.google.com](https://console.firebase.google.com)
2. Click **Add project** and follow the prompts
3. Once created, click the **</>** (Web) icon to register a web app
4. Copy the `firebaseConfig` object shown — you'll need these values

## Step 2: Configure Environment Variables

Create a `frontend/.env.local` file with your Firebase credentials:

```env
NEXT_PUBLIC_FIREBASE_API_KEY=your-api-key
NEXT_PUBLIC_FIREBASE_AUTH_DOMAIN=your-project.firebaseapp.com
NEXT_PUBLIC_FIREBASE_PROJECT_ID=your-project-id
NEXT_PUBLIC_FIREBASE_STORAGE_BUCKET=your-project.appspot.com
NEXT_PUBLIC_FIREBASE_MESSAGING_SENDER_ID=your-sender-id
NEXT_PUBLIC_FIREBASE_APP_ID=your-app-id
```

## Step 3: Enable Authentication Providers

1. In your Firebase project, go to **Authentication → Sign-in method**
2. Enable **Email/Password**
3. Enable **Google** (click the row, toggle on, add a support email, and save)

## Step 4: Authorize Your Domain (Production)

1. Go to **Authentication → Settings → Authorized domains**
2. Add your Vercel production domain (e.g., `cyper-pox-cy-hub-hack-nova-cyber-te-two.vercel.app`)

## Step 5: Test Authentication

1. Start the dev server:
   ```bash
   cd frontend
   npm run dev
   ```
2. Navigate to `http://localhost:3000/login`
3. Test both Email/Password and Google sign-in

## Troubleshooting

- **`auth/api-key-not-valid`** — Double-check your `NEXT_PUBLIC_FIREBASE_API_KEY` value
- **`auth/unauthorized-domain`** — Add the domain to Firebase authorized domains
- **Google popup blocked** — Ensure the browser allows popups from localhost or your domain

## Security Notes

- Never commit your `.env.local` file to version control
- Keep your Firebase credentials out of public repositories (they are safe to expose client-side, but prefer `.env.local`)

## Additional Resources

- [Firebase Auth Documentation](https://firebase.google.com/docs/auth)
- [Next.js with Firebase](https://firebase.google.com/docs/web/setup)
