# Supabase Authentication Setup Guide

This guide will help you set up Supabase authentication for CyHub.

## Step 1: Create a Supabase Project

1. Go to [https://app.supabase.com](https://app.supabase.com)
2. Sign in or create a new account
3. Click "New Project"
4. Fill in your project details:
   - **Name**: CyHub (or your preferred name)
   - **Database Password**: Choose a strong password
   - **Region**: Select your preferred region
5. Click "Create new project" and wait for setup to complete

## Step 2: Get Your Project Credentials

1. Once your project is ready, go to **Settings** → **API**
2. Find these two values:
   - **Project URL** (under "Project URL")
   - **anon public** key (under "Project API keys")

## Step 3: Configure Environment Variables

1. Open `frontend/.env.local` in your project
2. Replace the placeholder values:

```env
NEXT_PUBLIC_SUPABASE_URL=https://your-project-id.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=your-anon-key-here
```

## Step 4: Enable Authentication Providers

### Email/Password Authentication (Already Enabled)
Email authentication is enabled by default in Supabase.

### Google OAuth Setup

1. In your Supabase project, go to **Authentication** → **Providers**
2. Find **Google** and click on it
3. Enable the Google provider
4. You'll need to create Google OAuth credentials:

#### Create Google OAuth Credentials:

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Go to **APIs & Services** → **Credentials**
4. Click **Create Credentials** → **OAuth client ID**
5. If prompted, configure the OAuth consent screen first:
   - User Type: External
   - Add your app name and required fields
6. For OAuth client ID:
   - Application type: **Web application**
   - Name: CyHub
   - **Authorized JavaScript origins**: Add your frontend URL
     - `http://localhost:3000` (for development)
     - Your production URL (when deployed)
   - **Authorized redirect URIs**: Add your Supabase callback URL
     - Copy the "Callback URL" from Supabase Google provider settings
     - It will look like: `https://your-project-id.supabase.co/auth/v1/callback`
7. Click **Create**
8. Copy the **Client ID** and **Client Secret**

#### Add Google Credentials to Supabase:

1. Back in Supabase, paste the **Client ID** and **Client Secret** into the Google provider settings
2. Click **Save**

## Step 5: Test Authentication

1. Start your development server:
   ```bash
   cd frontend
   npm run dev
   ```

2. Navigate to `http://localhost:3000/login`

3. Try both authentication methods:
   - **Email/Password**: Create an account and sign in
   - **Google**: Click "Sign in with Google" and authenticate

## Step 6: Configure Redirect URLs (Production)

When you deploy to production, add your production URL to:

1. **Supabase**: 
   - Go to **Authentication** → **URL Configuration**
   - Add your production URL to **Site URL**
   - Add redirect URLs if needed

2. **Google Cloud Console**:
   - Update your OAuth client's authorized origins and redirect URIs to include your production domain

## Troubleshooting

### "Invalid API key" Error
- Double-check that you copied the correct **anon public** key (not the service_role key)
- Ensure there are no extra spaces in your `.env.local` file

### Google OAuth Not Working
- Verify your redirect URI in Google OAuth settings matches exactly what Supabase provides
- Make sure the Google provider is enabled in Supabase
- Check that your Google OAuth consent screen is configured

### Email Confirmation Required
- By default, Supabase requires email confirmation for new signups
- To disable this (for testing), go to **Authentication** → **Settings** and toggle "Enable email confirmations"

## Security Notes

- Never commit your `.env.local` file to version control
- Keep your Supabase keys secure
- Use the `anon` key for client-side code (it's designed for public use with Row Level Security)
- Never expose your `service_role` key in client-side code

## Additional Resources

- [Supabase Auth Documentation](https://supabase.com/docs/guides/auth)
- [Google OAuth Setup Guide](https://supabase.com/docs/guides/auth/social-login/auth-google)
- [Next.js with Supabase](https://supabase.com/docs/guides/getting-started/tutorials/with-nextjs)
