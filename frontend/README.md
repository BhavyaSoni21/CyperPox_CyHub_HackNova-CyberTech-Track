# CyHub Frontend

Next.js 16 frontend for the CyHub AI-driven web anomaly detection system.

## Stack

- **Next.js 16** + **React 19** + **TypeScript**
- **Tailwind CSS** for styling
- **Firebase** for authentication (Google OAuth, Email/Password, Phone OTP)
- **Spline** for 3D hero visualization
- **shadcn/ui** component primitives
- **Deployed on Vercel**

## Development

```bash
npm install
npm run dev       # http://localhost:3000
npm run build     # production build
npm run lint      # ESLint check
```

## Environment Variables

Create `frontend/.env.local`:

```env
NEXT_PUBLIC_API_URL=http://localhost:8000

NEXT_PUBLIC_FIREBASE_API_KEY=your-key
NEXT_PUBLIC_FIREBASE_AUTH_DOMAIN=your-project.firebaseapp.com
NEXT_PUBLIC_FIREBASE_PROJECT_ID=your-project-id
NEXT_PUBLIC_FIREBASE_STORAGE_BUCKET=your-project.appspot.com
NEXT_PUBLIC_FIREBASE_MESSAGING_SENDER_ID=your-sender-id
NEXT_PUBLIC_FIREBASE_APP_ID=your-app-id
```

## Key Pages

| Route | Description |
|---|---|
| `/` | Dashboard — stats, request analyzer, batch upload, logs |
| `/login` | Firebase auth (email, Google, phone OTP) |
| `/about` | System explainer — pipeline, models, tech stack |

## Key Components

| Component | Path |
|---|---|
| Request Analyzer | `src/components/dashboard/request-analyzer.tsx` |
| Batch CSV Upload | `src/components/dashboard/batch-upload.tsx` |
| Stats Overview | `src/components/dashboard/stats-overview.tsx` |
| Request Logs | `src/components/dashboard/request-logs.tsx` |
| Hero Section | `src/components/dashboard/hero-section.tsx` |
| Footer | `src/components/footer.tsx` |
| Navigation | `src/components/navigation.tsx` |

## API Integration

All backend calls go through `src/lib/api.ts`. The primary endpoint is `POST /analyze` which accepts a URL, raw HTTP request, or both and returns a `ComprehensiveThreatReport` (typed in `src/lib/types.ts`).

## Firebase Setup

1. Create a Firebase project at [console.firebase.google.com](https://console.firebase.google.com)
2. Enable **Email/Password**, **Google**, and **Phone** sign-in providers
3. Copy credentials into `.env.local`
4. For production: add your Vercel domain to Firebase > Authentication > Authorized Domains

---

© 2024 CyHub × CyperPox — All rights reserved.
