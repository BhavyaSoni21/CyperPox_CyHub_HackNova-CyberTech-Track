"use client";

import Link from 'next/link';
import { Shield, LogOut, User } from 'lucide-react';
import { useAuth } from '@/contexts/AuthContext';

export function Navigation() {
  const { user, signOut } = useAuth();

  return (
    <header className="border-b border-border backdrop-blur-xl bg-background/50 sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
        <div className="flex items-center justify-between">
          <Link href="/" className="flex items-center gap-2 group">
            <div className="w-10 h-10 bg-cyan-500/10 rounded-xl flex items-center justify-center group-hover:bg-cyan-500/20 transition">
              <Shield className="w-6 h-6 text-cyan-400" />
            </div>
            <span className="text-xl font-bold text-foreground">CyHub</span>
          </Link>

          <nav className="flex items-center gap-6">
            <Link href="/" className="text-muted-foreground hover:text-foreground transition text-sm font-medium">
              Dashboard
            </Link>
            <Link href="/about" className="text-muted-foreground hover:text-foreground transition text-sm font-medium">
              About
            </Link>
            
            {user ? (
              <div className="flex items-center gap-3">
                <div className="flex items-center gap-2 px-3 py-1.5 bg-slate-800 rounded-lg border border-slate-700">
                  <User className="w-4 h-4 text-cyan-400" />
                  <span className="text-sm text-slate-300">{user.email?.split('@')[0]}</span>
                </div>
                <button
                  onClick={signOut}
                  className="flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded-lg transition border border-slate-700 text-sm font-medium"
                >
                  <LogOut className="w-4 h-4" />
                  Logout
                </button>
              </div>
            ) : (
              <Link 
                href="/login"
                className="px-4 py-2 bg-cyan-500 hover:bg-cyan-600 text-white rounded-lg transition text-sm font-medium"
              >
                Login
              </Link>
            )}
          </nav>
        </div>
      </div>
    </header>
  );
}
