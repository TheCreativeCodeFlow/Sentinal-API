import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import React from "react";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

const menuItems = [
  { href: "/", label: "Dashboard", key: "1" },
  { href: "/projects", label: "Projects", key: "2" },
  { href: "/api-explorer", label: "API Explorer", key: "3" },
  { href: "/security-tests", label: "Security Tests", key: "4" },
  { href: "/findings", label: "Findings", key: "5" },
  { href: "/attack-surface", label: "Attack Surface", key: "6" },
  { href: "/settings", label: "Settings", key: "7" },
];

export const metadata: Metadata = {
  title: "SentinelAPI",
  description: "API Security Testing Platform",
};

function SidebarNav() {
  return (
    <nav className="border-r border-border bg-background/80 flex shrink-0 w-64 p-2">
      {menuItems.map((item) => (
        <a
          key={item.key}
          href={item.href}
          className="flex items-center rounded-md px-3 py-2 text-sm text-muted-foreground hover:text-foreground hover:bg-accent transition-colors"
        >
          {item.label}
        </a>
      ))}
    </nav>
  );
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html
      lang="en"
      className={`${geistSans.variable} ${geistMono.variable} h-full antialiased`}
    >
      <body className="min-h-full flex flex-col bg-background text-foreground">
        <header className="border-b border-border bg-background/90 backdrop-blur-sm shadow-sm">
          <div className="max-w-[1600px] mx-auto flex items-center justify-between h-16 px-6">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-md bg-primary flex items-center justify-center">
                <svg
                  width="16"
                  height="16"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                >
                  <rect x="3" y="3" width="18" height="18" rx="2" ry="2" />
                  <line x1="3" y1="15" x2="21" y2="15" />
                  <line x1="9" y1="21" x2="15" y2="21" />
                  <line x1="15" y1="3" x2="21" y2="3" />
                </svg>
              </div>
              <span className="text-xl font-bold">SentinelAPI</span>
            </div>
            <div className="hidden md:flex items-center gap-2">
              {menuItems.map((item) => (
                <a
                  key={item.key}
                  href={item.href}
                  className="text-sm font-medium transition-colors hover:text-foreground"
                >
                  {item.label}
                </a>
              ))}
            </div>
          </div>
        </header>

        <main className="max-w-[1600px] mx-auto p-6 flex-grow">
          <SidebarNav />
          {children}
        </main>

        <footer className="border-t border-border mt-8 pt-6 text-sm text-muted-foreground">
          <div className="max-w-[1600px] mx-auto">
            <div className="flex flex-col md:flex-row justify-between items-center">
              <span>SentinelAPI 2026</span>
              <div className="flex items-center gap-4">
                <a href="#" className="hover:text-foreground transition-colors">
                  GitHub
                </a>
                <a href="#" className="hover:text-foreground transition-colors">
                  Documentation
                </a>
              </div>
            </div>
          </div>
        </footer>
      </body>
    </html>
  );
}