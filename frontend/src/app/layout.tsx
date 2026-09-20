import type { Metadata } from "next";
import Link from "next/link";
import "./globals.css";
import React from "react";

const menuItems = [
  { href: "/", label: "Dashboard", key: "1" },
  { href: "/projects", label: "Projects", key: "2" },
  { href: "/api-explorer", label: "API Explorer", key: "3" },
  { href: "/identities", label: "Identities", key: "4" },
  { href: "/roles", label: "Roles", key: "5" },
  { href: "/resources", label: "Resources", key: "6" },
  { href: "/auth-model", label: "Auth Model", key: "7" },
  { href: "/security-tests", label: "Security Tests", key: "8" },
  { href: "/findings", label: "Findings", key: "9" },
  { href: "/attack-surface", label: "Attack Surface", key: "10" },
  { href: "/settings", label: "Settings", key: "11" },
];

export const metadata: Metadata = {
  title: "SentinelAPI",
  description: "API Security Testing Platform",
};

function SidebarNav() {
  return (
    <nav className="border border-border bg-card/40 rounded-xl flex flex-col shrink-0 w-full md:w-56 p-2 space-y-1 h-fit shadow-xs">
      {menuItems.map((item) => (
        <Link
          key={item.key}
          href={item.href}
          className="flex items-center rounded-lg px-3 py-2 text-sm font-medium text-muted-foreground hover:text-foreground hover:bg-accent transition-colors"
        >
          {item.label}
        </Link>
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
      className="h-full antialiased"
    >
      <body className="min-h-full flex flex-col bg-background text-foreground">
        <header className="border-b border-border bg-background/90 backdrop-blur-sm shadow-sm">
          <div className="max-w-[1600px] mx-auto flex items-center justify-between h-16 px-6">
            <div className="flex items-center gap-3">
              <Link href="/" className="flex items-center gap-3">
                <div className="w-8 h-8 rounded-md bg-primary flex items-center justify-center text-primary-foreground font-bold">
                  S
                </div>
                <span className="text-xl font-bold">SentinelAPI</span>
              </Link>
            </div>
            <div className="hidden lg:flex items-center gap-2">
              {menuItems.slice(0, 7).map((item) => (
                <Link
                  key={item.key}
                  href={item.href}
                  className="text-xs font-medium px-2.5 py-1.5 rounded-md text-muted-foreground hover:text-foreground hover:bg-accent transition-colors"
                >
                  {item.label}
                </Link>
              ))}
            </div>
          </div>
        </header>

        <main className="max-w-[1600px] w-full mx-auto p-6 flex-grow flex flex-col md:flex-row gap-6">
          <SidebarNav />
          <div className="flex-1 min-w-0">{children}</div>
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