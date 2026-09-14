import React, { useEffect, useState } from "react";

export default function DashboardPage() {
  return (
    <div className="p-6 bg-background">
      <h1 className="text-2xl font-bold mb-6">Dashboard</h1>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        <div className="bg-card p-6 rounded-xl shadow">
          <h3 className="text-sm font-medium text-muted-foreground mb-2">Total Projects</h3>
          <p className="text-3xl font-bold">0</p>
        </div>
        <div className="bg-card p-6 rounded-xl shadow">
          <h3 className="text-sm font-medium text-muted-foreground mb-2">Total APIs</h3>
          <p className="text-3xl font-bold">0</p>
        </div>
        <div className="bg-card p-6 rounded-xl shadow">
          <h3 className="text-sm font-medium text-muted-foreground mb-2">Endpoints</h3>
          <p className="text-3xl font-bold">0</p>
        </div>
      </div>
    </div>
  );
}