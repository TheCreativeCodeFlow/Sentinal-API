import React, { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";

interface API {
  id: number;
  name: string;
  description: string | null;
  status: string;
  version: string | null;
  endpoints?: Array<{
    id: number;
    method: string;
    path: string;
    tags?: string[];
  }>;
}

export default function APIExplorerPage() {
  const [apis, setApis] = useState<API[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchApis();
  }, []);

  const fetchApis = async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/v1/projects/", {
        credentials: "include",
      });
      if (!res.ok) throw new Error("Failed to fetch APIs");
      const data = await res.json();
      setApis(data);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  if (loading) return <div className="p-6">Loading...</div>;
  if (error) return <div className="p-6 text-error">{error}</div>;

  return (
    <div className="p-6 bg-background">
      <h1 className="text-2xl font-bold mb-6">API Explorer</h1>

      <Card>
        <CardHeader>
          <CardTitle>Imported APIs</CardTitle>
        </CardHeader>
        <CardContent>
          {apis.length === 0 ? (
            <p className="text-muted-foreground">No APIs imported yet. Upload an OpenAPI specification to get started.</p>
          ) : (
            <div className="space-y-4">
              {apis.map((api) => (
                <div key={api.id} className="bg-card p-6 rounded-xl shadow">
                  <div className="flex justify-between items-start mb-3">
                    <h3 className="text-lg font-medium">{api.name}</h3>
                    <span
                      className="text-xs font-medium capitalize"
                    >
                      {api.status}
                    </span>
                  </div>
                  <p className="text-sm text-muted-foreground mb-4">{api.description || "No description"}</p>
                  
                  <div className="space-y-3">
                    <h4 className="text-sm font-medium mb-2">Endpoints</h4>
                    <div className="grid grid-cols-2 gap-2">
                      {api.endpoints?.map((ep: any) => (
                        <div
                          key={ep.id}
                          className="p-3 rounded bg-muted/50 text-xs"
                        >
                          <span className="font-medium">{ep.method} {ep.path}</span>
                          <span className="text-muted-foreground opacity-75">{ep.tags?.join(", ") || "No tags"}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Upload OpenAPI Specification</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground mb-4">
            Upload an OpenAPI 3.x JSON or YAML file to import APIs and endpoints.
          </p>
          <Input
            type="file"
            accept=".json,.yaml,.yml"
            onChange={(e: React.ChangeEvent<HTMLInputElement>) => {
              const file = e.target.files?.[0];
              if (!file) return;
              const reader = new FileReader();
              reader.onload = async (e: any) => {
                const content = e.target.result as string;
                try {
                  const res = await fetch("/api/v1/1/ingest", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ spec_content: content }),
                    credentials: "include",
                  });
                  if (!res.ok) {
                    const err = await res.json();
                    throw new Error(err.detail || "Upload failed");
                  }
                  alert("Specification ingested successfully!");
                  fetchApis();
                } catch (e: any) {
                  alert("Error: " + e.message);
                }
              };
              reader.readAsText(file);
            }}
          />
        </CardContent>
      </Card>
    </div>
  );
}