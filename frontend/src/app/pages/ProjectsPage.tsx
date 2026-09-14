import React, { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";

interface Project {
  id: number;
  name: string;
  description: string | null;
  environment: string;
  authorization_status: string;
  base_url: string | null;
}

export default function ProjectsPage() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchProjects();
  }, []);

  const fetchProjects = async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/v1/projects/", {
        credentials: "include",
      });
      if (!res.ok) throw new Error("Failed to fetch projects");
      const data = await res.json();
      setProjects(data);
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
      <h1 className="text-2xl font-bold mb-6">Projects</h1>
      
      <div className="mb-4">
        <Button variant="primary" onClick={fetchProjects}>
          Refresh
        </Button>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full rounded-xl border-collapse shadow">
          <thead>
            <tr className="border-b border-border text-left text-sm font-medium text-muted-foreground">
              <th className="p-4">Name</th>
              <th className="p-4">Environment</th>
              <th className="p-4">Authorization</th>
              <th className="p-4 text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {projects.map((project) => (
              <tr key={project.id} className="border-b border-border hover:bg-accent/10">
                <td className="p-4 font-medium">{project.name}</td>
                <td className="p-4">{project.environment}</td>
                <td className="p-4">
                  <span
                    className={`px-2 py-0.5 rounded text-xs font-medium ${project.authorization_status === 'active' ? 'bg-green-100 text-green-800' : 'bg-yellow-100 text-yellow-800'}`}
                  >
                    {project.authorization_status}
                  </span>
                </td>
                <td className="p-4 text-right">
                  <Button variant="secondary" size="sm">Edit</Button>
                  <Button variant="destructive" size="sm">Delete</Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}