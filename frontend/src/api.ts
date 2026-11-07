import type { Health, HistoryItem, Run, Scenario } from "./types";

async function read<T>(path: string): Promise<T> {
  const response = await fetch(path);
  if (!response.ok) {
    throw new Error(`${path} returned ${response.status}`);
  }
  return response.json() as Promise<T>;
}

export function getHealth(): Promise<Health> {
  return read<Health>("/api/health");
}

export function getScenarios(): Promise<{ scenarios: Scenario[]; disclaimer: string }> {
  return read("/api/demo/scenarios");
}

export function getRun(runId: string): Promise<Run> {
  return read<Run>(`/api/verification/${runId}`);
}

export function getHistory(): Promise<{ runs: HistoryItem[] }> {
  return read("/api/history");
}

export async function downloadReport(runId: string): Promise<void> {
  const response = await fetch(`/api/verification/${runId}/report`);
  if (!response.ok) {
    throw new Error(`Report download failed (${response.status})`);
  }
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `medguard-${runId}.json`;
  link.click();
  URL.revokeObjectURL(url);
}

export async function rerunVerification(runId: string): Promise<Run> {
  const response = await fetch(`/api/verification/${runId}/rerun`, { method: "POST" });
  if (!response.ok) {
    throw new Error(`Rerun failed (${response.status})`);
  }
  return response.json() as Promise<Run>;
}

export async function verifyCode(code: string, scenarioId: string | null): Promise<Run> {
  const response = await fetch("/api/verify", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ code, scenario_id: scenarioId }),
  });
  if (!response.ok) {
    let detail = `Verification request failed (${response.status})`;
    try {
      const body = await response.json();
      if (typeof body.detail === "string") {
        detail = body.detail;
      }
    } catch {
      // Keep the status-based message when the body is not JSON.
    }
    throw new Error(detail);
  }
  return response.json() as Promise<Run>;
}
