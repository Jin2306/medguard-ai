export type Stage = {
  id: string;
  label: string;
  status: string;
  detail: string;
};

export type Finding = {
  policy_id: string;
  title: string;
  severity: string;
  source: string;
  confirmed: boolean;
  description: string;
  recommendation: string;
  line: number | null;
};

export type TestResult = {
  id: string;
  policy_id: string;
  title: string;
  mandatory: boolean;
  outcome: string;
  detail: string;
  layer?: string;
  counts_as_evidence?: boolean;
};

export type MemoryHit = {
  pattern_id?: string;
  vulnerability_type?: string;
  severity?: string;
  failure_pattern?: string;
  successful_test_strategy?: string;
  recommended_fix?: string;
  verified?: boolean;
  evidence_against_new_changes?: boolean;
  outcome?: string;
  strategy?: string;
};

export type Run = {
  run_id: string;
  status: string;
  created_at: string;
  scenario_id: string | null;
  code: string;
  code_sha256: string;
  policy_version: string;
  decision: string | null;
  decision_reason: string;
  ai: {
    mode: string;
    advisory_only: boolean;
    configured: boolean;
    model: string | null;
    risk_level: string;
    recommendation: string | null;
    disclaimer: string;
    error: string | null;
    vulnerabilities: { type: string; severity: string; description: string; recommendation: string }[];
  };
  stages: Stage[];
  findings: Finding[];
  advisory_findings: Finding[];
  generated_tests: string;
  test_results: TestResult[];
  memory_retrieval?: {
    mode?: string;
    label?: string;
    vector_search?: string;
    disclaimer?: string;
    hits?: MemoryHit[];
  };
  adversarial?: {
    origin?: string;
    label?: string;
    proposal_mode?: string;
    rejected?: { reason?: string; name?: string }[];
  };
  reproducibility?: string;
  rerun_of?: string | null;
  sandbox: {
    status?: string;
    reason?: string;
    isolation?: Record<string, string | number | boolean>;
  };
  storage_backend: string;
  storage_label: string;
  disclaimer: string;
  related_memory: MemoryHit[];
};

export type Scenario = {
  id: string;
  title: string;
  filename: string;
  expected_decision: string;
  summary: string;
  code: string;
  requirements: {
    endpoint: string;
    summary: string;
    expected_authorization: string[];
  };
  synthetic_patients: {
    notice: string;
    patients: { patient_id: string; name: string; clinic_id: string }[];
  };
};

export type Health = {
  status: string;
  policy_version: string;
  disclaimer: string;
  meta_ai: { mode: string; configured: boolean; label: string; model: string | null };
  mongodb: {
    backend: string;
    label: string;
    atlas: boolean;
    error: string | null;
    retrieval_mode?: string;
    retrieval_label?: string;
    vector_search?: string;
  };
  semgrep: { available: boolean; status: string; detail: string };
  sandbox: {
    available: boolean;
    docker: { detail: string; image_ready: boolean };
    isolation: Record<string, string | number | boolean>;
  };
};

export type HistoryItem = {
  run_id: string;
  created_at: string;
  scenario_id: string | null;
  decision: string | null;
  status: string;
  code_sha256: string;
  storage_backend: string;
  storage_label: string;
};
