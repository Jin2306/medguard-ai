import { useEffect, useMemo, useRef, useState } from "react";
import { downloadReport, getHealth, getHistory, getRun, getScenarios, rerunVerification, verifyCode } from "./api";
import type { Finding, Health, HistoryItem, Run, Scenario } from "./types";

const PIPELINE = [
  ["ingest", "Code submission"],
  ["policies", "Policy checks"],
  ["static_analysis", "Static analysis"],
  ["meta_ai", "Meta AI review"],
  ["test_generation", "Adversarial tests"],
  ["sandbox", "Sandbox execution"],
  ["persist", "Security evidence"],
  ["decision", "Final decision"],
];

const EMPTY_STAGES = [
  ["ingest", "Ingest code"],
  ["policies", "Load security policies"],
  ["static_analysis", "Static analysis"],
  ["meta_ai", "Independent model review"],
  ["test_generation", "Generate security tests"],
  ["sandbox", "Sandbox execution"],
  ["decision", "Verification decision"],
  ["persist", "Store evidence"],
];

export function App() {
  const [health, setHealth] = useState<Health | null>(null);
  const [healthError, setHealthError] = useState("");
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [selectedId, setSelectedId] = useState<string>("");
  const [code, setCode] = useState("");
  const [run, setRun] = useState<Run | null>(null);
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const selected = scenarios.find((item) => item.id === selectedId) ?? null;
  const visibleRunId = useRef<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    Promise.all([getHealth(), getScenarios(), getHistory()])
      .then(([healthBody, scenarioBody, historyBody]) => {
        if (cancelled) return;
        setHealth(healthBody);
        setScenarios(scenarioBody.scenarios);
        setHistory(historyBody.runs);
        const first = scenarioBody.scenarios[0];
        if (first) {
          setSelectedId(first.id);
          setCode(first.code);
        }
      })
      .catch((reason: unknown) => {
        if (!cancelled) {
          setHealthError(reason instanceof Error ? reason.message : "Backend is not reachable.");
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    visibleRunId.current = run?.run_id ?? null;
  }, [run?.run_id]);

  useEffect(() => {
    if (!run || run.status !== "running") {
      return;
    }
    const runId = run.run_id;
    let cancelled = false;
    const timer = window.setInterval(() => {
      getRun(runId)
        .then((next) => {
          if (cancelled || visibleRunId.current !== runId) return;
          setRun(next);
          if (next.status !== "running") {
            setBusy(false);
            getHistory().then((body) => setHistory(body.runs)).catch(() => undefined);
          }
        })
        .catch((reason: unknown) => {
          if (cancelled || visibleRunId.current !== runId) return;
          setError(reason instanceof Error ? reason.message : "Lost contact with the verification run.");
          setBusy(false);
        });
    }, 700);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [run?.run_id, run?.status]);

  const unmodified = Boolean(selected && code === selected.code);
  const stages = run?.stages?.length ? run.stages : EMPTY_STAGES.map(([id, label]) => ({ id, label, status: "pending", detail: "" }));
  const confirmed = useMemo(() => (run?.findings ?? []).filter((item) => item.confirmed), [run]);
  const leads = useMemo(() => (run?.findings ?? []).filter((item) => !item.confirmed), [run]);

  async function choose(scenario: Scenario) {
    setSelectedId(scenario.id);
    setCode(scenario.code);
    setRun(null);
    setBusy(false);
    setError("");
  }

  async function onVerify() {
    setError("");
    setBusy(true);
    try {
      const started = await verifyCode(code, selected && code === selected.code ? selected.id : selectedId || null);
      setRun(started);
      if (started.status !== "running") {
        setBusy(false);
        const body = await getHistory();
        setHistory(body.runs);
      }
    } catch (reason: unknown) {
      setBusy(false);
      setError(reason instanceof Error ? reason.message : "Verification failed to start.");
    }
  }

  function loadScenario(id: string) {
    const scenario = scenarios.find((item) => item.id === id);
    if (scenario) {
      choose(scenario);
    }
  }

  async function onDownload() {
    if (!run) return;
    setError("");
    try {
      await downloadReport(run.run_id);
    } catch (reason: unknown) {
      setError(reason instanceof Error ? reason.message : "Could not download the report.");
    }
  }

  async function onRerun() {
    if (!run) return;
    setError("");
    setBusy(true);
    try {
      const started = await rerunVerification(run.run_id);
      setRun(started);
      setCode(started.code);
      if (started.status !== "running") {
        setBusy(false);
        const body = await getHistory();
        setHistory(body.runs);
      }
    } catch (reason: unknown) {
      setBusy(false);
      setError(reason instanceof Error ? reason.message : "Rerun failed to start.");
    }
  }

  async function openHistory(runId: string) {
    setError("");
    try {
      const loaded = await getRun(runId);
      setRun(loaded);
      setCode(loaded.code);
      if (loaded.scenario_id) {
        setSelectedId(loaded.scenario_id);
      }
    } catch (reason: unknown) {
      setError(reason instanceof Error ? reason.message : "Could not load that run.");
    }
  }

  return (
    <div className="page">
      <header className="top">
        <div className="brand">
          <div className="brand-mark" aria-hidden="true">MG</div>
          <div>
            <p className="eyebrow">Trust but verify</p>
            <h1>MedGuard AI</h1>
            <p className="tagline">The AI That Doesn't Trust AI.</p>
            <p className="lede">Independent security verification for medical software. Explanations are not evidence.</p>
          </div>
        </div>
        <div className="chips" aria-label="Runtime status">
          <StatusChip
            label="Meta AI"
            value={health ? (health.meta_ai.mode === "live" ? health.meta_ai.label : "DEMO MODE") : "unknown"}
            title={health?.meta_ai.label}
            tone={health?.meta_ai.mode === "live" ? "good" : "warn"}
          />
          <StatusChip
            label="Storage"
            value={health ? (health.mongodb.atlas ? "MongoDB Atlas" : "Local fallback, not Atlas") : "unknown"}
            title={health?.mongodb.label}
            tone={health?.mongodb.atlas ? "good" : "warn"}
          />
          <StatusChip
            label="Semgrep"
            value={health?.semgrep.available ? health.semgrep.detail : "Unavailable"}
            title={health?.semgrep.detail}
            tone={health?.semgrep.available ? "good" : "warn"}
          />
          <StatusChip
            label="Sandbox"
            value={health?.sandbox.available ? "Docker ready" : "Not ready"}
            title={health?.sandbox.docker.detail}
            tone={health?.sandbox.available ? "good" : "warn"}
          />
          <StatusChip
            label="Retrieval"
            value={retrievalChip(health)}
            title={health?.mongodb.retrieval_label}
            tone={health?.mongodb.vector_search === "active" ? "good" : "warn"}
          />
          <StatusChip
            label="Current run"
            value={run?.decision ?? (run?.status === "running" ? "In progress" : run ? "Decision unavailable" : "Ready")}
            title={run?.decision_reason || run?.status || "No verification submitted"}
            tone={run?.decision === "APPROVE" ? "good" : run?.decision === "BLOCK" ? "danger" : "warn"}
          />
        </div>
      </header>

      {healthError ? <p className="banner review">Backend is not reachable. Start the API, then reload this page. {healthError}</p> : null}
      {health ? <p className="disclaimer">{health.disclaimer}</p> : null}

      <section className="panel demo-bar">
        <div>
          <p className="eyebrow">Live demo</p>
          <h2>Compare a vulnerable change with its corrected version</h2>
          <p className="note">Each verification uses the selected source and reports only checks returned by the backend.</p>
        </div>
        <div className="demo-actions">
          <button type="button" onClick={() => loadScenario("vulnerable-cross-clinic")}>Load vulnerable API</button>
          <button type="button" className="button-primary" onClick={onVerify} disabled={busy || code.trim().length === 0}>
            {busy ? "Verification running…" : "Verify selected code"}
          </button>
          <button type="button" onClick={() => loadScenario("corrected-clinic-scope")}>Load corrected API</button>
        </div>
      </section>

      <main className="layout">
        <section className="panel code-panel">
          <div className="section-heading">
            <div>
              <p className="eyebrow">01 / Source</p>
              <h2>Submitted change</h2>
            </div>
            <span className="synthetic-label">Synthetic data only</span>
          </div>
          <div className="scenarios" role="group" aria-label="Demo scenarios">
            {scenarios.map((scenario) => (
              <button
                key={scenario.id}
                className={scenario.id === selectedId ? "scenario active" : "scenario"}
                onClick={() => choose(scenario)}
                type="button"
                aria-pressed={scenario.id === selectedId}
              >
                <span className="scenario-copy">
                  <strong>{scenario.title}</strong>
                  <small>{scenario.filename}</small>
                </span>
                <span className={`fixture ${scenario.expected_decision.toLowerCase()}`}>Fixture: {scenario.expected_decision}</span>
              </button>
            ))}
          </div>
          {selected ? (
            <div className="brief">
              <p>{selected.summary}</p>
              <p className="endpoint">{selected.requirements.endpoint}. {selected.requirements.summary}</p>
              <table>
                <caption>{selected.synthetic_patients.notice}</caption>
                <thead>
                  <tr>
                    <th>Patient</th>
                    <th>Id</th>
                    <th>Clinic</th>
                  </tr>
                </thead>
                <tbody>
                  {selected.synthetic_patients.patients.map((patient) => (
                    <tr key={patient.patient_id}>
                      <td>{patient.name}</td>
                      <td>{patient.patient_id}</td>
                      <td>{patient.clinic_id}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <ul>
                {selected.requirements.expected_authorization.map((rule) => (
                  <li key={rule}>{rule}</li>
                ))}
              </ul>
            </div>
          ) : null}
          <label className="code-label" htmlFor="code">
            <span>Python source</span>
            <span className="code-state">{unmodified ? "Example unchanged" : "Local edits"}</span>
          </label>
          <CodeViewer value={code} onChange={setCode} />
          <button className="verify" type="button" onClick={onVerify} disabled={busy || code.trim().length === 0}>
            {busy ? "Verifying…" : "Verify Code"}
          </button>
          {error ? <p className="form-error">{error}</p> : null}
        </section>

        <section className="panel results-panel">
          <div className="section-heading">
            <div>
              <p className="eyebrow">02 / Independent checks</p>
              <h2>Verification pipeline</h2>
            </div>
            {run ? <span className="run-id">RUN {run.run_id.slice(0, 8)}</span> : null}
          </div>
          <Decision run={run} expected={unmodified ? selected?.expected_decision ?? null : null} />
          <ol className="pipeline" aria-label="Verification pipeline" aria-live="polite">
            {PIPELINE.map(([id, label], index) => {
              const stage = stages.find((item) => item.id === id);
              const status = stage?.status ?? "pending";
              return (
                <li key={id} className={`pipe ${status}`}>
                  <span className="pipe-index">{status === "completed" ? "✓" : index + 1}</span>
                  <strong>{label}</strong>
                  <em>{status === "pending" ? "Waiting" : status}</em>
                  {stage?.detail ? <small>{stage.detail}</small> : null}
                </li>
              );
            })}
          </ol>
          <p className="note">
            {stages.filter((stage) => stage.status === "completed").length} of {stages.length} stages complete.
          </p>
          <ol className="stages">
            {stages.map((stage, index) => (
              <li key={stage.id} className={`stage ${stage.status}`}>
                <span className="index">{index + 1}</span>
                <div>
                  <strong>{stage.label}</strong>
                  <em>{stage.status}</em>
                  {stage.detail ? <p>{stage.detail}</p> : null}
                </div>
              </li>
            ))}
          </ol>

          {run?.decision ? (
            <div className="demo-actions">
              <button type="button" onClick={onDownload}>Download JSON report</button>
              <button type="button" onClick={onRerun} disabled={busy}>Rerun this code and policy</button>
            </div>
          ) : null}
          {run?.reproducibility ? <p className="note">{run.reproducibility}</p> : null}
          {run?.rerun_of ? <p className="note">Rerun of {run.rerun_of}. The same source and policy version were submitted again. Model output is not guaranteed to match the previous run.</p> : null}

          {run?.ai ? (
            <div className="advisory">
              <h3>Model advisory, not proof</h3>
              <p>
                {run.ai.mode === "demo" ? "DEMO MODE. " : run.ai.mode === "live" ? `Model ${run.ai.model}. ` : "Model call failed. "}
                Advisory recommendation: <strong>{run.ai.recommendation ?? "pending"}</strong>
                {run.ai.risk_level ? ` · risk ${run.ai.risk_level}` : ""}
              </p>
              <p>{run.ai.disclaimer}</p>
              {run.ai.error ? <p className="form-error">{run.ai.error}</p> : null}
              {run.decision && run.ai.recommendation && run.decision !== run.ai.recommendation ? (
                <p className="diverge">The verification decision does not follow the model advisory.</p>
              ) : null}
            </div>
          ) : null}

          {run ? (
            <>
              <h3 className="subsection-title">Confirmed security findings</h3>
              <FindingList items={confirmed} empty="No confirmed static findings." />
              <h3 className="subsection-title">AI and heuristic leads</h3>
              <FindingList items={leads} empty="No heuristic leads." />
              <h3 className="subsection-title">Executed security tests</h3>
              <p className="note">
                {run.adversarial?.label
                  ? run.adversarial.label
                  : "Baseline tests come from MedGuard policy. A model suggestion is executed only after it passes validation."}
                {run.adversarial?.origin ? ` Origin: ${run.adversarial.origin}.` : ""}
              </p>
              {run.test_results.length === 0 ? <p className="note">No test results yet. {run.sandbox.reason ?? ""}</p> : null}
              <ul className="tests">
                {run.test_results.map((test) => (
                  <li key={test.id} className={test.outcome}>
                    <div>
                      <strong>{test.policy_id}</strong> {test.title}
                      <em>{test.layer ?? "baseline"} · {test.outcome}{test.mandatory ? " · mandatory" : ""}</em>
                    </div>
                    {test.detail ? <pre>{test.detail}</pre> : null}
                  </li>
                ))}
              </ul>
              {(run.adversarial?.rejected ?? []).length > 0 ? (
                <>
                  <h3>Rejected model tests</h3>
                  <p className="note">These proposals failed validation or were unavailable. They were not executed.</p>
                  <ul className="findings">
                    {run.adversarial?.rejected?.map((item, index) => (
                      <li key={`${item.name ?? "rejected"}-${index}`}>{item.reason || item.name || "Rejected"}</li>
                    ))}
                  </ul>
                </>
              ) : null}
              {run.generated_tests ? (
                <details>
                  <summary>Generated pytest source</summary>
                  <pre className="source">{run.generated_tests}</pre>
                </details>
              ) : null}
              <h3>Evidence</h3>
              <dl className="evidence">
                <dt>Run</dt>
                <dd>{run.run_id}</dd>
                <dt>Code hash</dt>
                <dd>{run.code_sha256 || "pending"}</dd>
                <dt>Policy</dt>
                <dd>{run.policy_version}</dd>
                <dt>Storage</dt>
                <dd>{run.storage_label}</dd>
                <dt>Sandbox</dt>
                <dd>{run.sandbox.status ?? "pending"}{run.sandbox.reason ? ` — ${run.sandbox.reason}` : ""}</dd>
              </dl>
              {run.sandbox.isolation ? (
                <ul className="isolation">
                  {Object.entries(run.sandbox.isolation).map(([key, value]) => (
                    <li key={key}>
                      <span>{key}</span> {String(value)}
                    </li>
                  ))}
                </ul>
              ) : null}
              <h3>Security memory retrieval</h3>
              <p className="note">
                {run.memory_retrieval?.label || "No retrieval record for this run."}
                {run.memory_retrieval?.vector_search ? ` Vector search: ${run.memory_retrieval.vector_search}.` : ""}
              </p>
              {run.memory_retrieval?.disclaimer ? <p className="note">{run.memory_retrieval.disclaimer}</p> : null}
              {(run.memory_retrieval?.hits ?? []).length === 0 ? <p className="note">No similar past findings were retrieved before this run.</p> : null}
              <ul className="findings">
                {(run.memory_retrieval?.hits ?? []).map((item, index) => (
                  <li key={`${item.pattern_id ?? item.vulnerability_type}-${index}`}>
                    <strong>{item.vulnerability_type || item.pattern_id || "Past finding"}</strong>
                    <em>{item.severity || item.outcome || "historical"}</em>
                    <p>{item.failure_pattern || item.strategy || "Stored strategy from an earlier run."}</p>
                    {item.successful_test_strategy ? <p>Strategy: {item.successful_test_strategy}</p> : null}
                    {item.recommended_fix ? <p>Suggested fix: {item.recommended_fix}</p> : null}
                  </li>
                ))}
              </ul>
              {run.related_memory.length > 0 ? (
                <>
                  <h3>Saved from this code hash</h3>
                  <ul>
                    {run.related_memory.map((item, index) => (
                      <li key={`${item.pattern_id}-${index}`}>
                        {item.vulnerability_type || item.pattern_id}: {item.failure_pattern || item.outcome}. {item.successful_test_strategy || item.strategy}
                      </li>
                    ))}
                  </ul>
                </>
              ) : null}
            </>
          ) : (
            <p className="note">Choose an example and verify it. MedGuard will load policy, scan the code, generate its own tests, and run them in Docker.</p>
          )}
        </section>
      </main>

      <section className="panel history">
        <div className="section-heading">
          <div>
            <p className="eyebrow">03 / Audit trail</p>
            <h2>Verification history</h2>
          </div>
        </div>
        {history.length === 0 ? <p className="note">No stored runs yet.</p> : null}
        <ul>
          {history.map((item) => (
            <li key={item.run_id}>
              <button type="button" onClick={() => openHistory(item.run_id)}>
                <strong className={item.decision ?? "pending"}>{item.decision ?? item.status}</strong>
                <span>{item.scenario_id ?? "custom code"}</span>
                <span title={item.code_sha256}>SHA {item.code_sha256 ? item.code_sha256.slice(0, 12) : "pending"}</span>
                <span>{item.storage_backend}</span>
                <span>{item.created_at}</span>
              </button>
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}

function retrievalChip(health: Health | null): string {
  if (!health) return "unknown";
  if (health.mongodb.vector_search === "active" || health.mongodb.retrieval_mode === "atlas_vector") {
    return "Atlas Vector Search";
  }
  if (health.mongodb.retrieval_mode === "mongodb_index") {
    return "MongoDB index";
  }
  return "Local keyword";
}

function StatusChip({ label, value, title, tone }: { label: string; value: string; title?: string; tone: "good" | "warn" | "danger" }) {
  return (
    <div className={`chip ${tone}`} title={title ?? value}>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function Decision({ run, expected }: { run: Run | null; expected: string | null }) {
  if (!run?.decision) {
    return (
      <div className="decision pending" aria-live="polite">
        <span>{run?.status === "running" ? "VERIFYING" : "NO DECISION"}</span>
        <p>{run?.status === "running" ? "Checks are still executing. No outcome is being assumed." : "Submit code to begin independent verification."}</p>
      </div>
    );
  }
  return (
    <div className={`decision ${run.decision.toLowerCase()}`}>
      <span>{run.decision}</span>
      <p>{run.decision_reason}</p>
      {expected ? <p className="fixture-note">Fixture reference only: {expected}. The decision above comes from this run's evidence.</p> : null}
    </div>
  );
}

function FindingList({ items, empty }: { items: Finding[]; empty: string }) {
  if (items.length === 0) {
    return <p className="note">{empty}</p>;
  }
  return (
    <ul className="findings">
      {items.map((item, index) => (
        <li key={`${item.policy_id}-${item.line}-${index}`}>
          <div className="finding-title">
            <span className={`severity ${item.severity.toLowerCase()}`}>{item.severity}</span>
            <strong>{item.title}</strong>
          </div>
          <em>{item.policy_id} · {item.source}{item.line ? ` · line ${item.line}` : ""}</em>
          <p>{item.description}</p>
          <p className="remediation"><strong>Recommended remediation:</strong> {item.recommendation}</p>
        </li>
      ))}
    </ul>
  );
}

const PYTHON_TOKEN = /#.*$|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|\b(?:async|await|break|class|continue|def|del|elif|else|except|finally|for|from|global|if|import|in|is|lambda|nonlocal|not|or|pass|raise|return|try|while|with|yield|and|as|assert)\b|\b(?:True|False|None)\b|\b\d+(?:\.\d+)?\b|\b[A-Za-z_]\w*(?=\s*\()/g;

function CodeViewer({ value, onChange }: { value: string; onChange: (value: string) => void }) {
  const highlight = useRef<HTMLPreElement>(null);
  const lines = value.split("\n");

  function syncScroll(event: React.UIEvent<HTMLTextAreaElement>) {
    if (!highlight.current) return;
    highlight.current.scrollTop = event.currentTarget.scrollTop;
    highlight.current.scrollLeft = event.currentTarget.scrollLeft;
  }

  return (
    <div className="code-editor">
      <pre className="code-highlight" ref={highlight} aria-hidden="true">
        <code>
          {lines.map((line, index) => (
            <span className="code-line" key={index}>
              <span className="line-number">{index + 1}</span>
              <span>{highlightPython(line)}</span>
            </span>
          ))}
        </code>
      </pre>
      <textarea
        id="code"
        className="code-input"
        aria-label="Python source under review"
        spellCheck={false}
        wrap="off"
        value={value}
        onChange={(event) => onChange(event.target.value)}
        onScroll={syncScroll}
      />
    </div>
  );
}

function highlightPython(line: string) {
  const parts: React.ReactNode[] = [];
  let cursor = 0;
  for (const match of line.matchAll(PYTHON_TOKEN)) {
    const token = match[0];
    const start = match.index ?? 0;
    if (start > cursor) parts.push(line.slice(cursor, start));
    const kind = token.startsWith("#")
      ? "comment"
      : token.startsWith("\"") || token.startsWith("'")
        ? "string"
        : /^(True|False|None)$/.test(token)
          ? "literal"
          : /^\d/.test(token)
            ? "number"
            : /^(async|await|break|class|continue|def|del|elif|else|except|finally|for|from|global|if|import|in|is|lambda|nonlocal|not|or|pass|raise|return|try|while|with|yield|and|as|assert)$/.test(token)
              ? "keyword"
              : "function";
    parts.push(<span className={`token-${kind}`} key={start}>{token}</span>);
    cursor = start + token.length;
  }
  if (cursor < line.length) parts.push(line.slice(cursor));
  return parts;
}
