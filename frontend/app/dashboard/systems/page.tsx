"use client";

import { useRouter } from "next/navigation";
import { type FormEvent, useEffect, useState } from "react";

import { Button } from "@/components/ui/button";
import { useApiClient } from "@/lib/api-client";
import type { CreateTargetSystemRequest, TargetSystemResponse, TargetSystemType } from "@/types/api";

const initialFormState: CreateTargetSystemRequest = {
  name: "",
  description: "",
  role: "",
  system_prompt: "",
  api_endpoint: "",
  target_type: "openai_compatible",
  api_key: "",
  model_name: "",
  is_active: true
};

const providerGuidance: Record<
  TargetSystemType,
  {
    credential: string;
    credentialPlaceholder: string;
    endpoint: string;
    endpointPlaceholder: string;
    label: string;
    model: string;
    modelPlaceholder: string;
  }
> = {
  openai_compatible: {
    label: "OpenAI-compatible",
    endpoint:
      "Use the provider base URL or its full /chat/completions route. ShadowLedger normalizes either form.",
    endpointPlaceholder: "https://api.openai.com/v1",
    model: "Enter the exact chat model ID enabled by your provider.",
    modelPlaceholder: "gpt-4o-mini",
    credential: "Use the provider API key sent as an Authorization bearer credential.",
    credentialPlaceholder: "Provider API key"
  },
  anthropic: {
    label: "Anthropic",
    endpoint: "Use the Anthropic API base URL or the full /v1/messages endpoint.",
    endpointPlaceholder: "https://api.anthropic.com",
    model: "Enter an exact Claude model ID enabled for your Anthropic account.",
    modelPlaceholder: "claude-model-id",
    credential: "Use an Anthropic API key; requests authenticate through the x-api-key header.",
    credentialPlaceholder: "Anthropic API key"
  }
};

export default function SystemsPage() {
  const apiClient = useApiClient();
  const router = useRouter();
  const [systems, setSystems] = useState<TargetSystemResponse[]>([]);
  const [form, setForm] = useState<CreateTargetSystemRequest>(initialFormState);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [isCreating, setIsCreating] = useState(false);
  const [runningSystemId, setRunningSystemId] = useState<string | null>(null);
  const [runError, setRunError] = useState<{ message: string; systemId: string } | null>(null);

  const guidance = providerGuidance[form.target_type];

  useEffect(() => {
    let active = true;

    async function loadSystems() {
      setIsLoading(true);
      setError(null);

      try {
        const data = await apiClient.getTargetSystems();
        if (active) {
          setSystems(data);
        }
      } catch (requestError) {
        if (active) {
          setError(requestError instanceof Error ? requestError.message : "Unable to load target systems.");
        }
      } finally {
        if (active) {
          setIsLoading(false);
        }
      }
    }

    void loadSystems();

    return () => {
      active = false;
    };
  }, [apiClient]);

  function updateField<K extends keyof CreateTargetSystemRequest>(field: K, value: CreateTargetSystemRequest[K]) {
    setForm((current) => ({
      ...current,
      [field]: value
    }));
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setSuccessMessage(null);

    const payload: CreateTargetSystemRequest = {
      ...form,
      description: form.description || null
    };

    // Do not retain credentials in component state while the protected request is in flight.
    setForm((current) => ({
      ...current,
      api_key: ""
    }));

    setIsCreating(true);
    try {
      const created = await apiClient.createTargetSystem(payload);
      setSystems((current) => [created, ...current]);
      setSuccessMessage(`Stored ${created.name}.`);
      setForm(initialFormState);
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Unable to create target system.");
    } finally {
      setIsCreating(false);
    }
  }

  async function handleRunScan(system: TargetSystemResponse) {
    if (!system.is_active || runningSystemId) {
      return;
    }

    const confirmed = window.confirm(
      `Run every active attack vector against ${system.name}? This sends prompts to the target and may incur provider charges.`
    );
    if (!confirmed) {
      return;
    }

    setRunError(null);
    setRunningSystemId(system.id);

    try {
      const attackRun = await apiClient.createAttackRun({
        target_system_id: system.id,
        vector_category_filter: null
      });
      router.push(`/dashboard/runs/${attackRun.id}`);
    } catch (requestError) {
      setRunError({
        message: requestError instanceof Error ? requestError.message : "Unable to start a scan.",
        systemId: system.id
      });
    } finally {
      setRunningSystemId(null);
    }
  }

  return (
    <div className="grid gap-6 xl:grid-cols-[360px_minmax(0,1fr)]">
      <section className="rounded-[1.75rem] border bg-white/85 p-6 shadow-sm">
        <p className="text-xs uppercase tracking-[0.24em] text-muted-foreground">Target system contract</p>
        <h2 className="mt-3 font-[family-name:var(--font-heading)] text-3xl font-semibold">
          Connect your own AI system
        </h2>
        <p className="mt-3 text-sm leading-7 text-muted-foreground">
          Start with a live model in the inventory, or connect an assistant you own. Your provider key is stored
          securely and stays private to your workspace.
        </p>

        <form onSubmit={handleSubmit} className="mt-6 space-y-4">
          <Field
            id="system-name"
            label="System name"
            value={form.name}
            onChange={(value) => updateField("name", value)}
            placeholder="Support triage assistant"
            required
          />
          <Field
            id="system-description"
            label="Description"
            value={form.description ?? ""}
            onChange={(value) => updateField("description", value)}
            placeholder="Describe the assistant, domain, and trust boundary."
            multiline
          />
          <Field
            id="system-role"
            label="Assistant role"
            value={form.role ?? ""}
            onChange={(value) => updateField("role", value)}
            placeholder="IT Support, Restaurant Help, Customer Support"
            required
          />
          <Field
            id="system-prompt"
            label="System prompt"
            value={form.system_prompt ?? ""}
            onChange={(value) => updateField("system_prompt", value)}
            placeholder="You are an IT support assistant. Help users troubleshoot safely..."
            hint="Define the assistant’s job, available knowledge, privacy rules, and escalation boundaries. Sent as system instructions on every test."
            multiline
            required
          />
          <div className="space-y-2">
            <label htmlFor="target-type" className="text-sm font-medium">
              Target type
            </label>
            <select
              id="target-type"
              value={form.target_type}
              onChange={(event) => updateField("target_type", event.target.value as TargetSystemType)}
              className="h-12 w-full rounded-2xl border bg-background px-4 text-sm outline-none transition focus:border-primary"
            >
              <option value="openai_compatible">OpenAI-compatible</option>
              <option value="anthropic">Anthropic</option>
            </select>
          </div>

          <div className="rounded-2xl border border-teal-100 bg-teal-50/70 p-4 text-sm text-teal-950">
            <p className="font-medium">{guidance.label} request settings</p>
            <ul className="mt-2 list-disc space-y-1 pl-5 text-xs leading-5 text-teal-900/80">
              <li>{guidance.endpoint}</li>
              <li>{guidance.model}</li>
              <li>{guidance.credential}</li>
            </ul>
          </div>

          <Field
            id="api-endpoint"
            label="API endpoint"
            value={form.api_endpoint}
            onChange={(value) => updateField("api_endpoint", value)}
            placeholder={guidance.endpointPlaceholder}
            hint={guidance.endpoint}
            type="url"
            required
          />

          <Field
            id="model-name"
            label="Model name"
            value={form.model_name}
            onChange={(value) => updateField("model_name", value)}
            placeholder={guidance.modelPlaceholder}
            hint={guidance.model}
            required
          />
          <Field
            id="api-key"
            label="API key"
            value={form.api_key}
            onChange={(value) => updateField("api_key", value)}
            placeholder={guidance.credentialPlaceholder}
            hint={`${guidance.credential} Cleared from this form as soon as submission begins.`}
            type="password"
            autoComplete="new-password"
            required
          />

          <label className="flex items-center gap-3 rounded-2xl border bg-muted/60 px-4 py-3 text-sm">
            <input
              type="checkbox"
              checked={form.is_active}
              onChange={(event) => updateField("is_active", event.target.checked)}
              className="h-4 w-4 rounded border"
            />
            Active and ready for attack execution
          </label>

          {error ? <p className="text-sm text-orange-600">{error}</p> : null}
          {successMessage ? <p className="text-sm text-teal-700">{successMessage}</p> : null}

          <Button type="submit" size="lg" className="w-full" disabled={isCreating}>
            {isCreating ? "Saving target..." : "Create target system"}
          </Button>
        </form>
      </section>

      <section className="rounded-[1.75rem] border bg-white/85 p-6 shadow-sm">
        {systems.some((system) => system.is_starter) ? (
          <div className="mb-6 rounded-2xl border border-teal-200 bg-teal-50 p-5 text-teal-950">
            <p className="font-medium">Start with a live assistant</p>
            <p className="mt-2 text-sm leading-6">
              IT Support, Restaurant Help, and Customer Support each have their own system instructions and call live
              OpenAI models using the app-provided key. Choose an assistant to test its role and boundaries.
            </p>
          </div>
        ) : null}
        <div className="flex items-center justify-between gap-4">
          <div>
            <p className="text-xs uppercase tracking-[0.24em] text-muted-foreground">Registered systems</p>
            <h2 className="mt-3 font-[family-name:var(--font-heading)] text-3xl font-semibold">
              Attack surface inventory
            </h2>
          </div>
          <span className="rounded-full bg-secondary px-4 py-2 text-xs uppercase tracking-[0.22em] text-secondary-foreground">
            {systems.length} tracked
          </span>
        </div>

        {isLoading ? (
          <div className="mt-8 grid gap-4 md:grid-cols-2">
            {Array.from({ length: 4 }).map((_, index) => (
              <div key={index} className="h-44 animate-pulse rounded-[1.5rem] border bg-muted/60" />
            ))}
          </div>
        ) : systems.length > 0 ? (
          <div className="mt-8 grid gap-4 md:grid-cols-2">
            {systems.map((system) => (
              <article key={system.id} className="rounded-[1.5rem] border bg-background/80 p-5">
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <h3 className="font-[family-name:var(--font-heading)] text-xl font-semibold">{system.name}</h3>
                    <p className="mt-2 text-sm text-muted-foreground">{system.role || "General Assistant"} · {system.model_name}</p>
                  </div>
                  <span
                    className={`rounded-full px-3 py-1 text-xs uppercase tracking-[0.22em] ${
                      system.is_active && system.api_key_configured ? "bg-teal-100 text-teal-900" : "bg-slate-200 text-slate-700"
                    }`}
                  >
                    {system.is_active ? system.api_key_configured ? "ready" : "needs key" : "inactive"}
                  </span>
                </div>
                <p className="mt-4 text-sm leading-7 text-muted-foreground">
                  {system.description || "No description supplied for this target system yet."}
                </p>
                <dl className="mt-5 grid gap-3 text-sm">
                  <div>
                    <dt className="text-xs uppercase tracking-[0.22em] text-muted-foreground">Endpoint</dt>
                    <dd className="mt-1 break-all">{system.api_endpoint}</dd>
                  </div>
                  <div>
                    <dt className="text-xs uppercase tracking-[0.22em] text-muted-foreground">Target type</dt>
                    <dd className="mt-1">{system.target_type}</dd>
                  </div>
                  <div>
                    <dt className="text-xs uppercase tracking-[0.22em] text-muted-foreground">Credential</dt>
                    <dd className="mt-1">{system.credential_source === "app"
                      ? "Provided by ShadowLedger"
                      : system.api_key_configured ? "Your encrypted API key" : "Connection required"}</dd>
                  </div>
                </dl>
                <details className="mt-4 rounded-2xl border bg-muted/40 p-4">
                  <summary className="cursor-pointer text-sm font-medium focus-visible:outline focus-visible:outline-2 focus-visible:outline-primary">
                    View system prompt
                  </summary>
                  <p className="mt-3 whitespace-pre-wrap break-words text-sm leading-6 text-muted-foreground">
                    {system.system_prompt || "No system instructions are configured for this target."}
                  </p>
                </details>
                <div className="mt-5 border-t pt-4">
                  <Button
                    type="button"
                    className="w-full"
                    onClick={() => void handleRunScan(system)}
                    disabled={!system.is_active || !system.api_key_configured || runningSystemId !== null}
                    title={!system.api_key_configured ? "Configure a provider key before starting a scan." : system.is_active ? undefined : "Activate this target before starting a scan."}
                  >
                    {runningSystemId === system.id ? "Starting scan..." : "Run Full Scan"}
                  </Button>
                  {system.is_active ? (
                    <p className="mt-2 text-xs text-muted-foreground">
                      Runs every active vector and may consume both orchestration and target-provider credits.
                    </p>
                  ) : null}
                  {!system.is_active ? (
                    <p className="mt-2 text-xs text-muted-foreground">Inactive targets cannot start new scans.</p>
                  ) : null}
                  {runError?.systemId === system.id ? (
                    <p className="mt-2 text-sm text-orange-600">{runError.message}</p>
                  ) : null}
                </div>
              </article>
            ))}
          </div>
        ) : (
          <div className="mt-8 rounded-[1.5rem] border border-dashed bg-muted/50 p-8 text-sm text-muted-foreground">
            {error || "No target systems are available yet. Add one with the form to begin mapping your attack surface."}
          </div>
        )}
      </section>
    </div>
  );
}

interface FieldProps {
  id: string;
  label: string;
  value: string;
  onChange: (value: string) => void;
  placeholder: string;
  hint?: string;
  multiline?: boolean;
  type?: "text" | "password" | "url";
  autoComplete?: string;
  required?: boolean;
}

function Field({
  id,
  label,
  value,
  onChange,
  placeholder,
  hint,
  multiline = false,
  type = "text",
  autoComplete,
  required = false
}: FieldProps) {
  const sharedClasses =
    "w-full rounded-2xl border bg-background px-4 text-sm outline-none transition focus:border-primary";

  return (
    <div className="space-y-2">
      <label htmlFor={id} className="text-sm font-medium">
        {label}
      </label>
      {multiline ? (
        <textarea
          id={id}
          value={value}
          onChange={(event) => onChange(event.target.value)}
          placeholder={placeholder}
          required={required}
          aria-describedby={hint ? `${id}-hint` : undefined}
          className={`${sharedClasses} min-h-[112px] py-3`}
        />
      ) : (
        <input
          id={id}
          type={type}
          value={value}
          onChange={(event) => onChange(event.target.value)}
          placeholder={placeholder}
          autoComplete={autoComplete}
          required={required}
          aria-describedby={hint ? `${id}-hint` : undefined}
          className={`${sharedClasses} h-12`}
        />
      )}
      {hint ? (
        <p id={`${id}-hint`} className="text-xs leading-5 text-muted-foreground">
          {hint}
        </p>
      ) : null}
    </div>
  );
}
