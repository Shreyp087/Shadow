"use client";

import { type FormEvent, useEffect, useState, useTransition } from "react";

import { Button } from "@/components/ui/button";
import { useApiClient } from "@/lib/api-client";
import type { CreateTargetSystemRequest, TargetSystemResponse, TargetSystemType } from "@/types/api";

const initialFormState: CreateTargetSystemRequest = {
  name: "",
  description: "",
  api_endpoint: "",
  target_type: "openai_compatible",
  api_key: "",
  model_name: "",
  is_active: true
};

function formatMaskedApiKey(maskedApiKey: string) {
  const suffix = maskedApiKey.slice(-4);
  return `sk-...${suffix}`;
}

export default function SystemsPage() {
  const apiClient = useApiClient();
  const [systems, setSystems] = useState<TargetSystemResponse[]>([]);
  const [form, setForm] = useState<CreateTargetSystemRequest>(initialFormState);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [isPending, startTransition] = useTransition();

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

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setSuccessMessage(null);

    startTransition(async () => {
      try {
        const created = await apiClient.createTargetSystem({
          ...form,
          description: form.description || null
        });
        setSystems((current) => [created, ...current]);
        setSuccessMessage(`Stored ${created.name}.`);
        setForm(initialFormState);
      } catch (requestError) {
        setError(requestError instanceof Error ? requestError.message : "Unable to create target system.");
      }
    });
  }

  return (
    <div className="grid gap-6 xl:grid-cols-[360px_minmax(0,1fr)]">
      <section className="rounded-[1.75rem] border bg-white/85 p-6 shadow-sm">
        <p className="text-xs uppercase tracking-[0.24em] text-muted-foreground">Target system contract</p>
        <h2 className="mt-3 font-[family-name:var(--font-heading)] text-3xl font-semibold">
          Register the AI systems you want ShadowLedger to probe
        </h2>
        <p className="mt-3 text-sm leading-7 text-muted-foreground">
          This form uses the authenticated Clerk identity automatically and encrypts the API key on the backend
          before it is stored.
        </p>

        <form onSubmit={handleSubmit} className="mt-6 space-y-4">
          <Field
            id="system-name"
            label="System name"
            value={form.name}
            onChange={(value) => updateField("name", value)}
            placeholder="Support triage assistant"
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
            id="api-endpoint"
            label="API endpoint"
            value={form.api_endpoint}
            onChange={(value) => updateField("api_endpoint", value)}
            placeholder="https://example.com/v1/chat/completions"
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
              <option value="openai_compatible">openai_compatible</option>
              <option value="anthropic">anthropic</option>
            </select>
          </div>

          <Field
            id="model-name"
            label="Model name"
            value={form.model_name}
            onChange={(value) => updateField("model_name", value)}
            placeholder="gpt-4o-mini"
          />
          <Field
            id="api-key"
            label="API key"
            value={form.api_key}
            onChange={(value) => updateField("api_key", value)}
            placeholder="sk-..."
            type="password"
            autoComplete="new-password"
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

          <Button type="submit" size="lg" className="w-full" disabled={isPending}>
            {isPending ? "Saving target..." : "Create target system"}
          </Button>
        </form>
      </section>

      <section className="rounded-[1.75rem] border bg-white/85 p-6 shadow-sm">
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
                    <p className="mt-2 text-sm text-muted-foreground">{system.model_name}</p>
                  </div>
                  <span
                    className={`rounded-full px-3 py-1 text-xs uppercase tracking-[0.22em] ${
                      system.is_active ? "bg-teal-100 text-teal-900" : "bg-slate-200 text-slate-700"
                    }`}
                  >
                    {system.is_active ? "active" : "inactive"}
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
                    <dt className="text-xs uppercase tracking-[0.22em] text-muted-foreground">API key</dt>
                    <dd className="mt-1 font-mono">{formatMaskedApiKey(system.api_key_masked)}</dd>
                  </div>
                </dl>
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
  multiline?: boolean;
  type?: "text" | "password";
  autoComplete?: string;
}

function Field({
  id,
  label,
  value,
  onChange,
  placeholder,
  multiline = false,
  type = "text",
  autoComplete
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
          className={`${sharedClasses} h-12`}
        />
      )}
    </div>
  );
}
