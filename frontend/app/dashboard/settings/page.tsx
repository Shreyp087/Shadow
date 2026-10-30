"use client";

import {
  BrainCircuit,
  CheckCircle2,
  Cloud,
  GitCompareArrows,
  Laptop,
  Loader2,
  PlugZap,
  RefreshCw,
  Save,
  ShieldCheck,
  Sparkles
} from "lucide-react";
import { type FormEvent, useEffect, useMemo, useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { useApiClient } from "@/lib/api-client";
import { cn } from "@/lib/utils";
import type {
  LLMConnectionTestResponse,
  LLMProvider,
  LLMRole,
  LLMRoleSettingResponse,
  UpdateLLMRoleSettingRequest
} from "@/types/api";

const roles: LLMRole[] = ["attacker", "mutator", "judge"];
const localDefaultBaseUrl = "http://127.0.0.1:1234/v1";

const roleDetails = {
  attacker: {
    label: "Attacker",
    icon: Sparkles,
    description: "Generates the first adversarial prompt for each active attack vector."
  },
  mutator: {
    label: "Mutator",
    icon: GitCompareArrows,
    description: "Rewrites high-risk prompts into fresh follow-up attempts."
  },
  judge: {
    label: "Scorer / Judge",
    icon: ShieldCheck,
    description: "Scores target responses and records the reason for each risk decision."
  }
} satisfies Record<LLMRole, { description: string; icon: typeof Sparkles; label: string }>;

const providerDetails = {
  hosted_openai: {
    label: "Hosted OpenAI",
    shortLabel: "Hosted",
    icon: Cloud,
    description: "OpenAI's fixed API endpoint with an environment or encrypted saved key."
  },
  hosted_anthropic: {
    label: "Anthropic Claude",
    shortLabel: "Claude",
    icon: BrainCircuit,
    description: "Claude through Anthropic's official API, using an app or saved Anthropic key."
  },
  local_openai_compatible: {
    label: "Local / LM Studio",
    shortLabel: "Local",
    icon: Laptop,
    description: "A loopback OpenAI-compatible server, such as LM Studio."
  }
} satisfies Record<LLMProvider, { description: string; icon: typeof Cloud; label: string; shortLabel: string }>;

interface RoleDraft {
  provider: LLMProvider;
  model_name: string;
  base_url: string;
  api_key: string;
}

interface RoleNotice {
  kind: "error" | "success";
  message: string;
}

type SettingsByRole = Partial<Record<LLMRole, LLMRoleSettingResponse>>;
type DraftsByRole = Record<LLMRole, RoleDraft>;
type PendingByRole = Record<LLMRole, "save" | "test" | null>;
type NoticesByRole = Partial<Record<LLMRole, RoleNotice>>;

function createInitialDrafts(): DraftsByRole {
  return {
    attacker: {
      provider: "hosted_openai",
      model_name: "",
      base_url: "",
      api_key: ""
    },
    mutator: {
      provider: "hosted_openai",
      model_name: "",
      base_url: "",
      api_key: ""
    },
    judge: {
      provider: "hosted_openai",
      model_name: "",
      base_url: "",
      api_key: ""
    }
  };
}

function draftFromSetting(setting: LLMRoleSettingResponse): RoleDraft {
  return {
    provider: setting.provider,
    model_name: setting.model_name,
    base_url: setting.provider === "local_openai_compatible" ? setting.base_url || localDefaultBaseUrl : "",
    api_key: ""
  };
}

function isDraftDirty(draft: RoleDraft, saved?: LLMRoleSettingResponse) {
  if (!saved || draft.api_key.length > 0) {
    return true;
  }

  const savedBaseUrl = saved.provider === "local_openai_compatible" ? saved.base_url || "" : "";
  const draftBaseUrl = draft.provider === "local_openai_compatible" ? draft.base_url.trim() : "";

  return (
    draft.provider !== saved.provider ||
    draft.model_name.trim() !== saved.model_name ||
    draftBaseUrl !== savedBaseUrl
  );
}

export default function SettingsPage() {
  const apiClient = useApiClient();
  const [settings, setSettings] = useState<SettingsByRole>({});
  const [drafts, setDrafts] = useState<DraftsByRole>(createInitialDrafts);
  const [pending, setPending] = useState<PendingByRole>({ attacker: null, mutator: null, judge: null });
  const [notices, setNotices] = useState<NoticesByRole>({});
  const [isLoading, setIsLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [loadAttempt, setLoadAttempt] = useState(0);

  useEffect(() => {
    let active = true;

    async function loadSettings() {
      setIsLoading(true);
      setLoadError(null);

      try {
        const response = await apiClient.getLlmRoleSettings();
        if (!active) {
          return;
        }

        const nextSettings: SettingsByRole = {};
        const nextDrafts = createInitialDrafts();

        for (const setting of response) {
          nextSettings[setting.role] = setting;
          nextDrafts[setting.role] = draftFromSetting(setting);
        }

        setSettings(nextSettings);
        setDrafts(nextDrafts);
      } catch (requestError) {
        if (active) {
          setLoadError(requestError instanceof Error ? requestError.message : "Unable to load LLM role settings.");
        }
      } finally {
        if (active) {
          setIsLoading(false);
        }
      }
    }

    void loadSettings();

    return () => {
      active = false;
    };
  }, [apiClient, loadAttempt]);

  const localCount = useMemo(
    () => roles.filter((role) => drafts[role].provider === "local_openai_compatible").length,
    [drafts]
  );
  const hostedCount = roles.length - localCount;

  function updateDraft(role: LLMRole, patch: Partial<RoleDraft>) {
    setDrafts((current) => ({
      ...current,
      [role]: {
        ...current[role],
        ...patch
      }
    }));
    setNotices((current) => ({ ...current, [role]: undefined }));
  }

  function selectProvider(role: LLMRole, provider: LLMProvider) {
    const current = drafts[role];
    updateDraft(role, {
      provider,
      api_key: "",
      model_name: provider === "hosted_anthropic"
        ? "claude-sonnet-4-6"
        : current.provider === "hosted_anthropic" ? "gpt-4o-mini" : current.model_name,
      base_url:
        provider === "local_openai_compatible"
          ? current.base_url || localDefaultBaseUrl
          : ""
    });
  }

  function setPendingAction(role: LLMRole, action: "save" | "test" | null) {
    setPending((current) => ({ ...current, [role]: action }));
  }

  async function saveRole(role: LLMRole) {
    const draft = drafts[role];
    const apiKey = draft.api_key.trim();
    const payload: UpdateLLMRoleSettingRequest = {
      provider: draft.provider,
      model_name: draft.model_name.trim(),
      base_url: draft.provider === "local_openai_compatible" ? draft.base_url.trim() : null,
      ...(apiKey ? { api_key: apiKey } : {})
    };

    // Credentials are write-only: remove the value before the protected request leaves this component.
    setDrafts((current) => ({
      ...current,
      [role]: {
        ...current[role],
        api_key: ""
      }
    }));
    setNotices((current) => ({ ...current, [role]: undefined }));
    setPendingAction(role, "save");

    try {
      const saved = await apiClient.updateLlmRoleSetting(role, payload);
      setSettings((current) => ({ ...current, [role]: saved }));
      setDrafts((current) => ({ ...current, [role]: draftFromSetting(saved) }));
      setNotices((current) => ({
        ...current,
        [role]: {
          kind: "success",
          message: `${roleDetails[role].label} now uses ${providerDetails[saved.provider].label}.`
        }
      }));
    } catch (requestError) {
      setNotices((current) => ({
        ...current,
        [role]: {
          kind: "error",
          message: `${requestError instanceof Error ? requestError.message : "Unable to save this role."} Re-enter the API key if you supplied one.`
        }
      }));
    } finally {
      setPendingAction(role, null);
    }
  }

  async function testRole(role: LLMRole) {
    setNotices((current) => ({ ...current, [role]: undefined }));
    setPendingAction(role, "test");

    try {
      const result = await apiClient.testLlmRoleSetting(role);
      setNotices((current) => ({
        ...current,
        [role]: connectionTestNotice(result)
      }));
    } catch (requestError) {
      setNotices((current) => ({
        ...current,
        [role]: {
          kind: "error",
          message: requestError instanceof Error ? requestError.message : "Connection test failed."
        }
      }));
    } finally {
      setPendingAction(role, null);
    }
  }

  return (
    <div className="space-y-6">
      <Card className="overflow-hidden">
        <div className="grid gap-0 lg:grid-cols-[minmax(0,1fr)_340px]">
          <CardHeader className="p-7 lg:p-8">
            <div className="flex h-11 w-11 items-center justify-center rounded-2xl bg-primary text-primary-foreground shadow-md">
              <BrainCircuit className="h-5 w-5" aria-hidden="true" />
            </div>
            <p className="pt-4 text-xs uppercase tracking-[0.24em] text-muted-foreground">LLM execution routing</p>
            <CardTitle className="max-w-2xl text-3xl leading-tight">Choose the provider behind every orchestration role</CardTitle>
            <CardDescription className="max-w-3xl">
              Route Attacker, Mutator, and Judge independently between hosted OpenAI and your local LM Studio server.
              Every role stays enabled, and all 8 local/hosted assignments are supported.
            </CardDescription>
          </CardHeader>

          <div className="border-t bg-secondary/45 p-7 lg:border-l lg:border-t-0 lg:p-8">
            <p className="text-xs uppercase tracking-[0.24em] text-muted-foreground">Selected combination</p>
            <p className="mt-3 font-[family-name:var(--font-heading)] text-3xl font-semibold">
              {localCount} local <span className="text-muted-foreground">·</span> {hostedCount} hosted
            </p>
            <div className="mt-5 space-y-2">
              {roles.map((role) => {
                const detail = roleDetails[role];
                const provider = providerDetails[drafts[role].provider];
                const ProviderIcon = provider.icon;

                return (
                  <div key={role} className="flex items-center justify-between gap-4 rounded-2xl bg-white/80 px-4 py-3 text-sm">
                    <span className="font-medium">{detail.label}</span>
                    <span className="inline-flex items-center gap-2 text-muted-foreground">
                      <ProviderIcon className="h-4 w-4" aria-hidden="true" />
                      {provider.shortLabel}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </Card>

      {loadError ? (
        <div role="alert" className="flex flex-col gap-4 rounded-[1.5rem] border border-orange-200 bg-orange-50 p-5 text-orange-950 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <p className="font-medium">Settings could not be loaded</p>
            <p className="mt-1 text-sm text-orange-900/80">{loadError}</p>
          </div>
          <Button type="button" variant="outline" onClick={() => setLoadAttempt((attempt) => attempt + 1)}>
            <RefreshCw className="mr-2 h-4 w-4" aria-hidden="true" />
            Retry
          </Button>
        </div>
      ) : null}

      {isLoading ? (
        <div className="grid gap-5 xl:grid-cols-3" aria-label="Loading LLM role settings">
          {roles.map((role) => (
            <div key={role} className="h-[590px] animate-pulse rounded-[1.5rem] border bg-muted/60" />
          ))}
        </div>
      ) : (
        <div className="grid items-start gap-5 xl:grid-cols-3">
          {roles.map((role) => (
            <RoleSettingsCard
              key={role}
              role={role}
              draft={drafts[role]}
              saved={settings[role]}
              pending={pending[role]}
              notice={notices[role]}
              onChange={(patch) => updateDraft(role, patch)}
              onProviderChange={(provider) => selectProvider(role, provider)}
              onSave={() => void saveRole(role)}
              onTest={() => void testRole(role)}
            />
          ))}
        </div>
      )}

      <Card>
        <CardContent className="grid gap-5 p-6 md:grid-cols-[auto_minmax(0,1fr)] md:p-7">
          <div className="flex h-11 w-11 items-center justify-center rounded-2xl bg-teal-100 text-teal-900">
            <ShieldCheck className="h-5 w-5" aria-hidden="true" />
          </div>
          <div>
            <h2 className="font-[family-name:var(--font-heading)] text-xl font-semibold">Credential boundary</h2>
            <p className="mt-2 max-w-4xl text-sm leading-7 text-muted-foreground">
              API keys entered here are sent only to the authenticated backend, encrypted at rest, and never returned
              by the API. A blank credential field keeps the current key or server environment fallback. ShadowLedger
              clears a replacement value from this page as soon as saving starts. Never paste a Clerk secret here.
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

interface RoleSettingsCardProps {
  role: LLMRole;
  draft: RoleDraft;
  saved?: LLMRoleSettingResponse;
  pending: "save" | "test" | null;
  notice?: RoleNotice;
  onChange: (patch: Partial<RoleDraft>) => void;
  onProviderChange: (provider: LLMProvider) => void;
  onSave: () => void;
  onTest: () => void;
}

function RoleSettingsCard({
  role,
  draft,
  saved,
  pending,
  notice,
  onChange,
  onProviderChange,
  onSave,
  onTest
}: RoleSettingsCardProps) {
  const detail = roleDetails[role];
  const RoleIcon = detail.icon;
  const dirty = isDraftDirty(draft, saved);
  const providerChanged = Boolean(saved && saved.provider !== draft.provider);
  const needsHostedKey =
    draft.provider !== "local_openai_compatible" &&
    saved?.provider === draft.provider &&
    !saved.api_key_configured &&
    !draft.api_key.trim();
  const valid =
    Boolean(draft.model_name.trim()) &&
    !needsHostedKey &&
    (draft.provider !== "local_openai_compatible" || Boolean(draft.base_url.trim()));
  const canTest = Boolean(saved) && !dirty && pending === null;

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (valid && dirty && pending === null) {
      onSave();
    }
  }

  return (
    <Card className="overflow-hidden">
      <form onSubmit={handleSubmit}>
        <CardHeader className="border-b bg-white/65">
          <div className="flex items-start justify-between gap-4">
            <div className="flex h-11 w-11 items-center justify-center rounded-2xl bg-secondary text-secondary-foreground">
              <RoleIcon className="h-5 w-5" aria-hidden="true" />
            </div>
            <CredentialBadge draft={draft} saved={saved} providerChanged={providerChanged} />
          </div>
          <CardTitle className="pt-3">{detail.label}</CardTitle>
          <CardDescription>{detail.description}</CardDescription>
          {saved ? (
            <p className="pt-2 text-xs text-muted-foreground">
              {saved.is_default ? "Using the backend environment default" : "Using a saved role override"}
            </p>
          ) : null}
        </CardHeader>

        <CardContent className="space-y-5 p-6">
          <fieldset className="space-y-3">
            <legend className="text-sm font-medium">Provider</legend>
            <div className="grid gap-2">
              {(Object.keys(providerDetails) as LLMProvider[]).map((provider) => {
                const providerDetail = providerDetails[provider];
                const ProviderIcon = providerDetail.icon;
                const selected = draft.provider === provider;

                return (
                  <label
                    key={provider}
                    className={cn(
                      "flex cursor-pointer items-start gap-3 rounded-2xl border p-4 transition focus-within:ring-2 focus-within:ring-ring focus-within:ring-offset-2",
                      selected ? "border-primary bg-teal-50/70" : "bg-background hover:bg-muted/60"
                    )}
                  >
                    <input
                      type="radio"
                      name={`${role}-provider`}
                      value={provider}
                      checked={selected}
                      onChange={() => onProviderChange(provider)}
                      className="mt-1 h-4 w-4 accent-[hsl(var(--primary))]"
                    />
                    <span className="min-w-0">
                      <span className="flex items-center gap-2 text-sm font-medium">
                        <ProviderIcon className="h-4 w-4" aria-hidden="true" />
                        {providerDetail.label}
                      </span>
                      <span className="mt-1 block text-xs leading-5 text-muted-foreground">
                        {providerDetail.description}
                      </span>
                    </span>
                  </label>
                );
              })}
            </div>
          </fieldset>

          <SettingsField
            id={`${role}-model`}
            label="Model ID"
            value={draft.model_name}
            onChange={(value) => onChange({ model_name: value })}
            placeholder={
              draft.provider === "local_openai_compatible"
                ? "mistralai/ministral-3-14b-reasoning"
                : draft.provider === "hosted_anthropic" ? "claude-sonnet-4-6" : "gpt-4o-mini"
            }
            hint={
              draft.provider === "local_openai_compatible"
                ? "Use the exact id returned by LM Studio at GET /v1/models."
                : draft.provider === "hosted_anthropic"
                  ? "Use a Claude model ID enabled for your Anthropic account, such as claude-sonnet-4-6."
                  : "Use an exact chat model ID enabled for the OpenAI project."
            }
            required
          />

          {draft.provider === "local_openai_compatible" ? (
            <SettingsField
              id={`${role}-base-url`}
              label="Local base URL"
              value={draft.base_url}
              onChange={(value) => onChange({ base_url: value })}
              placeholder={localDefaultBaseUrl}
              hint="Development only. ShadowLedger accepts a loopback LM Studio/OpenAI-compatible URL."
              type="url"
              required
            />
          ) : (
            <div className="rounded-2xl border bg-muted/50 px-4 py-3">
              <p className="text-xs uppercase tracking-[0.2em] text-muted-foreground">Hosted endpoint</p>
              <p className="mt-2 break-all text-sm">
                {draft.provider === "hosted_anthropic" ? "https://api.anthropic.com" : "https://api.openai.com/v1"}
              </p>
              {draft.provider === "hosted_anthropic" ? (
                <p className="mt-2 text-xs leading-5 text-muted-foreground">
                  Uses the app&apos;s ANTHROPIC_API_KEY when configured, or an Anthropic key saved for this role.
                </p>
              ) : null}
            </div>
          )}

          <SettingsField
            id={`${role}-api-key`}
            label={needsHostedKey ? "API key" : "Replacement API key (optional)"}
            value={draft.api_key}
            onChange={(value) => onChange({ api_key: value })}
            placeholder={saved?.api_key_configured && !providerChanged ? "Leave blank to keep stored key" : "Paste a new provider key"}
            hint={
              providerChanged
                ? "Provider changes require a provider-appropriate credential; the old credential is never forwarded."
                : "Write-only. A saved key is never redisplayed, and blank preserves it."
            }
            type="password"
            autoComplete="new-password"
            required={needsHostedKey}
          />

          {notice ? (
            <div
              role={notice.kind === "error" ? "alert" : "status"}
              aria-live="polite"
              className={cn(
                "rounded-2xl border px-4 py-3 text-sm leading-6",
                notice.kind === "success"
                  ? "border-emerald-200 bg-emerald-50 text-emerald-950"
                  : "border-orange-200 bg-orange-50 text-orange-950"
              )}
            >
              {notice.message}
            </div>
          ) : null}

          <div className="grid grid-cols-2 gap-3 border-t pt-5">
            <Button type="submit" disabled={!valid || !dirty || pending !== null}>
              {pending === "save" ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" aria-hidden="true" />
              ) : (
                <Save className="mr-2 h-4 w-4" aria-hidden="true" />
              )}
              {pending === "save" ? "Saving…" : dirty ? "Save role" : "Saved"}
            </Button>
            <Button
              type="button"
              variant="outline"
              disabled={!canTest}
              onClick={onTest}
              title={dirty ? "Save changes before testing the connection." : undefined}
            >
              {pending === "test" ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" aria-hidden="true" />
              ) : (
                <PlugZap className="mr-2 h-4 w-4" aria-hidden="true" />
              )}
              {pending === "test" ? "Testing…" : "Test"}
            </Button>
          </div>
          {dirty && saved ? (
            <p className="text-center text-xs text-muted-foreground">Save this role before testing its connection.</p>
          ) : null}
        </CardContent>
      </form>
    </Card>
  );
}

function CredentialBadge({
  draft,
  saved,
  providerChanged
}: {
  draft: RoleDraft;
  saved?: LLMRoleSettingResponse;
  providerChanged: boolean;
}) {
  if (draft.api_key) {
    return <Badge variant="blue">New key entered</Badge>;
  }

  if (providerChanged) {
    return <Badge variant="yellow">Unsaved provider</Badge>;
  }

  if (saved?.api_key_configured) {
    return (
      <Badge variant="green">
        <CheckCircle2 className="mr-1 h-3.5 w-3.5" aria-hidden="true" />
        Key configured
      </Badge>
    );
  }

  if (draft.provider === "local_openai_compatible") {
    return <Badge variant="slate">Key optional</Badge>;
  }

  return <Badge variant="orange">Key required</Badge>;
}

interface SettingsFieldProps {
  id: string;
  label: string;
  value: string;
  onChange: (value: string) => void;
  placeholder: string;
  hint: string;
  type?: "text" | "password" | "url";
  autoComplete?: string;
  required?: boolean;
}

function SettingsField({
  id,
  label,
  value,
  onChange,
  placeholder,
  hint,
  type = "text",
  autoComplete,
  required = false
}: SettingsFieldProps) {
  return (
    <div className="space-y-2">
      <label htmlFor={id} className="text-sm font-medium">
        {label}
      </label>
      <input
        id={id}
        type={type}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        autoComplete={autoComplete}
        required={required}
        spellCheck={false}
        aria-describedby={`${id}-hint`}
        className="h-12 w-full rounded-2xl border bg-background px-4 text-sm outline-none transition focus:border-primary focus:ring-2 focus:ring-ring/20"
      />
      <p id={`${id}-hint`} className="text-xs leading-5 text-muted-foreground">
        {hint}
      </p>
    </div>
  );
}

function connectionTestNotice(result: LLMConnectionTestResponse): RoleNotice {
  const latency = result.latency_ms === null ? "" : ` (${Math.round(result.latency_ms)} ms)`;

  return {
    kind: result.ok ? "success" : "error",
    message: `${result.message}${latency}`
  };
}
