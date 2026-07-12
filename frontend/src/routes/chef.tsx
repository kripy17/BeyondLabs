import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useEffect, useRef, useState } from "react";
import { PageShell } from "@/components/PageShell";
import { takePendingArtifact } from "@/lib/handoff";
import {
  ChefHat, Search, Star, X, GripVertical, Copy, Check, Eraser, Trash2,
  ArrowDown, ArrowUp, RotateCcw, FileDown, BookMarked,
  Clock, ArrowDownToLine, ArrowUpFromLine, Settings2, Upload, Download, Send, AlertTriangle,
  WrapText,
} from "lucide-react";
import OPS, { OP_BY_ID, DEFAULT_FAVS, CATEGORIES, type Op, type Cat, type RecipeStep } from "@/lib/chef-ops";

export const Route = createFileRoute("/chef")({ component: ChefPage });

const PRESETS: { id: string; steps: RecipeStep[]; sample?: string }[] = [];

function createStep(opId: string, opts: Record<string, any> = {}): RecipeStep {
  return { id: crypto.randomUUID(), operationId: opId, options: opts };
}
function stepOptions(step: RecipeStep) { return step.options || {}; }
function serializeRecipe(r: RecipeStep[]) { return r.map((s) => ({ operationId: s.operationId, options: s.options })); }
function normalizeRecipeItems(arr: any[]): RecipeStep[] {
  if (!Array.isArray(arr)) return [];
  return arr.map((item) => {
    const opId = typeof item === "string" ? item : item?.operationId || item?.id || item?.operation;
    if (!OP_BY_ID[opId]) return null;
    return createStep(opId, typeof item === "string" ? {} : item?.options || {});
  }).filter(Boolean) as RecipeStep[];
}

/* ── OpItem component ── */
function OpItem({ op, isFav, onAdd, onFav }: { op: Op; isFav: boolean; onAdd: (id: string) => void; onFav: (id: string) => void }) {
  return (
    <div className="group flex items-stretch gap-0.5">
      <button
        onClick={() => onAdd(op.id)}
        title={op.description}
        draggable
        onDragStart={(e) => { e.dataTransfer.setData("text/op-id", op.id); e.dataTransfer.effectAllowed = "copy"; }}
        className="flex-1 cursor-grab rounded-md border border-transparent px-2.5 py-1.5 text-left transition-colors hover:border-primary/30 hover:bg-primary/[0.04] active:bg-primary/[0.08]"
      >
        <div className="flex items-center justify-between gap-2">
          <span className={"truncate text-mono ba-text-base leading-tight " + (isFav ? "text-warning" : "text-foreground/90")}>{op.label}</span>
          <span className="shrink-0 rounded border border-border/50 px-1.5 py-0.5 ba-text-3xs uppercase tracking-[0.12em] text-muted-foreground/60 group-hover:text-muted-foreground/90">{op.category}</span>
        </div>
        <div className="mt-0.5 line-clamp-1 text-mono text-[10.5px] leading-snug text-muted-foreground/70 group-hover:text-muted-foreground/90">{op.description}</div>
      </button>
      <button
        onClick={() => onFav(op.id)}
        title={isFav ? "Unfavourite" : "Favourite"}
        className="flex items-center px-1.5 text-muted-foreground/40 opacity-0 transition-opacity hover:text-warning group-hover:opacity-100"
      >
        <Star className={"h-3.5 w-3.5 " + (isFav ? "fill-warning text-warning opacity-100" : "")} />
      </button>
    </div>
  );
}

/* =================== Component =================== */

const FAVS_KEY = "beyondlabs.chefFavs";
const RECIPE_KEY = "beyondlabs.chefRecipe";
const LIBRARY_KEY = "beyondlabs.chefLibrary";

type SavedBake = { id: string; name: string; recipe: { operationId: string; options: Record<string, any> }[]; ts: number };

function ChefPage() {
  const navigate = useNavigate();
  const [input, setInput] = useState("");
  const [recipe, setRecipe] = useState<RecipeStep[]>([]);
  const [output, setOutput] = useState<string>("");
  const [error, setError] = useState<string>("");
  const [notice, setNotice] = useState("");
  const [query, setQuery] = useState("");
  const [favs, setFavs] = useState<string[]>(DEFAULT_FAVS);
  const [copied, setCopied] = useState(false);
  const [dragIdx, setDragIdx] = useState<number | null>(null);
  const [library, setLibrary] = useState<SavedBake[]>([]);
  const [showLibrary, setShowLibrary] = useState(false);
  const [expandedStep, setExpandedStep] = useState<number | null>(null);
  const [inputFileName, setInputFileName] = useState("");
  const [inputDrag, setInputDrag] = useState(false);
  const [secretScanOpen, setSecretScanOpen] = useState(false);
  const [autoBake, setAutoBake] = useState(true);
  const [baking, setBaking] = useState(false);
  const [wordWrap, setWordWrap] = useState(true);
  const [outputSig, setOutputSig] = useState("");
  const [stepOutputs, setStepOutputs] = useState<{label: string; output: string; status: string}[]>([]);
  const [stepDetailsOpen, setStepDetailsOpen] = useState(false);
  const [showMoreMenu, setShowMoreMenu] = useState(false);
  const [showSendMenu, setShowSendMenu] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const outputStale = !autoBake && !!output && outputSig !== input + recipe.map((s) => s.operationId).join(",");

  // Hydrate persisted state + inbound handoff
  useEffect(() => {
    try {
      const f = localStorage.getItem(FAVS_KEY); if (f) setFavs(JSON.parse(f));
      const r = localStorage.getItem(RECIPE_KEY); if (r) setRecipe(normalizeRecipeItems(JSON.parse(r)));
      const l = localStorage.getItem(LIBRARY_KEY); if (l) setLibrary(JSON.parse(l));
    } catch {}
    const pending = takePendingArtifact();
    if (pending?.value) setInput(pending.value);
  }, []);

  // Persist favourites + recipe + library
  useEffect(() => { try { localStorage.setItem(FAVS_KEY, JSON.stringify(favs)); } catch {} }, [favs]);
  useEffect(() => { try { localStorage.setItem(RECIPE_KEY, JSON.stringify(serializeRecipe(recipe))); } catch {} }, [recipe]);
  useEffect(() => { try { localStorage.setItem(LIBRARY_KEY, JSON.stringify(library)); } catch {} }, [library]);

  // Auto-bake pipeline
  useEffect(() => {
    if (!autoBake) return;
    let cancelled = false;
    (async () => {
      try {
        let acc: string = input;
        const steps: {label: string; output: string; status: string}[] = [];
        for (const step of recipe) {
          if (cancelled) return;
          const op = OP_BY_ID[step.operationId];
          if (!op) continue;
          acc = await op.run(acc, step.options);
          if (!cancelled) steps.push({label: op.label, output: acc, status: "success"});
        }
        if (!cancelled) { setOutput(acc); setOutputSig(input + recipe.map((s) => s.operationId).join(",")); setError(""); setStepOutputs(steps); setNotice(""); }
      } catch (e: any) {
        if (!cancelled) {
          const msg = e?.message ?? "pipeline error";
          setStepOutputs((s) => [...s, {label: "error", output: msg, status: "failed"}]);
          setError(msg);
        }
      }
    })();
    return () => { cancelled = true; };
  }, [input, recipe, autoBake]);

  const manualBake = () => {
    if (!input || !recipe.length) return;
    setBaking(true);
    setStepOutputs([]);
    (async () => {
      try {
        let acc = input;
        const steps: {label: string; output: string; status: string}[] = [];
        for (const step of recipe) {
          const op = OP_BY_ID[step.operationId];
          if (!op) continue;
          acc = await op.run(acc, step.options);
          steps.push({label: op.label, output: acc, status: "success"});
        }
        setOutput(acc); setOutputSig(input + recipe.map((s) => s.operationId).join(",")); setError(""); setStepOutputs(steps); setNotice("");
      } catch (e: any) {
        const msg = e?.message ?? "pipeline error";
        setStepOutputs((s) => [...s, {label: "error", output: msg, status: "failed"}]);
        setError(msg);
      } finally { setBaking(false); }
    })();
  };

  const addStep = (id: string) => setRecipe((r) => [...r, createStep(id)]);
  const removeStep = (i: number) => setRecipe((r) => r.filter((_, idx) => idx !== i));
  const toggleFav = (id: string) => setFavs((f) => f.includes(id) ? f.filter((x) => x !== id) : [...f, id]);

  const recipePanelRef = useRef<HTMLDivElement>(null);
  const onDragStart = (i: number) => setDragIdx(i);
  const onDragOver = (e: React.DragEvent, over: number) => {
    e.preventDefault();
    if (dragIdx === null || dragIdx === over) return;
    setRecipe((r) => {
      const copy = r.slice();
      const [m] = copy.splice(dragIdx, 1);
      copy.splice(over, 0, m);
      setDragIdx(over);
      return copy;
    });
  };
  const onRecipeDragEnd = (e: React.DragEvent) => {
    const panel = recipePanelRef.current;
    if (dragIdx !== null && panel && !panel.contains(e.relatedTarget as Node) && !panel.contains(e.target as Node)) {
      setRecipe((r) => r.filter((_, i) => i !== dragIdx));
    }
    setDragIdx(null);
  };

  const copy = () => { navigator.clipboard.writeText(output); setCopied(true); setTimeout(() => setCopied(false), 1200); };
  const copyMarkdownSummary = () => {
    const steps = recipe.map((s, i) => `${i + 1}. ${OP_BY_ID[s.operationId]?.label ?? s.operationId}`).join("\n");
    const iocLines = (() => {
      const iocRx = { "URLs": /\bhttps?:\/\/[^\s"'<>]+/g, "IPs": /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g, "Emails": /\b[\w.+-]+@[\w.-]+\.\w{2,}\b/g, "Domains": /\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b/g, "Hashes": /\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b/g };
      return Object.entries(iocRx).map(([k, rx]) => {
        const matches = output.match(rx); const u = matches ? [...new Set(matches)].length : 0;
        return u > 0 ? `- ${k}: ${u}` : null;
      }).filter(Boolean).join("\n");
    })();
    const md = `# CyberChef Transform Summary\n\n**Recipe**\n${steps}\n\n**Output**\n- Characters: ${Array.from(output).length}\n- Lines: ${output.split(/\r?\n/).length}\n${iocLines ? `\n**Indicators**\n${iocLines}` : ""}\n\n_Generated by BeyondLabs CyberChef_`;
    navigator.clipboard.writeText(md); setNotice("Markdown summary copied"); setTimeout(() => setNotice(""), 1500);
  };

  const loadPreset = (idOrSteps: string | RecipeStep[]) => {
    if (Array.isArray(idOrSteps)) { setRecipe(idOrSteps as RecipeStep[]); return; }
    const preset = PRESETS.find((p) => p.id === idOrSteps);
    if (!preset) { setRecipe([createStep(idOrSteps)]); return; }
    setRecipe(normalizeRecipeItems(preset.steps));
    if (preset.sample) setInput(preset.sample);
  };
  const clearAll = () => { setRecipe([]); setInput(""); setOutput(""); setError(""); setNotice(""); };
  const saveBake = () => {
    const blob = new Blob([JSON.stringify({ input, recipe: serializeRecipe(recipe), output }, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a"); a.href = url; a.download = `chef-bake-${Date.now()}.json`; a.click(); URL.revokeObjectURL(url);
  };
  const importRecipe = (file: File) => {
    const reader = new FileReader();
    reader.onload = () => {
      try {
        const data = JSON.parse(reader.result as string);
        const steps = data.recipe || data.steps || [];
        if (Array.isArray(steps) && steps.length) {
          setRecipe(normalizeRecipeItems(steps));
          if (data.input) setInput(data.input);
          setNotice(`Recipe imported (${steps.length} steps)`);
        }
      } catch { setNotice("Invalid recipe file"); }
    };
    reader.readAsText(file);
  };
  const saveToLibrary = () => {
    if (!recipe.length) return;
    const name = window.prompt("Name this recipe:", recipe.map((s) => OP_BY_ID[s.operationId]?.label ?? s.operationId).slice(0, 3).join(" → "));
    if (!name) return;
    setLibrary((l) => [{ id: crypto.randomUUID(), name, recipe: serializeRecipe(recipe), ts: Date.now() }, ...l].slice(0, 20));
    setNotice(`Saved "${name}" to library`);
  };

  const loadSample = () => {
    const first = recipe[0];
    const op = first ? OP_BY_ID[first.operationId] : null;
    if (op?.placeholder) setInput(op.placeholder);
    else setInput("https://example.com/login?user=test\n8.8.8.8\nuser@example.com");
  };
  const loadFile = (file: File | null) => {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => { setInput(reader.result as string); setInputFileName(file.name); };
    reader.readAsText(file);
  };
  const HANDOFF_TARGETS: Record<string, { label: string; page: string }> = {
    parser: { label: "Investigation", page: "/parser" },
    phishing: { label: "Phishing Triage", page: "/phishing" },
    recon: { label: "Recon & Exposure", page: "/recon" },
    detection: { label: "Detection & MITRE", page: "/detection" },
    logs: { label: "Logs & Alerts", page: "/logs" },
  };
  const sendOutputTo = (target: string) => {
    const route = HANDOFF_TARGETS[target];
    if (!route || !output) return;
    try {
      localStorage.setItem("beyondlabs.pendingArtifact", JSON.stringify({ target: route.page.replace("/", ""), value: output, source: "CyberChef", type: "transform" }));
      navigate({ to: route.page });
    } catch {}
  };

  const moveStep = (i: number, dir: -1 | 1) => {
    const j = i + dir;
    if (j < 0 || j >= recipe.length) return;
    setRecipe((r) => { const c = r.slice(); [c[i], c[j]] = [c[j], c[i]]; return c; });
  };
  const duplicateStep = (i: number) => setRecipe((r) => { const c = r.slice(); c.splice(i + 1, 0, createStep(r[i].operationId, r[i].options)); return c; });
  const updateStepOpts = (i: number, opts: Record<string, any>) => setRecipe((r) => { const c = r.slice(); c[i] = { ...c[i], options: { ...c[i].options, ...opts } }; return c; });

  function StepOptionsForm({ idx, opId }: { idx: number; opId: string }) {
    const step = recipe[idx];
    const opts = step?.options || {};
    const toggle = (k: string) => updateStepOpts(idx, { [k]: !opts[k] });
    const set = (k: string, v: any) => updateStepOpts(idx, { [k]: v });
    const li = "flex items-center gap-1.5 text-mono ba-text-2xs text-muted-foreground";
    if (opId === "to-hex") return (
      <div className="mt-2 grid grid-cols-3 gap-2 text-mono ba-text-2xs text-muted-foreground">
        <label>Delimiter <select value={opts.delimiter ?? ""} onChange={(e) => set("delimiter", e.target.value)} className="mt-0.5 w-full rounded border border-divider-strong bg-background/60 px-1 py-0.5 ba-text-2xs"><option value="">None</option><option value=" ">Space</option><option value=":">Colon</option><option value="none">None</option></select></label>
        <label>Case <select value={opts.case ?? "lower"} onChange={(e) => set("case", e.target.value)} className="mt-0.5 w-full rounded border border-divider-strong bg-background/60 px-1 py-0.5 ba-text-2xs"><option value="lower">lower</option><option value="upper">UPPER</option></select></label>
        <label>Prefix <select value={opts.prefix ?? ""} onChange={(e) => set("prefix", e.target.value)} className="mt-0.5 w-full rounded border border-divider-strong bg-background/60 px-1 py-0.5 ba-text-2xs"><option value="">None</option><option value="0x">0x</option></select></label>
      </div>
    );
    if (opId === "to-base64") return (
      <div className="mt-2 flex flex-wrap gap-3 text-mono ba-text-2xs text-muted-foreground">
        <label>Alphabet <select value={opts.alphabet ?? "standard"} onChange={(e) => set("alphabet", e.target.value)} className="rounded border border-divider-strong bg-background/60 px-1 py-0.5 ba-text-2xs"><option value="standard">Standard</option><option value="urlsafe">URL-safe</option></select></label>
        <label>Padding <select value={opts.padding ?? true} onChange={(e) => set("padding", e.target.value === "true")} className="rounded border border-divider-strong bg-background/60 px-1 py-0.5 ba-text-2xs"><option value="true">Yes</option><option value="false">No</option></select></label>
        <label>Line length <input type="number" min={0} max={256} value={opts.lineLength ?? 0} onChange={(e) => set("lineLength", Number(e.target.value) || 0)} className="w-14 rounded border border-divider-strong bg-background/60 px-1 py-0.5 ba-text-2xs" /></label>
      </div>
    );
    if (opId === "from-base64") return (
      <div className="mt-2 flex flex-wrap gap-3 text-mono ba-text-2xs text-muted-foreground">
        <label className={li}><input type="checkbox" checked={!!opts.keepWhitespace} onChange={() => toggle("keepWhitespace")} /> Keep whitespace</label>
      </div>
    );
    if (opId === "to-binary") return (
      <div className="mt-2 text-mono ba-text-2xs text-muted-foreground">
        <label>Delimiter <select value={opts.delimiter ?? " "} onChange={(e) => set("delimiter", e.target.value)} className="ml-1 rounded border border-divider-strong bg-background/60 px-1 py-0.5 ba-text-2xs"><option value=" ">Space</option><option value="none">None</option><option value="newline">New line</option></select></label>
      </div>
    );
    if (["to-charcode", "from-charcode"].includes(opId)) return (
      <div className="mt-2 flex flex-wrap gap-3 text-mono ba-text-2xs text-muted-foreground">
        <label>Base <select value={opts.base ?? 10} onChange={(e) => set("base", Number(e.target.value))} className="rounded border border-divider-strong bg-background/60 px-1 py-0.5 ba-text-2xs"><option value={10}>Decimal</option><option value={16}>Hex</option></select></label>
        <label>Delimiter <select value={opts.delimiter ?? " "} onChange={(e) => set("delimiter", e.target.value)} className="rounded border border-divider-strong bg-background/60 px-1 py-0.5 ba-text-2xs"><option value=" ">Space</option><option value=",">Comma</option><option value="\n">New line</option></select></label>
      </div>
    );
    if (opId === "rot13") return (
      <label className="mt-2 block text-mono ba-text-2xs text-muted-foreground">Rotation <input type="number" min={1} max={25} value={opts.rotation ?? 13} onChange={(e) => set("rotation", Number(e.target.value))} className="ml-1 w-14 rounded border border-divider-strong bg-background/60 px-1 py-0.5 ba-text-2xs" /></label>
    );
    if (opId === "unicode-escape") return (
      <div className="mt-2 flex flex-wrap gap-3 text-mono ba-text-2xs text-muted-foreground">
        <label className={li}><input type="checkbox" checked={!!opts.allChars} onChange={() => toggle("allChars")} /> All characters</label>
        <label className={li}><input type="checkbox" checked={!!opts.uppercase} onChange={() => toggle("uppercase")} /> Uppercase hex</label>
      </div>
    );
    if (["sort-lines", "unique-lines"].includes(opId)) return (
      <div className="mt-2 flex flex-wrap gap-3 text-mono ba-text-2xs text-muted-foreground">
        <label className={li}><input type="checkbox" checked={!!opts.caseSensitive} onChange={() => toggle("caseSensitive")} /> Case sensitive</label>
        {opId === "sort-lines" && <label className={li}><input type="checkbox" checked={!!opts.reverse} onChange={() => toggle("reverse")} /> Reverse</label>}
      </div>
    );
    if (["sha1", "sha256", "sha384", "sha512"].includes(opId)) return (
      <label className="mt-2 block text-mono ba-text-2xs text-muted-foreground">Case <select value={opts.case ?? "lower"} onChange={(e) => set("case", e.target.value)} className="ml-1 rounded border border-divider-strong bg-background/60 px-1 py-0.5 ba-text-2xs"><option value="lower">lower</option><option value="upper">UPPER</option></select></label>
    );
    if (opId === "extract-iocs") return (
      <div className="mt-2 flex flex-wrap gap-2 text-mono ba-text-2xs text-muted-foreground">
        {["urls","ips","emails","domains","hashes"].map((t) => {
          const inc = opts.include ?? ["urls","ips","emails","domains","hashes"];
          return <label key={t} className={li}><input type="checkbox" checked={inc.includes(t)} onChange={() => { const cur = opts.include ?? ["urls","ips","emails","domains","hashes"]; set("include", cur.includes(t) ? cur.filter((x: string) => x !== t) : [...cur, t]); }} /> {t}</label>;
        })}
      </div>
    );
    if (opId === "regex-extract") return (
      <div className="mt-2 flex flex-wrap gap-2 text-mono ba-text-2xs text-muted-foreground">
        {["ipv4","urls","emails","hashes","cves","event_ids"].map((t) => {
          const types = opts.types ?? ["ipv4","urls","emails","hashes","cves","event_ids"];
          return <label key={t} className={li}><input type="checkbox" checked={types.includes(t)} onChange={() => { const cur = opts.types ?? ["ipv4","urls","emails","hashes","cves","event_ids"]; set("types", cur.includes(t) ? cur.filter((x: string) => x !== t) : [...cur, t]); }} /> {t}</label>;
        })}
      </div>
    );
    if (opId === "regex-redact") return (
      <label className="mt-2 block text-mono ba-text-2xs text-muted-foreground">Replacement <input type="text" value={opts.replacement ?? "[REDACTED]"} onChange={(e) => set("replacement", e.target.value)} className="ml-1 w-24 rounded border border-divider-strong bg-background/60 px-1 py-0.5 ba-text-2xs" /></label>
    );
    return null;
  }

  return (
    <PageShell
      title="CyberChef"
      description="Encode, decode, extract, hash — all local."
      actions={
        <div className="flex items-center gap-1.5">
          <div className="relative">
            <button onClick={() => setShowLibrary((v) => !v)} className="inline-flex items-center gap-1 rounded-md border border-divider-strong bg-background/60 px-2.5 py-1 text-mono ba-text-sm text-muted-foreground hover:text-foreground">
              <BookMarked className="h-3.5 w-3.5" /> {library.length}
            </button>
            {showLibrary && (
              <div className="absolute right-0 z-20 mt-1 w-72 rounded-md border border-border bg-card elevation-raised">
                <div className="border-b border-divider-strong px-2 py-1.5 text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground">saved recipes</div>
                {library.length === 0 ? (
                  <div className="px-3 py-3 text-mono ba-text-sm text-muted-foreground">No saved recipes yet.</div>
                ) : (
                  <ul className="max-h-64 overflow-y-auto py-1">
                    {library.map((b) => (
                      <li key={b.id} className="group flex items-center gap-1 px-2 py-1 hover:bg-primary/5">
                        <button onClick={() => { setRecipe(normalizeRecipeItems(b.recipe)); setShowLibrary(false); setNotice("Recipe loaded from library"); }} className="min-w-0 flex-1 text-left">
                          <div className="truncate text-mono text-[11.5px] text-foreground/90">{b.name}</div>
                          <div className="truncate text-mono ba-text-2xs text-muted-foreground">{b.recipe.length} steps · {new Date(b.ts).toLocaleDateString()}</div>
                        </button>
                        <button onClick={() => setLibrary((l) => l.filter((x) => x.id !== b.id))} aria-label="Remove" className="opacity-0 group-hover:opacity-100 text-muted-foreground hover:text-destructive"><X className="h-3 w-3" /></button>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            )}
          </div>
          <button onClick={saveToLibrary} disabled={!recipe.length} className="inline-flex items-center gap-1 rounded-md border border-divider-strong bg-background/60 px-2 py-1 text-mono ba-text-2xs text-muted-foreground hover:text-foreground disabled:opacity-40"><Star className="h-3 w-3" /> save</button>
          <button onClick={clearAll} className="inline-flex items-center gap-1 rounded-md border border-divider-strong bg-background/60 px-2 py-1 text-mono ba-text-2xs text-muted-foreground hover:text-foreground"><Eraser className="h-3 w-3" /> clear</button>
          <button onClick={saveBake} className="inline-flex items-center gap-1 rounded-md border border-divider-strong bg-background/60 px-2 py-1 text-mono ba-text-2xs text-muted-foreground hover:text-foreground"><FileDown className="h-3 w-3" /> export</button>
          <label className="inline-flex cursor-pointer items-center gap-1 rounded-md border border-divider-strong bg-background/60 px-2 py-1 text-mono ba-text-2xs text-muted-foreground hover:text-foreground">
            <Upload className="h-3 w-3" /> import
            <input type="file" accept=".json" onChange={(e) => { const f = e.target.files?.[0]; if (f) { importRecipe(f); e.target.value = ""; } }} className="hidden" />
          </label>
        </div>
      }
    >
      {notice && (
        <div className="mb-3 rounded border border-info/40 bg-info/10 px-3 py-1.5 text-mono text-[10.5px] text-info transition-opacity">
          {notice}
          <button onClick={() => setNotice("")} aria-label="Dismiss" className="ml-2 inline text-muted-foreground hover:text-foreground"><X className="inline h-3 w-3" /></button>
        </div>
      )}

      {/* 3-pane layout: Operations | Recipe | Input/Output */}
      <div className="flex gap-3" style={{ height: "calc(100vh - 310px)" }}>

        {/* PANE 1 — Operations (CyberChef style) */}
        <aside className="flex w-[240px] shrink-0 flex-col overflow-hidden rounded-md border border-border bg-card/40">
          <div className="border-b border-divider-strong px-2.5 py-2">
            <div className="flex items-center gap-1.5">
              <ChefHat className="h-3.5 w-3.5 text-primary" />
              <span className="text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground">operations</span>
              <span className="ml-auto text-mono ba-text-2xs text-muted-foreground/70">{OPS.length}</span>
            </div>
            <div className="mt-2 flex items-center gap-1.5 rounded-md border border-divider-strong bg-background/60 px-2">
              <Search className="h-3 w-3 shrink-0 text-muted-foreground/70" />
              <input autoFocus value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search operations…" className="flex-1 bg-transparent py-1 text-mono ba-text-sm outline-none placeholder:text-muted-foreground/50" />
            </div>
          </div>
          <div className="flex-1 overflow-y-auto p-1.5">
            {(() => {
              const q = query.trim().toLowerCase();
              if (q) {
                const flat = OPS.filter((o) => o.label.toLowerCase().includes(q) || o.description.toLowerCase().includes(q));
                if (!flat.length) return <div className="flex items-center justify-center p-6 text-center text-mono ba-text-sm text-muted-foreground/60">No matching operations</div>;
                return (
                  <div className="space-y-0.5">
                    <div className="mb-1.5 px-2 py-1 text-mono ba-text-3xs uppercase tracking-[0.2em] text-muted-foreground/50">results · {flat.length}</div>
                    {flat.map((op) => (
                      <OpItem key={op.id} op={op} isFav={favs.includes(op.id)} onAdd={addStep} onFav={toggleFav} />
                    ))}
                  </div>
                );
              }
              return CATEGORIES.map((cat) => {
                const catOps = OPS.filter((o) => o.category === cat.id);
                if (!catOps.length) return null;
                return (
                  <div key={cat.id} className="mb-3">
                    <div className="flex items-center gap-2 px-2 py-1">
                      <span className="text-mono ba-text-2xs font-bold uppercase tracking-[0.18em] text-foreground/70">{cat.label}</span>
                      <span className="text-mono ba-text-3xs text-muted-foreground/40">{catOps.length}</span>
                    </div>
                    <div className="space-y-0.5">
                      {catOps.map((op) => {
                        const isFav = favs.includes(op.id);
                        return (
                          <OpItem key={op.id} op={op} isFav={isFav} onAdd={addStep} onFav={toggleFav} />
                        );
                      })}
                    </div>
                  </div>
                );
              });
            })()}
          </div>
        </aside>

        {/* PANE 2 — Recipe */}
        <section
          ref={recipePanelRef}
          className="flex w-[260px] shrink-0 min-h-0 flex-col overflow-hidden rounded-md border border-border bg-card/40"
          onDragOver={(e) => { if (e.dataTransfer.types.includes("text/op-id")) { e.preventDefault(); e.dataTransfer.dropEffect = "copy"; } }}
          onDrop={(e) => {
            const id = e.dataTransfer.getData("text/op-id");
            if (id && OP_BY_ID[id]) { e.preventDefault(); addStep(id); }
          }}
          onDragEnd={onRecipeDragEnd}
        >
            <div className="border-b border-divider-strong px-3 py-1.5">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="grid h-4 w-4 place-items-center rounded-sm border border-warning/40 bg-warning/10 text-warning"><Clock className="h-2.5 w-2.5" strokeWidth={2.5} /></span>
                  <span className="text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground">recipe</span>
                </div>
                <div className="flex items-center gap-1">
                  <button
                    onClick={() => setAutoBake((v) => !v)}
                    className={"inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-mono ba-text-3xs uppercase tracking-widest " + (autoBake ? "bg-success/15 text-success" : "bg-muted/40 text-muted-foreground")}
                    title="Toggle automatic baking"
                  >
                    auto {autoBake ? "on" : "off"}
                  </button>
                  <button onClick={() => { try { localStorage.setItem("beyondlabs.chefRecipeSaved", JSON.stringify(serializeRecipe(recipe))); setNotice("Recipe saved to browser"); } catch {} }} disabled={!recipe.length} className="inline-flex items-center gap-1 text-mono ba-text-3xs uppercase tracking-widest text-muted-foreground hover:text-primary disabled:opacity-30" title="Save recipe to browser">save</button>
                  <button onClick={() => { try { const r = localStorage.getItem("beyondlabs.chefRecipeSaved"); if (r) setRecipe(normalizeRecipeItems(JSON.parse(r))); } catch {} }} className="inline-flex items-center gap-1 text-mono ba-text-3xs uppercase tracking-widest text-muted-foreground hover:text-primary" title="Load saved recipe from browser">load</button>
                  {recipe.length > 0 && (
                    <button onClick={() => setRecipe([])} className="inline-flex items-center gap-1 text-mono ba-text-3xs uppercase tracking-widest text-muted-foreground hover:text-destructive">
                      <Trash2 className="h-3 w-3" /> clr
                    </button>
                  )}
                </div>
              </div>
              <div className="mt-1 text-mono ba-text-2xs text-muted-foreground/70 truncate">{recipe.length ? recipe.map((s) => OP_BY_ID[s.operationId]?.label ?? s.operationId).join(" → ") : "Double-click or drag operations to build a pipeline"}</div>
            </div>
          <div className="flex-1 overflow-y-auto p-2">
            {recipe.length === 0 ? (
              <div className="grid h-full place-items-center rounded border border-dashed border-divider-strong px-3 py-6 text-center">
                <div className="flex flex-col items-center gap-2">
                  <ChefHat className="h-8 w-8 text-muted-foreground/40" />
                  <div className="text-mono ba-text-sm text-muted-foreground">No recipe steps added</div>
                  <div className="text-mono ba-text-2xs text-muted-foreground/70">Double-click an operation or drag it here to build a pipeline.</div>
                </div>
              </div>
            ) : (
              <div className="space-y-2">
                {recipe.map((step, i) => {
                  const op = OP_BY_ID[step.operationId];
                  return (
                    <div
                      key={step.id}
                      draggable
                      onDragStart={() => onDragStart(i)}
                      onDragOver={(e) => onDragOver(e, i)}
                      className={"rounded-lg border bg-card/50 p-2.5 transition " + (dragIdx === i ? "border-primary/60 opacity-60" : "border-divider-strong hover:border-primary/40")}
                    >
                      <div className="flex items-start justify-between gap-2">
                        <div className="min-w-0 flex-1">
                          <div className="flex items-center gap-2">
                            <GripVertical className="h-3.5 w-3.5 shrink-0 cursor-grab text-muted-foreground" />
                            <span className="grid h-5 w-5 shrink-0 place-items-center rounded border border-border/50 bg-primary/10 text-mono ba-text-3xs font-bold text-primary">{i + 1}</span>
                            <span className="truncate text-mono ba-text-base font-semibold text-foreground/90">{op?.label ?? step.operationId}</span>
                          </div>
                          <p className="ml-7 mt-0.5 truncate text-mono ba-text-2xs text-muted-foreground">{op?.description ?? op?.category ?? "—"}</p>
                        </div>
                        <button onClick={() => removeStep(i)} title="Remove" aria-label="Remove step" className="shrink-0 rounded p-1 text-muted-foreground hover:bg-destructive/10 hover:text-destructive"><X className="h-3.5 w-3.5" /></button>
                      </div>
                      <div className="ml-7 mt-2 flex flex-wrap items-center gap-1.5">
                        <button onClick={() => moveStep(i, -1)} disabled={i === 0} title="Move up" className="rounded border border-border/50 bg-background/40 px-1.5 py-0.5 text-mono ba-text-3xs text-muted-foreground hover:text-primary disabled:opacity-30"><ArrowUp className="mr-0.5 inline h-3 w-3" />up</button>
                        <button onClick={() => moveStep(i, 1)} disabled={i === recipe.length - 1} title="Move down" className="rounded border border-border/50 bg-background/40 px-1.5 py-0.5 text-mono ba-text-3xs text-muted-foreground hover:text-primary disabled:opacity-30"><ArrowDown className="mr-0.5 inline h-3 w-3" />down</button>
                        <button onClick={() => duplicateStep(i)} title="Duplicate" className="rounded border border-border/50 bg-background/40 px-1.5 py-0.5 text-mono ba-text-3xs text-muted-foreground hover:text-primary"><Copy className="mr-0.5 inline h-3 w-3" />dup</button>
                        <button onClick={() => setExpandedStep(expandedStep === i ? null : i)} title="Options" className={"rounded border px-1.5 py-0.5 text-mono ba-text-3xs " + (expandedStep === i ? "border-primary/40 bg-primary/10 text-primary" : "border-border/50 bg-background/40 text-muted-foreground hover:text-primary")}><Settings2 className="mr-0.5 inline h-3 w-3" />opts</button>
                      </div>
                      {expandedStep === i && (
                        <div className="ml-7 mt-2 border-t border-divider-soft pt-2">
                          <StepOptionsForm idx={i} opId={step.operationId} />
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
          {/* recipe stats footer + bake button */}
          <div className="border-t border-divider-strong">
            <div className="flex items-center justify-between px-3 py-2">
              <div className="flex items-center gap-3 text-mono ba-text-2xs text-muted-foreground">
                <span>{recipe.length} step{recipe.length === 1 ? "" : "s"}</span>
                <span className={"flex items-center gap-1 " + (autoBake ? "text-success" : "text-muted-foreground/60")}>
                  <span className={"inline-block h-1.5 w-1.5 rounded-full " + (autoBake ? "bg-success" : "bg-muted-foreground/40")} />
                  {autoBake ? "auto" : "manual"}
                </span>
                <span>{error ? "halted" : output ? "baked" : "idle"}</span>
              </div>
              {recipe.length > 0 && !autoBake && (
                <button onClick={manualBake} disabled={baking} className="inline-flex items-center gap-1.5 rounded-md border border-primary/50 bg-primary/15 px-3 py-1 text-mono ba-text-sm font-semibold uppercase tracking-widest text-primary transition-colors hover:bg-primary/25 disabled:opacity-40">
                  <ChefHat className="h-4 w-4" /> {baking ? "..." : "Bake!"}
                </button>
              )}
              {recipe.length > 0 && autoBake && (
                <span className="inline-flex items-center gap-1.5 rounded-md border border-success/30 bg-success/10 px-2 py-1 text-mono ba-text-2xs text-success">
                  <ChefHat className="h-3.5 w-3.5" /> auto-baking
                </span>
              )}
            </div>
          </div>
        </section>

        {/* PANE 3 — Input + Output stacked */}
        <div className="grid grid-rows-2 min-h-0 gap-3">
          {/* Input */}
          <section
            className={"flex min-h-0 flex-col overflow-hidden rounded-md border bg-card/40 transition-colors " + (inputDrag ? "border-primary/60 bg-primary/5" : "border-border")}
            onDragOver={(e) => { e.preventDefault(); setInputDrag(true); }}
            onDragLeave={() => setInputDrag(false)}
            onDrop={(e) => { e.preventDefault(); setInputDrag(false); const f = e.dataTransfer.files?.[0]; if (f) loadFile(f); }}
          >
            <div className="flex items-center justify-between border-b border-divider-strong px-3 py-1.5">
              <div className="flex items-center gap-2">
                <span className="grid h-4 w-4 place-items-center rounded-sm border border-primary/40 bg-primary/10 text-primary"><ArrowDownToLine className="h-2.5 w-2.5" strokeWidth={2.5} /></span>
                <span className="text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground">input</span>
                {inputFileName && <span className="truncate text-mono ba-text-3xs text-muted-foreground/70 max-w-[120px]" title={inputFileName}>{inputFileName}</span>}
              </div>
              <div className="flex items-center gap-1.5 text-mono ba-text-2xs text-muted-foreground">
                <span>{input.length} chars</span>
                <span>·</span>
                <span>{input.split(/\r?\n/).length} lines</span>
                <button onClick={loadSample} title="Load sample input" className="rounded border border-border bg-background/60 px-1.5 py-0.5 uppercase tracking-widest hover:border-primary/40 hover:text-primary">sample</button>
                <button onClick={() => inputRef.current?.click()} title="Open file" aria-label="Open file" className="rounded border border-border bg-background/60 px-1.5 py-0.5 uppercase tracking-widest hover:border-primary/40 hover:text-primary"><Upload className="h-3 w-3" /></button>
                <input ref={inputRef} type="file" onChange={(e) => loadFile(e.target.files?.[0] ?? null)} className="hidden" />
                <button onClick={() => setInput("")} title="Clear input" aria-label="Clear input" className="rounded border border-border bg-background/60 px-1.5 py-0.5 uppercase tracking-widest hover:border-destructive/50 hover:text-destructive">
                  <Eraser className="h-3 w-3" />
                </button>
              </div>
            </div>
            <textarea
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder={recipe.length ? OP_BY_ID[recipe[0].operationId]?.placeholder ?? "Paste input here…" : "Paste input here, or drag a file."}
              className="flex-1 resize-none bg-transparent p-3 text-mono ba-text-base leading-relaxed text-foreground outline-none placeholder:text-muted-foreground/50"
              spellCheck={false}
            />
          </section>

          {/* Output */}
          <section className="flex min-h-0 flex-col overflow-hidden rounded-md border border-border bg-card/40">
            <div className="flex items-center justify-between border-b border-divider-strong px-3 py-1.5">
              <div className="flex items-center gap-2">
                <span className="grid h-4 w-4 place-items-center rounded-sm border border-success/40 bg-success/10 text-success"><ArrowUpFromLine className="h-2.5 w-2.5" strokeWidth={2.5} /></span>
                <span className="text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground">output</span>
                {error && <span className="rounded border border-destructive/50 bg-destructive/10 px-1.5 py-0.5 text-mono text-[9.5px] uppercase tracking-widest text-destructive">error</span>}
                {outputStale && <span className="rounded border border-warning/50 bg-warning/10 px-1.5 py-0.5 text-mono text-[9.5px] text-warning">stale</span>}
                <button onClick={() => setWordWrap((v) => !v)} className="rounded border border-border bg-background/60 px-1.5 py-0.5 text-mono ba-text-2xs text-muted-foreground hover:border-primary/40 hover:text-primary" title="Toggle word wrap">
                  <WrapText className={`h-3 w-3 ${wordWrap ? "" : "opacity-40"}`} />
                </button>
              </div>
              <div className="flex items-center gap-1.5 text-mono ba-text-2xs text-muted-foreground">
                {(input && !autoBake && (input || recipe.length)) && (
                  <button onClick={manualBake} disabled={baking} className="inline-flex items-center gap-1 rounded border border-primary/30 bg-primary/10 px-2 py-0.5 uppercase tracking-widest text-primary hover:bg-primary/20 disabled:opacity-50" title="Run pipeline manually">
                    {baking ? "..." : "run"}
                  </button>
                )}
                <span>{output.length} chars</span>
                <span>·</span>
                <span>{output.split(/\r?\n/).length} lines</span>
                <button onClick={copy} className="rounded border border-border bg-background/60 px-1.5 py-0.5 uppercase tracking-widest hover:border-primary/40 hover:text-primary">
                  {copied ? <><Check className="h-3 w-3" /></> : <><Copy className="h-3 w-3" /></>}
                </button>
                <button onClick={() => setInput(output)} title="Swap output → input" className="rounded border border-border bg-background/60 px-1.5 py-0.5 uppercase tracking-widest hover:border-primary/40 hover:text-primary">
                  <RotateCcw className="h-3 w-3" />
                </button>
                {/* More dropdown */}
                <div className="relative">
                  <button onClick={() => { setShowMoreMenu(v => !v); setShowSendMenu(false); }} className="rounded border border-border bg-background/60 px-1.5 py-0.5 uppercase tracking-widest hover:border-primary/40 hover:text-primary">more</button>
                  {showMoreMenu && (
                    <>
                      <div className="fixed inset-0 z-10" onClick={() => setShowMoreMenu(false)} />
                      <div className="absolute right-0 z-20 mt-1 w-48 rounded-md border border-border bg-card py-1 elevation-raised">
                        <button onClick={() => { setInput(output); setOutput(""); setShowMoreMenu(false); }} className="flex w-full items-center gap-2 px-3 py-1.5 text-left text-mono ba-text-sm text-foreground/80 hover:bg-primary/5"><RotateCcw className="h-3 w-3" /> Swap I/O</button>
                        <button onClick={() => { const b = new Blob([output], { type: "text/plain" }); const u = URL.createObjectURL(b); const a = document.createElement("a"); a.href = u; a.download = "chef-output.txt"; a.click(); URL.revokeObjectURL(u); setShowMoreMenu(false); }} className="flex w-full items-center gap-2 px-3 py-1.5 text-left text-mono ba-text-sm text-foreground/80 hover:bg-primary/5"><Download className="h-3 w-3" /> Download</button>
                        <button onClick={() => { copyMarkdownSummary(); setShowMoreMenu(false); }} className="flex w-full items-center gap-2 px-3 py-1.5 text-left text-mono ba-text-sm text-foreground/80 hover:bg-primary/5"><Copy className="h-3 w-3" /> Copy md summary</button>
                        <button onClick={() => { setOutput(""); setShowMoreMenu(false); }} className="flex w-full items-center gap-2 px-3 py-1.5 text-left text-mono ba-text-sm text-foreground/80 hover:bg-primary/5"><Eraser className="h-3 w-3" /> Clear</button>
                      </div>
                    </>
                  )}
                </div>
                {/* Send to dropdown */}
                {output && (
                  <div className="relative">
                    <button onClick={() => { setShowSendMenu(v => !v); setShowMoreMenu(false); }} aria-label="send output" className="rounded border border-border bg-background/60 px-1.5 py-0.5 uppercase tracking-widest hover:border-primary/40 hover:text-primary"><Send className="h-3 w-3" /></button>
                    {showSendMenu && (
                      <>
                        <div className="fixed inset-0 z-10" onClick={() => setShowSendMenu(false)} />
                        <div className="absolute right-0 z-20 mt-1 w-48 rounded-md border border-border bg-card py-1 elevation-raised">
                          {Object.entries(HANDOFF_TARGETS).map(([k, v]) => (
                            <button key={k} onClick={() => { sendOutputTo(k); setShowSendMenu(false); }} className="flex w-full items-center gap-2 px-3 py-1.5 text-left text-mono ba-text-sm text-foreground/80 hover:bg-primary/5"><Send className="h-3 w-3" /> {v.label}</button>
                          ))}
                        </div>
                      </>
                    )}
                  </div>
                )}
              </div>
            </div>
            {error ? (
              <pre className={"flex-1 overflow-auto p-3 text-mono ba-text-base text-destructive " + (wordWrap ? "whitespace-pre-wrap break-words" : "whitespace-pre")}>{error}</pre>
            ) : output ? (
              <pre className={"flex-1 overflow-auto p-3 text-mono ba-text-base leading-relaxed text-foreground " + (wordWrap ? "whitespace-pre-wrap break-words" : "whitespace-pre")}>{output}</pre>
            ) : (
              <div className="grid flex-1 place-items-center p-6 text-center">
                <div>
                  <div className="text-mono ba-text-sm text-muted-foreground">{recipe.length ? "Type or paste input." : "Add a recipe step, then paste input."}</div>
                  <div className="mt-1 text-mono ba-text-2xs text-muted-foreground/70">Everything runs locally in your browser.</div>
                </div>
              </div>
            )}
            {/* IOC summary */}
            {output && !error && (() => {
              const iocRx = { "URLs": /\bhttps?:\/\/[^\s"'<>]+/g, "IPs": /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g, "Emails": /\b[\w.+-]+@[\w.-]+\.\w{2,}\b/g, "Domains": /\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b/g };
              const counts = Object.entries(iocRx).map(([k, rx]) => {
                const matches = output.match(rx);
                const unique = matches ? [...new Set(matches)].length : 0;
                return unique > 0 ? `${k}:${unique}` : null;
              }).filter(Boolean);
              return counts.length > 0 ? (
                <div className="border-t border-divider-strong px-3 py-1 text-mono ba-text-2xs text-muted-foreground">
                  IOC: {counts.join(" · ")}
                </div>
              ) : null;
            })()}
            {/* Transformation summary */}
            {output && !error && (
              <div className="border-t border-divider-strong px-3 py-1 text-mono ba-text-2xs text-muted-foreground">
                {recipe.map((s) => OP_BY_ID[s.operationId]?.label ?? s.operationId).join(" → ") || "passthrough"}
              </div>
            )}
            {/* Step outputs */}
            {stepOutputs.length > 0 && (
              <div className="border-t border-divider-strong">
                <button
                  onClick={() => setStepDetailsOpen((v) => !v)}
                  className="flex w-full items-center gap-1.5 px-3 py-1 text-left text-mono ba-text-2xs text-muted-foreground hover:text-foreground"
                >
                  Step outputs ({stepOutputs.length}) {stepDetailsOpen ? "▲" : "▼"}
                </button>
                {stepDetailsOpen && (
                  <div className="max-h-36 overflow-y-auto border-t border-divider-soft">
                    {stepOutputs.map((s, i) => (
                      <div key={i} className={"border-b border-divider-soft px-3 py-1.5 last:border-0 " + (s.status === "failed" ? "bg-destructive/5" : "")}>
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-mono ba-text-2xs font-bold text-foreground/80">{i + 1}. {s.label}</span>
                          <span className={"text-mono ba-text-3xs uppercase tracking-widest " + (s.status === "failed" ? "text-destructive" : "text-success")}>{s.status}</span>
                        </div>
                        <pre className="mt-1 max-h-20 overflow-auto whitespace-pre-wrap break-all rounded bg-background/60 p-1.5 text-mono ba-text-2xs text-foreground/70">{s.output}</pre>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
            {/* Secret scan collapsible */}
            {output && !error && (() => {
              const lines = output.split(/\r?\n/);
              const rules: { name: string; rx: RegExp }[] = [
                { name: "AWS key", rx: /\bAKIA[0-9A-Z]{16}\b/ },
                { name: "GitHub token", rx: /\bghp_[A-Za-z0-9]{20,}\b/ },
                { name: "Stripe key", rx: /\bsk_(live|test)_[A-Za-z0-9]{16,}\b/ },
                { name: "Private key PEM", rx: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/ },
                { name: ".env assign", rx: /^[A-Z][A-Z0-9_]+=[\S]+$/ },
              ];
              const hits: string[] = [];
              lines.forEach((l, i) => rules.forEach((r) => { if (r.rx.test(l)) hits.push(`L${i+1} [${r.name}]`); }));
              return hits.length > 0 ? (
                <div className="border-t border-divider-strong">
                  <button onClick={() => setSecretScanOpen((v) => !v)} className="flex w-full items-center gap-1.5 px-3 py-1 text-left text-mono ba-text-2xs text-muted-foreground hover:text-warning">
                    <AlertTriangle className="h-3 w-3 text-warning" /> {hits.length} potential secret{hits.length === 1 ? "" : "s"} {secretScanOpen ? "▲" : "▼"}
                  </button>
                  {secretScanOpen && (
                    <div className="max-h-24 overflow-y-auto border-t border-divider-soft px-3 py-1 text-mono ba-text-2xs text-muted-foreground">
                      {hits.map((h, i) => <div key={i}>{h}</div>)}
                    </div>
                  )}
                </div>
              ) : null;
            })()}
            <div className="flex items-center justify-between border-t border-divider-strong px-3 py-1 text-mono ba-text-2xs text-muted-foreground">
              <span>{recipe.length} op{recipe.length === 1 ? "" : "s"} · local</span>
              <span>{error ? "halted" : output ? "baked" : "idle"}</span>
            </div>
          </section>
        </div>
      </div>
    </PageShell>
  );
}
