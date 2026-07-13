declare module "@/api/backend" {
  export const safeAnalyzeUrl: (payload: Record<string, unknown>) => Promise<Record<string, unknown>>;
  export const parseLogs: (text: string) => Promise<Record<string, unknown>>;
  export const runReconNmapScan: (opts: { target: string; mode: string; confirmPermission: boolean; allowPrivate?: boolean; signal?: AbortSignal }) => Promise<Record<string, unknown>>;
  export const analyzeFullEmail: (headers: string, body: string, refangFirst?: boolean) => Promise<Record<string, unknown>>;
  export const passiveRecon: (target: string, fetchOptions?: Record<string, unknown>) => Promise<Record<string, unknown>>;
  export const analyzeSiemText: (text: string) => Promise<Record<string, unknown>>;
  export const getHackingtoolCategories: () => Promise<Record<string, unknown>>;
  export const runHackingtoolTool: (opts: { categoryId: string; toolId: string; target: string; args: string; signal?: AbortSignal }) => Promise<Record<string, unknown>>;
  export const emailOsint: (email: string) => Promise<Record<string, unknown>>;
  export const socialLinksFinder: (website: string) => Promise<Record<string, unknown>>;
  export const usernameOsint: (username: string) => Promise<Record<string, unknown>>;
  export const getLocalOsintTools: () => Promise<Record<string, unknown>>;
  export const runLocalOsintTool: (opts: { toolId: string; domain: string; source: string; limit: number }) => Promise<Record<string, unknown>>;
  export const runTheHarvester: (opts: { domain: string; source: string; limit: number; confirmPermission: boolean }) => Promise<Record<string, unknown>>;
  export const runMaigret: (username: string) => Promise<Record<string, unknown>>;
  export const uploadMalwareFile: (file: File) => Promise<Record<string, unknown>>;
}
declare module "@/api/detection" {
  export const mapMitre: (text: string) => Promise<Record<string, unknown>>;
  export const generateSigmaRule: (title: string, description: string, severity: string, logsourceType: string | null) => Promise<Record<string, unknown>>;
  export const getIdsRuleTemplates: () => Promise<Record<string, unknown>>;
  export const buildIdsRule: (payload: Record<string, unknown>) => Promise<Record<string, unknown>>;
  export const explainIdsRule: (rule: string) => Promise<Record<string, unknown>>;
}
