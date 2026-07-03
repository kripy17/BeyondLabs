export const SECRET_RX: { type: string; re: RegExp }[] = [
  { type: "AWS Access Key", re: /AKIA[0-9A-Z]{16}\b/g },
  { type: "GitHub Token", re: /(?:ghp_|gho_|ghu_|ghs_|ghr_)[a-zA-Z0-9]{36}\b|github_pat_[a-zA-Z0-9_]{22,}\b/g },
  { type: "JWT Token", re: /eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g },
  { type: "Slack Token", re: /xox[baprs]-[a-zA-Z0-9-]{10,48}\b/g },
  { type: "Private Key", re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g },
  { type: "Discord Token", re: /[MN][a-zA-Z0-9_-]{23,25}\.[a-zA-Z0-9_-]{6,7}\.[a-zA-Z0-9_-]{27,}/g },
];

export const SUSPICIOUS_TLDS = new Set([
  "tk","ml","ga","cf","gq","xyz","top","download","review","work","date","men","loan","win","bid","cam",
  "click","quest","trade","webcam","science","party","gdn","racing","accountant","country","faith","online",
  "site","rest","cyou","bond","bar","club","kim","cfd","mom","link","tech","space","press","host","wiki",
  "ink","ru","cn",
]);

export const SHORTENERS = new Set([
  "bit.ly","tinyurl.com","ow.ly","is.gd","buff.ly","shorturl.at","cutt.ly","t.co","goo.gl","tiny.cc",
  "cli.gs","url.ie","rb.gy","short.link","shrten.com","v.gd","snipr.com","snipurl.com","surl.li",
  "lnkd.in","rebrandly","vur.me",
]);

export const LOLBINS = [
  "powershell","cmd.exe","wscript","cscript","mshta","regsvr32","rundll32","wmic","certutil","bitsadmin",
  "msiexec","scrcons","wshom.ocx","shell32",
];

export const DOWNLOAD_CRADLES = [
  "Invoke-WebRequest","iwr","wget","curl","Invoke-RestMethod","irm","Start-BitsTransfer",
  "bitsadmin /transfer","(new-object system.net.webclient).downloadstring",
  "(new-object system.net.webclient).downloadfile","System.Net.WebClient","XMLHttpRequest",
  "WinHttp.WinHttpRequest",
];

export const AMSI_BYPASS_PATTERNS = [
  "amsiutils","amsiinitfailed","system.management.automation.amsiutils","etw",
];
