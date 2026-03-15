const { LuaFactory } = require('wasmoon');
const path = require('path');
const fs = require('fs');

const VALID_PRESETS = ['Minify', 'Weak', 'Medium', 'Strong', 'Vmify', 'Maximum'];
const VALID_LUA_VERSIONS = ['Lua51', 'LuaU'];
const MAX_CODE_BYTES = 2 * 1024 * 1024; // 2 MB — supports ~10 000+ line scripts

// ── Prometheus file loader ────────────────────────────────────────────────────
function loadLuaFiles(dir, baseDir) {
  const result = {};
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    const rel = path.relative(baseDir, full).replace(/\\/g, '/');
    if (entry.isDirectory()) Object.assign(result, loadLuaFiles(full, baseDir));
    else if (entry.name.endsWith('.lua')) result[rel] = fs.readFileSync(full);
  }
  return result;
}

let factoryPromise = null;
function getFactory() {
  if (factoryPromise) return factoryPromise;
  factoryPromise = (async () => {
    const factory = new LuaFactory();
    const srcDir = path.join(process.cwd(), 'prometheus');
    for (const [rel, buf] of Object.entries(loadLuaFiles(srcDir, srcDir))) {
      await factory.mountFile(rel, buf);
    }
    return factory;
  })();
  return factoryPromise;
}

// ── Post-processor (runs in Node.js — fast, no Lua overhead) ─────────────────
// Applies a random rotation cipher then base64-encodes the result.
// Output is a compact self-decoding Lua snippet (~33% size overhead vs ~300%
// for the old number-array approach), pure Lua 5.1 arithmetic, works on all
// executors. Minify is excluded (it's meant to stay readable/minimal).
function postProcess(code, preset) {
  if (preset === 'Minify') return code;

  const key = Math.floor(Math.random() * 226) + 15; // 15–240

  // Rotation-encode every byte
  const src = Buffer.from(code, 'utf8');
  const enc = Buffer.alloc(src.length);
  for (let i = 0; i < src.length; i++) enc[i] = (src[i] + key) % 256;
  const b64 = enc.toString('base64');

  // Random hex-style variable names to blend with Prometheus output
  const v = () => '_0x' + Math.floor(Math.random() * 0xFFFFF).toString(16).padStart(5, '0');
  const [vD, vA, vT, vI, vC, vO, vP, vN] = Array.from({ length: 8 }, v);

  // Compact pure-Lua-5.1 base64+rotation decoder
  return [
    `local ${vD}="${b64}"`,
    `local ${vA}="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"`,
    `local ${vT}={}`,
    `for ${vI}=1,#${vA} do ${vT}[${vA}:sub(${vI},${vI})]=${vI}-1 end`,
    `local ${vO},${vP},${vN}={},0,0`,
    `for ${vI}=1,#${vD} do`,
    `local ${vC}=${vT}[${vD}:sub(${vI},${vI})]`,
    `if ${vC} then ${vN}=${vN}*64+${vC} ${vP}=${vP}+6`,
    `if ${vP}>=8 then ${vP}=${vP}-8`,
    `${vO}[#${vO}+1]=string.char((math.floor(${vN}/2^${vP})%256-${key})%256) end`,
    `end end`,
    `(loadstring or load)(table.concat(${vO}))()`,
  ].join('\n');
}

// ── Lua obfuscation wrapper ───────────────────────────────────────────────────
// Runs inside wasmoon. Handles single-pass and Maximum multi-pass.
// Post-processing is intentionally NOT done here — it runs in Node.js above,
// which keeps the Lua script simple and avoids base64 overhead in wasmoon.
const OBFUSCATE_LUA = `
arg = {}
package.path = "?.lua;" .. package.path
print = function() end

-- Lua 5.1 polyfills (prometheus.lua sets these but we bypass that file)
_G.newproxy = _G.newproxy or function(a)
  if a then return setmetatable({},{}) end
  return {}
end
if not pcall(function() return math.random(1,2^40) end) then
  local _r=math.random
  math.random=function(a,b)
    if not a and not b then return _r() end
    if not b then return math.random(1,a) end
    if a>b then a,b=b,a end
    local d=b-a
    if d>2^31-1 then return math.floor(_r()*d+a) else return _r(a,b) end
  end
end

local f=assert(io.open(__src_file,"r"),"cannot open source file")
local sourceCode=f:read("*a")
f:close()

local Logger   = require("logger")
local Pipeline = require("prometheus.pipeline")
local Presets  = require("presets")

Logger.logLevel      = Logger.LogLevel.Error
Logger.logCallback   = function() end
Logger.warnCallback  = function() end
Logger.debugCallback = function() end

-- Deep-copy a preset config and fix executor-breaking settings
local function makeConfig(presetName, luaVer)
  local src=Presets[presetName]
  if not src then error("Unknown preset: "..tostring(presetName)) end
  local cfg={}
  for k,v in pairs(src) do cfg[k]=v end
  cfg.LuaVersion=luaVer
  cfg.Steps={}
  for i,step in ipairs(src.Steps or {}) do
    local s={Name=step.Name,Settings={}}
    for k,v in pairs(step.Settings or {}) do s.Settings[k]=v end
    -- AntiTamper with UseDebug=true fails in all executors (restricted debug lib)
    if step.Name=="AntiTamper" then s.Settings.UseDebug=false end
    cfg.Steps[i]=s
  end
  return cfg
end

local function runPass(code,presetName,luaVer)
  return Pipeline:fromConfig(makeConfig(presetName,luaVer)):apply(code,"input.lua")
end

-- Maximum: Vmify first, then encrypt/obfuscate the VM output
-- No AntiTamper in either pass — reliable on all executors
local MAX_PASS2={
  LuaVersion=__lua_version, VarNamePrefix="", NameGenerator="MangledShuffled",
  PrettyPrint=false, Seed=0,
  Steps={
    {Name="EncryptStrings",       Settings={}},
    {Name="ConstantArray",        Settings={Treshold=1,StringsOnly=false,Shuffle=true,Rotate=true,LocalWrapperTreshold=0}},
    {Name="NumbersToExpressions", Settings={}},
    {Name="WrapInFunction",       Settings={}},
  }
}

local result
if __preset_name=="Maximum" then
  local pass1=runPass(sourceCode,"Vmify",__lua_version)
  result=Pipeline:fromConfig(MAX_PASS2):apply(pass1,"input.lua")
else
  result=runPass(sourceCode,__preset_name,__lua_version)
end

return result
`;

// ── Handler ───────────────────────────────────────────────────────────────────
module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { code, preset, luaVersion } = req.body || {};

  if (!code || typeof code !== 'string')
    return res.status(400).json({ error: 'Missing or invalid code' });
  if (!VALID_PRESETS.includes(preset))
    return res.status(400).json({ error: `Invalid preset. Use one of: ${VALID_PRESETS.join(', ')}` });
  if (luaVersion && !VALID_LUA_VERSIONS.includes(luaVersion))
    return res.status(400).json({ error: 'Invalid luaVersion. Use Lua51 or LuaU' });

  const codeBytes = Buffer.byteLength(code, 'utf8');
  if (codeBytes > MAX_CODE_BYTES)
    return res.status(400).json({ error: `Code exceeds ${MAX_CODE_BYTES / 1024 / 1024} MB limit` });

  const startTime = Date.now();

  try {
    const factory = await getFactory();
    const srcFile = `__src_${Date.now()}_${Math.random().toString(36).slice(2, 8)}.lua`;
    await factory.mountFile(srcFile, Buffer.from(code, 'utf8'));
    const lua = await factory.createEngine();

    let obfuscated;
    try {
      lua.global.set('__src_file',    srcFile);
      lua.global.set('__preset_name', preset);
      lua.global.set('__lua_version', luaVersion || 'Lua51');

      const raw = await lua.doString(OBFUSCATE_LUA);
      if (typeof raw !== 'string')
        throw new Error('Obfuscation returned unexpected type: ' + typeof raw);

      // Post-process in Node.js (base64 + rotation cipher) — fast, no Lua overhead
      obfuscated = postProcess(raw, preset);
    } finally {
      lua.global.close();
    }

    return res.status(200).json({
      obfuscated,
      inputSize:  codeBytes,
      outputSize: Buffer.byteLength(obfuscated, 'utf8'),
      elapsedMs:  Date.now() - startTime,
    });
  } catch (err) {
    console.error('Obfuscation error:', err);
    return res.status(500).json({
      error: err?.message?.replace(/\x1b\[[0-9;]*m/g, '') || 'Obfuscation failed',
    });
  }
};
