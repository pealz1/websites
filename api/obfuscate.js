const { LuaFactory } = require('wasmoon');
const path = require('path');
const fs = require('fs');

const VALID_PRESETS = ['Minify', 'Weak', 'Medium', 'Strong', 'Vmify', 'Maximum'];
const VALID_LUA_VERSIONS = ['Lua51', 'LuaU'];
const MAX_CODE_BYTES = 512 * 1024;

function loadLuaFiles(dir, baseDir) {
  const result = {};
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    const rel = path.relative(baseDir, full).replace(/\\/g, '/');
    if (entry.isDirectory()) {
      Object.assign(result, loadLuaFiles(full, baseDir));
    } else if (entry.name.endsWith('.lua')) {
      result[rel] = fs.readFileSync(full);
    }
  }
  return result;
}

let factoryPromise = null;
function getFactory() {
  if (factoryPromise) return factoryPromise;
  factoryPromise = (async () => {
    const factory = new LuaFactory();
    const srcDir = path.join(process.cwd(), 'prometheus');
    const files = loadLuaFiles(srcDir, srcDir);
    for (const [rel, buf] of Object.entries(files)) {
      await factory.mountFile(rel, buf);
    }
    return factory;
  })();
  return factoryPromise;
}

const OBFUSCATE_LUA = `
arg = {}
package.path = "?.lua;" .. package.path
print = function() end

-- Lua 5.1 polyfills (prometheus.lua sets these, but we bypass it)
_G.newproxy = _G.newproxy or function(a)
  if a then return setmetatable({}, {}) end
  return {}
end

if not pcall(function() return math.random(1, 2^40) end) then
  local _r = math.random
  math.random = function(a, b)
    if not a and not b then return _r() end
    if not b then return math.random(1, a) end
    if a > b then a, b = b, a end
    local d = b - a
    if d > 2^31-1 then return math.floor(_r()*d+a) else return _r(a,b) end
  end
end

local f = assert(io.open(__src_file, "r"), "cannot open source file")
local sourceCode = f:read("*a")
f:close()

local Logger   = require("logger")
local Pipeline = require("prometheus.pipeline")
local Presets  = require("presets")

Logger.logLevel      = Logger.LogLevel.Error
Logger.logCallback   = function() end
Logger.warnCallback  = function() end
Logger.debugCallback = function() end

-- Deep-copy a preset config and fix known executor-breaking settings
local function makeConfig(presetName, luaVer)
  local src = Presets[presetName]
  if not src then error("Unknown preset: " .. tostring(presetName)) end
  local cfg = {}
  for k, v in pairs(src) do cfg[k] = v end
  cfg.LuaVersion = luaVer
  -- Deep-copy Steps so we never mutate the shared Presets table
  cfg.Steps = {}
  for i, step in ipairs(src.Steps or {}) do
    local s = { Name = step.Name, Settings = {} }
    for k, v in pairs(step.Settings or {}) do s.Settings[k] = v end
    -- AntiTamper with UseDebug=true breaks most executors (debug lib is restricted).
    -- Always force UseDebug=false so scripts actually run.
    if step.Name == "AntiTamper" then
      s.Settings.UseDebug = false
    end
    cfg.Steps[i] = s
  end
  return cfg
end

local function runPass(code, presetName, luaVer)
  local pipeline = Pipeline:fromConfig(makeConfig(presetName, luaVer))
  return pipeline:apply(code, "input.lua")
end

-- Post-processor: wrap the obfuscated output in a byte-rotation decoder.
-- Adds a custom layer that no existing Roblox deobfuscator targets.
-- Minify is excluded (it is meant to stay readable).
local function postProcess(code)
  local key = math.random(15, 240)
  local enc = {}
  for i = 1, #code do
    enc[i] = tostring((string.byte(code, i) + key) % 256)
  end
  -- Use hex-style names to blend with Prometheus output style
  local n1 = string.format("_0x%x", math.random(0x10000, 0xFFFFF))
  local n2 = string.format("_0x%x", math.random(0x10000, 0xFFFFF))
  local n3 = string.format("_0x%x", math.random(0x10000, 0xFFFFF))
  return string.format(
    "local %s={%s}local %s=%d for %s=1,#%s do %s[%s]=string.char((%s[%s]-%s)%%256)end;(loadstring or load)(table.concat(%s))()",
    n1, table.concat(enc, ","),
    n2, key,
    n3, n1, n1, n3, n1, n3, n2,
    n1
  )
end

-- Maximum: three-layer pipeline
--   Pass 1: Vmify         -> compiles to custom VM bytecode
--   Pass 2: custom steps  -> encrypts strings + constant array + number obf + wrap
--   Pass 3: post-process  -> byte-rotation loader (custom, no existing deobf targets it)
local MAXIMUM_PASS2 = {
  LuaVersion    = __lua_version,
  VarNamePrefix = "",
  NameGenerator = "MangledShuffled",
  PrettyPrint   = false,
  Seed          = 0,
  Steps = {
    { Name = "EncryptStrings",       Settings = {} },
    { Name = "ConstantArray",        Settings = { Treshold = 1, StringsOnly = false, Shuffle = true, Rotate = true, LocalWrapperTreshold = 0 } },
    { Name = "NumbersToExpressions", Settings = {} },
    { Name = "WrapInFunction",       Settings = {} },
  }
}

local result

if __preset_name == "Maximum" then
  local pass1 = runPass(sourceCode, "Vmify",  __lua_version)
  local pipeline2 = Pipeline:fromConfig(MAXIMUM_PASS2)
  local pass2 = pipeline2:apply(pass1, "input.lua")
  result = postProcess(pass2)
elseif __preset_name == "Minify" then
  result = runPass(sourceCode, "Minify", __lua_version)
else
  result = postProcess(runPass(sourceCode, __preset_name, __lua_version))
end

return result
`;

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
  if (Buffer.byteLength(code, 'utf8') > MAX_CODE_BYTES)
    return res.status(400).json({ error: 'Code exceeds 512 KB limit' });

  const startTime = Date.now();

  try {
    const factory = await getFactory();
    const srcFile = `__src_${Date.now()}_${Math.random().toString(36).slice(2, 8)}.lua`;
    await factory.mountFile(srcFile, Buffer.from(code, 'utf8'));
    const lua = await factory.createEngine();

    try {
      lua.global.set('__src_file',     srcFile);
      lua.global.set('__preset_name',  preset);
      lua.global.set('__lua_version',  luaVersion || 'Lua51');

      const obfuscated = await lua.doString(OBFUSCATE_LUA);

      if (typeof obfuscated !== 'string')
        throw new Error('Obfuscation returned unexpected type: ' + typeof obfuscated);

      return res.status(200).json({
        obfuscated,
        inputSize:  Buffer.byteLength(code,       'utf8'),
        outputSize: Buffer.byteLength(obfuscated, 'utf8'),
        elapsedMs:  Date.now() - startTime,
      });
    } finally {
      lua.global.close();
    }
  } catch (err) {
    console.error('Obfuscation error:', err);
    return res.status(500).json({
      error: err?.message?.replace(/\x1b\[[0-9;]*m/g, '') || 'Obfuscation failed',
    });
  }
};
