const { LuaFactory } = require('wasmoon');
const path = require('path');
const fs = require('fs');

const VALID_PRESETS = ['Minify', 'Weak', 'Medium', 'Strong', 'Vmify'];
const VALID_LUA_VERSIONS = ['Lua51', 'LuaU'];
const MAX_CODE_BYTES = 512 * 1024;

// Load all .lua files from a directory tree, returning {relativePath: Buffer}
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

// Mount all Prometheus Lua sources into the wasmoon virtual filesystem once
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

// Wrapper script — reads source from a virtual file (avoids JS→Lua string
// encoding issues), bypasses prometheus.lua's debug.getinfo path setup.
const OBFUSCATE_LUA = `
-- config.lua iterates arg at load time; always force a real Lua table
arg = {}

package.path = "?.lua;" .. package.path

-- Lua 5.1 polyfills (prometheus.lua normally sets these, but we bypass it)
_G.newproxy = _G.newproxy or function(arg)
  if arg then return setmetatable({}, {}) end
  return {}
end

if not pcall(function() return math.random(1, 2^40) end) then
  local _r = math.random
  math.random = function(a, b)
    if not a and not b then return _r() end
    if not b then return math.random(1, a) end
    if a > b then a, b = b, a end
    local diff = b - a
    if diff > 2^31 - 1 then return math.floor(_r() * diff + a)
    else return _r(a, b) end
  end
end

-- Read source code from virtual file (set by JS before engine creation)
local f = assert(io.open(__src_file, "r"), "cannot open source file")
local sourceCode = f:read("*a")
f:close()

local Pipeline = require("prometheus.pipeline")
local Presets  = require("presets")

local presetConfig = Presets[__preset_name]
if not presetConfig then
  error("Unknown preset: " .. tostring(__preset_name))
end

-- deep-copy to avoid mutating the shared global preset table
local config = {}
for k, v in pairs(presetConfig) do config[k] = v end
config.LuaVersion = __lua_version

local pipeline = Pipeline:fromConfig(config)
return pipeline:apply(sourceCode, "input.lua")
`;

module.exports = async function handler(req, res) {
  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { code, preset, luaVersion } = req.body || {};

  if (!code || typeof code !== 'string') {
    return res.status(400).json({ error: 'Missing or invalid code' });
  }
  if (!VALID_PRESETS.includes(preset)) {
    return res.status(400).json({ error: `Invalid preset. Use one of: ${VALID_PRESETS.join(', ')}` });
  }
  if (luaVersion && !VALID_LUA_VERSIONS.includes(luaVersion)) {
    return res.status(400).json({ error: 'Invalid luaVersion. Use Lua51 or LuaU' });
  }
  if (Buffer.byteLength(code, 'utf8') > MAX_CODE_BYTES) {
    return res.status(400).json({ error: 'Code exceeds 512 KB limit' });
  }

  const startTime = Date.now();

  try {
    const factory = await getFactory();

    // Mount source code as a virtual file with a unique per-request name
    // so concurrent requests don't overwrite each other on the shared FS
    const srcFile = `__src_${Date.now()}_${Math.random().toString(36).slice(2, 8)}.lua`;
    await factory.mountFile(srcFile, Buffer.from(code, 'utf8'));

    const lua = await factory.createEngine();

    try {
      // Pass short safe strings as globals; source code goes via the virtual file
      lua.global.set('__src_file', srcFile);
      lua.global.set('__preset_name', preset);
      lua.global.set('__lua_version', luaVersion || 'Lua51');

      const obfuscated = await lua.doString(OBFUSCATE_LUA);

      if (typeof obfuscated !== 'string') {
        throw new Error('Obfuscation returned unexpected type: ' + typeof obfuscated);
      }

      return res.status(200).json({
        obfuscated,
        inputSize: Buffer.byteLength(code, 'utf8'),
        outputSize: Buffer.byteLength(obfuscated, 'utf8'),
        elapsedMs: Date.now() - startTime,
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
