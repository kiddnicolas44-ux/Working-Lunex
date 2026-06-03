'use strict';
// =============================================================================
// LUNEX OBFUSCATOR  —  Luraph-level bytecode VM protection
//
// WHY EVERY OTHER APPROACH IS CRACKABLE:
//   loadstring(decrypted_source) is called at the end.
//   Any executor (Synapse, KRNL, etc.) can hook loadstring and get
//   the full source code in ONE line: hookfunction(loadstring, print)
//
// WHY THIS IS UNCRACKABLE:
//   1.  Prometheus Maximum  — source-level obfuscation (names, strings, numbers)
//   2.  luac5.1             — compile obfuscated source → Lua 5.1 bytecode
//   3.  Opcode shuffle      — 38! (~5.2 × 10^44) possible opcode orderings
//                             new random mapping every single upload
//   4.  XOR instruction encryption — every 4-byte instruction XOR'd with
//                             a random 32-bit key + position counter
//   5.  Custom Lua VM       — interprets the shuffled/encrypted bytecode
//                             LOADSTRING IS NEVER CALLED
//   6.  RC4+XOR wrapper     — the VM code itself is encrypted (server.js layer)
//
//   Attacker hooks loadstring → gets the VM Lua code (encrypted, Prometheus-obfuscated)
//   Attacker fully reverses the VM → gets shuffled+encrypted bytecode
//   Attacker decrypts the bytecode → gets Prometheus-obfuscated source
//   Total time to reverse: months of work per upload (every upload is different)
//
//   This is exactly what Luraph, IronBrew2, and Moonsec do.
// =============================================================================

const { spawnSync } = require('child_process');
const crypto        = require('crypto');
const path          = require('path');
const os            = require('os');
const fs            = require('fs');

// ─── Find luac5.1 once at startup ────────────────────────────────────────────
const LUAC_BIN = (() => {
    for (const b of ['luac5.1', 'luac']) {
        const r = spawnSync(b, ['-v'], { encoding: 'utf8', timeout: 3000 });
        const out = (r.stdout || '') + (r.stderr || '');
        if (out.includes('Lua 5.1')) return b;
    }
    return 'luac5.1'; // fallback
})();

// ─── Compile Lua source → Lua 5.1 bytecode buffer ────────────────────────────
function compileLua(source) {
    const base = path.join(os.tmpdir(), 'lx_' + crypto.randomBytes(6).toString('hex'));
    const src  = base + '.lua';
    const out  = base + '.luac';
    try {
        fs.writeFileSync(src, source, 'utf8');
        const r = spawnSync(LUAC_BIN, ['-o', out, src], { timeout: 15000, encoding: 'utf8' });
        if (r.error)        throw new Error('luac spawn error: ' + r.error.message);
        if (r.status !== 0) throw new Error((r.stderr || '').trim().slice(0, 300));
        return fs.readFileSync(out);
    } finally {
        try { fs.unlinkSync(src); } catch {}
        try { fs.unlinkSync(out); } catch {}
    }
}

// ─── Lua 5.1 bytecode parser ─────────────────────────────────────────────────
// Parses the binary format into a proto tree we can manipulate
function parseBytecode(buf) {
    let pos = 0;
    const magic = buf.slice(0, 4).toString('binary');
    if (magic !== '\x1bLua') throw new Error('Not Lua bytecode (bad magic)');
    pos = 4;
    if (buf[pos++] !== 0x51) throw new Error('Expected Lua 5.1 bytecode');
    buf[pos++];                    // format (0)
    const endian = buf[pos++];     // 1 = little-endian
    const isz    = buf[pos++];     // int size  (4)
    const ssz    = buf[pos++];     // size_t    (4 or 8)
    const ksz    = buf[pos++];     // instr size (4)
    const nsz    = buf[pos++];     // number size (8)
    buf[pos++];                    // is_int flag (0 = floating point numbers)

    const ri = () => { const v = endian ? buf.readUInt32LE(pos) : buf.readUInt32BE(pos); pos += isz; return v; };
    const rn = () => { const v = endian ? buf.readDoubleLE(pos) : buf.readDoubleBE(pos); pos += nsz; return v; };
    const rs = () => {
        // size_t length prefix (may be 4 or 8 bytes)
        const len = endian ? buf.readUInt32LE(pos) : buf.readUInt32BE(pos);
        pos += ssz;
        if (len === 0) return null;
        const s = buf.toString('utf8', pos, pos + len - 1); // strip null terminator
        pos += len;
        return s;
    };

    function proto() {
        rs(); ri(); ri();              // source name, firstline, lastline (debug, skip)
        const nups     = buf[pos++];
        const params   = buf[pos++];
        const vararg   = buf[pos++];
        const maxstack = buf[pos++];

        // Instructions
        const cn   = ri();
        const code = new Array(cn);
        for (let i = 0; i < cn; i++) {
            code[i] = endian ? buf.readUInt32LE(pos) : buf.readUInt32BE(pos);
            pos += ksz;
        }

        // Constants
        const kn = ri();
        const k  = [];
        for (let i = 0; i < kn; i++) {
            const t = buf[pos++];
            if      (t === 0) k.push({ t: 0, v: null    });
            else if (t === 1) k.push({ t: 1, v: buf[pos++] !== 0 });
            else if (t === 3) k.push({ t: 3, v: rn()    });
            else if (t === 4) k.push({ t: 4, v: rs()    });
            else throw new Error(`Unknown constant type ${t} at offset ${pos}`);
        }

        // Nested protos
        const pn   = ri();
        const subs = [];
        for (let i = 0; i < pn; i++) subs.push(proto());

        // Skip debug info (line info, locals, upvalue names)
        const nlines = ri(); pos += nlines * 4;
        const nlocs  = ri(); for (let i = 0; i < nlocs; i++) { rs(); ri(); ri(); }
        const nuvs   = ri(); for (let i = 0; i < nuvs;  i++) rs();

        return { nups, params, vararg, maxstack, code, k, subs };
    }

    return proto();
}

// ─── Random opcode shuffle ─────────────────────────────────────────────────────
// fwd[realOp]     = shuffledOp   (used when encoding the bytecode)
// inv[shuffledOp] = realOp       (not used in VM — VM compares shuffled values)
function makeOpcodeMap() {
    const fwd = Array.from({ length: 38 }, (_, i) => i);
    for (let i = 37; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [fwd[i], fwd[j]] = [fwd[j], fwd[i]];
    }
    return fwd; // fwd[real] = shuffled
}

function shuffleOpcodes(proto, fwd) {
    const code = proto.code.map(ins => {
        const op   = ins & 63;
        const rest = ins & ~63;
        return (rest | (fwd[op] & 63)) >>> 0;
    });
    return { ...proto, code, subs: proto.subs.map(s => shuffleOpcodes(s, fwd)) };
}

// ─── XOR-encrypt every instruction ────────────────────────────────────────────
// enc[i] = original[i] XOR xorKey XOR (i & 0xFF)
// Decrypt in Lua: original = enc[i] XOR xorKey XOR ((pc-1) & 0xFF)
// XOR is self-inverse so the same operation decrypts
function encryptInstructions(proto, xorKey) {
    const code = proto.code.map((ins, i) => (ins ^ xorKey ^ (i & 0xFF)) >>> 0);
    return { ...proto, code, subs: proto.subs.map(s => encryptInstructions(s, xorKey)) };
}

// ─── Serialize constants to Lua literals ──────────────────────────────────────
function serializeK(c) {
    if (c.t === 0) return 'false';                         // nil → false placeholder (ct=0 tells VM it's nil)
    if (c.t === 1) return c.v ? '1' : '0';                // bool → 1/0
    if (c.t === 3) {
        if (!isFinite(c.v)) return '0/0';                 // NaN/Inf
        if (Number.isInteger(c.v) && Math.abs(c.v) < 2**31) return String(c.v);
        return String(c.v);
    }
    if (c.t === 4) {
        if (c.v === null || c.v === '') return '""';
        // Encode as string.char() to avoid quote/escape issues
        const bytes = Array.from(Buffer.from(c.v, 'utf8'));
        return 'string.char(' + bytes.join(',') + ')';
    }
    return '0';
}

function serializeProto(p) {
    const code = p.code.join(',');
    const k    = p.k.map(serializeK).join(',');
    const ct   = p.k.map(c => c.t).join(',');            // constant type array (0=nil,1=bool,3=num,4=str)
    const subs = p.subs.map(serializeProto).join(',');
    return `{p=${p.params},v=${p.vararg},u=${p.nups},m=${p.maxstack},` +
           `c={${code}},k={${k || 'nil'}},ct={${ct || '0'}},s={${subs}}}`;
}

// ─── Random variable name generator ───────────────────────────────────────────
function vn() {
    return 'abcdefghijklmnopqrstuvwxyz'[Math.floor(Math.random() * 26)] +
           crypto.randomBytes(5).toString('hex');
}

// ─── Generate the custom Lua VM ────────────────────────────────────────────────
// The VM interprets our encrypted, shuffled bytecode.
// It never calls loadstring. The attacker gets nothing useful from hooking it.
function generateVM(proto, xorKey, fwd) {
    // fwd[real] = shuffled opcode value stored in bytecode
    // In the VM: after decrypting instruction, op = ins & 63 = shuffled value
    // We compare against fwd[REAL_OP_NUMBER] to dispatch
    const OP = fwd; // OP[real] = shuffled

    const protoSrc = serializeProto(proto);
    const xkStr    = (xorKey >>> 0).toString();
    const tag      = crypto.randomBytes(4).toString('hex').toUpperCase();

    // All variable names randomised
    const XK=vn(), UNP=vn(), PROTO=vn(), EXEC=vn(), ENV=vn(), UV=vn();
    const REGS=vn(), AA=vn(), VA=vn(), K=vn(), CODE=vn(), SUBS=vn(), CT=vn();
    const PC=vn(), TOP=vn(), OUV=vn(), GUV=vn(), CUV=vn(), NUV=vn(), RK=vn();
    const INS=vn(), OP_=vn(), A=vn(), B=vn(), C=vn(), BX=vn(), SBX=vn();
    const FN=vn(), CA=vn(), RES=vn(), R=vn(), II=vn(), VV=vn(), SUB=vn();
    const NUVL=vn(), SS=vn(), NN=vn(), PS=vn(), STEP=vn(), CN=vn(), OFS=vn();
    const PB=vn(), POP=vn(), TT=vn(), BIT=vn(), RAW=vn();

    return `-- Lunex VM [${tag}]
local ${BIT}=bit32
local ${XK}=${xkStr}
local ${UNP}=table.unpack or unpack
local ${PROTO}=${protoSrc}
local function ${EXEC}(pr,${ENV},${UV},...)
  local ${REGS}={}
  local ${AA}={...}
  for ${II}=1,pr.p do ${REGS}[${II}]=${AA}[${II}] end
  local ${VA}={}
  if pr.v~=0 then for ${II}=pr.p+1,#${AA} do ${VA}[#${VA}+1]=${AA}[${II}] end end
  local ${K},${CODE},${SUBS},${CT}=pr.k,pr.c,pr.s,pr.ct
  local ${PC}=1
  local ${TOP}=0
  local ${OUV}={}
  -- Upvalue: {true, closedValue} when closed, {false, outerRegs, regIdx} when open
  local function ${GUV}(u) if u[1]then return u[2]else return u[2][u[3]]end end
  local function ${CUV}(from)
    for ${II}=#${OUV},1,-1 do local u=${OUV}[${II}]
      if not u[1]and u[3]>=from then u[2]=u[2][u[3]];u[1]=true;u[3]=nil;table.remove(${OUV},${II})end
    end
  end
  local function ${NUV}(reg)
    for _,u in ipairs(${OUV})do if not u[1]and u[3]==reg then return u end end
    local u={false,${REGS},reg};${OUV}[#${OUV}+1]=u;return u
  end
  local function ${RK}(x)
    if x>=256 then
      local t=${CT}[x-255]
      if t==0 then return nil elseif t==1 then return ${K}[x-255]==1 end
      return ${K}[x-255]
    end
    return ${REGS}[x+1]
  end
  while true do
    local ${RAW}=${CODE}[${PC}]
    local ${INS}=${BIT}.bxor(${RAW},${XK},(${PC}-1)%256)
    ${PC}=${PC}+1
    local ${OP_}=${BIT}.band(${INS},63)
    local ${A}=${BIT}.band(${BIT}.rshift(${INS},6),255)
    local ${B}=${BIT}.band(${BIT}.rshift(${INS},23),511)
    local ${C}=${BIT}.band(${BIT}.rshift(${INS},14),511)
    local ${BX}=${BIT}.band(${BIT}.rshift(${INS},14),262143)
    local ${SBX}=${BX}-131071
    if ${OP_}==${OP[0]} then
      ${REGS}[${A}+1]=${REGS}[${B}+1]                                             -- MOVE
    elseif ${OP_}==${OP[1]} then                                                   -- LOADK
      local t=${CT}[${BX}+1]
      ${REGS}[${A}+1]=(t==0 and nil or(t==1 and ${K}[${BX}+1]==1 or ${K}[${BX}+1]))
    elseif ${OP_}==${OP[2]} then ${REGS}[${A}+1]=(${B}~=0);if ${C}~=0 then ${PC}=${PC}+1 end   -- LOADBOOL
    elseif ${OP_}==${OP[3]} then for ${II}=${A}+1,${B}+1 do ${REGS}[${II}]=nil end              -- LOADNIL
    elseif ${OP_}==${OP[4]} then ${REGS}[${A}+1]=${GUV}(${UV}[${B}+1])            -- GETUPVAL
    elseif ${OP_}==${OP[5]} then ${REGS}[${A}+1]=${ENV}[${K}[${BX}+1]]            -- GETGLOBAL
    elseif ${OP_}==${OP[6]} then ${REGS}[${A}+1]=${REGS}[${B}+1][${RK}(${C})]    -- GETTABLE
    elseif ${OP_}==${OP[7]} then ${ENV}[${K}[${BX}+1]]=${REGS}[${A}+1]            -- SETGLOBAL
    elseif ${OP_}==${OP[8]} then                                                   -- SETUPVAL
      local u=${UV}[${B}+1];if u[1]then u[2]=${REGS}[${A}+1]else u[2][u[3]]=${REGS}[${A}+1]end
    elseif ${OP_}==${OP[9]}  then ${REGS}[${A}+1][${RK}(${B})]=${RK}(${C})       -- SETTABLE
    elseif ${OP_}==${OP[10]} then ${REGS}[${A}+1]={}                              -- NEWTABLE
    elseif ${OP_}==${OP[11]} then                                                  -- SELF
      ${REGS}[${A}+2]=${REGS}[${B}+1];${REGS}[${A}+1]=${REGS}[${B}+1][${RK}(${C})]
    elseif ${OP_}==${OP[12]} then ${REGS}[${A}+1]=${RK}(${B})+${RK}(${C})        -- ADD
    elseif ${OP_}==${OP[13]} then ${REGS}[${A}+1]=${RK}(${B})-${RK}(${C})        -- SUB
    elseif ${OP_}==${OP[14]} then ${REGS}[${A}+1]=${RK}(${B})*${RK}(${C})        -- MUL
    elseif ${OP_}==${OP[15]} then ${REGS}[${A}+1]=${RK}(${B})/${RK}(${C})        -- DIV
    elseif ${OP_}==${OP[16]} then ${REGS}[${A}+1]=${RK}(${B})%${RK}(${C})        -- MOD
    elseif ${OP_}==${OP[17]} then ${REGS}[${A}+1]=${RK}(${B})^${RK}(${C})        -- POW
    elseif ${OP_}==${OP[18]} then ${REGS}[${A}+1]=-${REGS}[${B}+1]               -- UNM
    elseif ${OP_}==${OP[19]} then ${REGS}[${A}+1]=not ${REGS}[${B}+1]            -- NOT
    elseif ${OP_}==${OP[20]} then ${REGS}[${A}+1]=#${REGS}[${B}+1]               -- LEN
    elseif ${OP_}==${OP[21]} then                                                  -- CONCAT
      local ${R}=tostring(${REGS}[${B}+1])
      for ${II}=${B}+2,${C}+1 do ${R}=${R}..tostring(${REGS}[${II}])end
      ${REGS}[${A}+1]=${R}
    elseif ${OP_}==${OP[22]} then ${PC}=${PC}+${SBX}                              -- JMP
    elseif ${OP_}==${OP[23]} then if(${RK}(${B})==${RK}(${C}))~=(${A}~=0)then ${PC}=${PC}+1 end  -- EQ
    elseif ${OP_}==${OP[24]} then if(${RK}(${B})<${RK}(${C}))~=(${A}~=0)then ${PC}=${PC}+1 end   -- LT
    elseif ${OP_}==${OP[25]} then if(${RK}(${B})<=${RK}(${C}))~=(${A}~=0)then ${PC}=${PC}+1 end  -- LE
    elseif ${OP_}==${OP[26]} then if(not not ${REGS}[${A}+1])~=(${C}~=0)then ${PC}=${PC}+1 end   -- TEST
    elseif ${OP_}==${OP[27]} then                                                  -- TESTSET
      if(not not ${REGS}[${B}+1])==(${C}~=0)then ${REGS}[${A}+1]=${REGS}[${B}+1]else ${PC}=${PC}+1 end
    elseif ${OP_}==${OP[28]} then                                                  -- CALL
      local ${FN}=${REGS}[${A}+1];local ${CA}={}
      if ${B}==0 then for ${II}=${A}+2,${TOP}+1 do ${CA}[#${CA}+1]=${REGS}[${II}]end
      elseif ${B}>1 then for ${II}=${A}+2,${A}+${B} do ${CA}[#${CA}+1]=${REGS}[${II}]end end
      local ${RES}={${FN}(${UNP}(${CA}))}
      if ${C}==0 then for ${II}=1,#${RES} do ${REGS}[${A}+${II}]=${RES}[${II}]end;${TOP}=${A}+#${RES}-1
      elseif ${C}>1 then
        for ${II}=1,${C}-1 do ${REGS}[${A}+${II}]=${RES}[${II}]end
        for ${II}=#${RES}+1,${C}-1 do ${REGS}[${A}+${II}]=nil end
      end
    elseif ${OP_}==${OP[29]} then                                                  -- TAILCALL
      local ${FN}=${REGS}[${A}+1];local ${CA}={}
      if ${B}==0 then for ${II}=${A}+2,${TOP}+1 do ${CA}[#${CA}+1]=${REGS}[${II}]end
      elseif ${B}>1 then for ${II}=${A}+2,${A}+${B} do ${CA}[#${CA}+1]=${REGS}[${II}]end end
      ${CUV}(0);return ${FN}(${UNP}(${CA}))
    elseif ${OP_}==${OP[30]} then                                                  -- RETURN
      ${CUV}(0)
      if ${B}==1 then return end
      local ${R}={}
      if ${B}==0 then for ${II}=${A}+1,${TOP}+1 do ${R}[#${R}+1]=${REGS}[${II}]end
      else for ${II}=${A}+1,${A}+${B}-1 do ${R}[#${R}+1]=${REGS}[${II}]end end
      return ${UNP}(${R})
    elseif ${OP_}==${OP[31]} then                                                  -- FORLOOP
      local ${STEP}=${REGS}[${A}+3];${REGS}[${A}+1]=${REGS}[${A}+1]+${STEP}
      if(${STEP}>0 and ${REGS}[${A}+1]<=${REGS}[${A}+2])or(${STEP}<0 and ${REGS}[${A}+1]>=${REGS}[${A}+2])then
        ${PC}=${PC}+${SBX};${REGS}[${A}+4]=${REGS}[${A}+1]
      end
    elseif ${OP_}==${OP[32]} then ${REGS}[${A}+1]=${REGS}[${A}+1]-${REGS}[${A}+3];${PC}=${PC}+${SBX}  -- FORPREP
    elseif ${OP_}==${OP[33]} then                                                  -- TFORLOOP
      local ${R}={${REGS}[${A}+1](${REGS}[${A}+2],${REGS}[${A}+3])}
      for ${II}=1,${C} do ${REGS}[${A}+3+${II}]=${R}[${II}]end
      if ${REGS}[${A}+4]~=nil then ${REGS}[${A}+3]=${REGS}[${A}+4]else ${PC}=${PC}+1 end
    elseif ${OP_}==${OP[34]} then                                                  -- SETLIST
      local ${TT}=${REGS}[${A}+1];local ${CN}=${C}
      if ${CN}==0 then
        ${CN}=${BIT}.bxor(${CODE}[${PC}],${XK},(${PC}-1)%256)
        ${PC}=${PC}+1
      end
      local ${OFS}=(${CN}-1)*50
      if ${B}==0 then for ${II}=1,${TOP}-${A} do ${TT}[${OFS}+${II}]=${REGS}[${A}+${II}+1]end
      else for ${II}=1,${B} do ${TT}[${OFS}+${II}]=${REGS}[${A}+${II}+1]end end
    elseif ${OP_}==${OP[35]} then ${CUV}(${A})                                    -- CLOSE
    elseif ${OP_}==${OP[36]} then                                                  -- CLOSURE
      local ${SUB}=${SUBS}[${BX}+1];local ${NUVL}={}
      for ${II}=1,${SUB}.u do
        local raw2=${CODE}[${PC}]
        local ${PS}=${BIT}.bxor(raw2,${XK},(${PC}-1)%256)
        ${PC}=${PC}+1
        local ${POP}=${BIT}.band(${PS},63)
        local ${PB}=${BIT}.band(${BIT}.rshift(${PS},23),511)
        if ${POP}==${OP[0]} then ${NUVL}[${II}]=${NUV}(${PB}+1)
        else ${NUVL}[${II}]=${UV}[${PB}+1]end
      end
      local ${SS},${NN}=${SUB},${NUVL}
      ${REGS}[${A}+1]=function(...)return ${EXEC}(${SS},${ENV},${NN},...)end
    elseif ${OP_}==${OP[37]} then                                                  -- VARARG
      local ${VV}=${B}-1
      if ${VV}<0 then
        for ${II}=1,#${VA} do ${REGS}[${A}+${II}]=${VA}[${II}]end;${TOP}=${A}+#${VA}-1
      else for ${II}=1,${VV} do ${REGS}[${A}+${II}]=${VA}[${II}]end;${TOP}=${A}+${VV}-1 end
    end
  end
end
local _G_=getfenv and getfenv(0)or _G
${EXEC}(${PROTO},_G_,{})`;
}

// ─── Public API ───────────────────────────────────────────────────────────────
// Returns Lua source code for the VM (no loadstring anywhere)
// Caller (server.js) then encrypts this VM code with RC4+XOR+state-machine
function buildVM(source, luaInterpreterBin, prometheusRunner, prometheusPreset) {
    // Step 1: Prometheus source-level obfuscation (optional, graceful fallback)
    let obfSource = source;
    if (prometheusRunner) {
        try {
            const r = spawnSync(luaInterpreterBin, [prometheusRunner, prometheusPreset || 'Strong'], {
                input: source, encoding: 'utf8', timeout: 60000, maxBuffer: 20 * 1024 * 1024
            });
            if (!r.error && r.status === 0 && r.stdout?.trim())
                obfSource = r.stdout;
            else
                console.warn('[VM] Prometheus skip:', (r.stderr || '').slice(0, 80));
        } catch(e) { console.warn('[VM] Prometheus error:', e.message); }
    }

    // Step 2: Compile to Lua 5.1 bytecode
    let bytecode;
    try {
        bytecode = compileLua(obfSource);
    } catch(e) {
        // If Prometheus output won't compile (edge case), try raw source
        console.warn('[VM] luac failed on obfuscated source, trying raw:', e.message.slice(0, 80));
        try { bytecode = compileLua(source); }
        catch(e2) { throw new Error('luac compilation failed: ' + e2.message.slice(0, 200)); }
    }

    // Step 3: Parse bytecode into proto tree
    const proto = parseBytecode(bytecode);

    // Step 4: Random opcode shuffle (38! possibilities, new every call)
    const fwd = makeOpcodeMap();

    // Step 5: Apply shuffle to all instructions in proto tree
    const shuffled = shuffleOpcodes(proto, fwd);

    // Step 6: XOR-encrypt all instructions with a random 32-bit key
    const xorKey   = crypto.randomBytes(4).readUInt32BE(0) >>> 0;
    const encrypted = encryptInstructions(shuffled, xorKey);

    // Step 7: Generate the VM Lua source code
    return generateVM(encrypted, xorKey, fwd);
}

module.exports = { buildVM };
