require("dotenv").config();
const {
    Client, GatewayIntentBits, SlashCommandBuilder, REST, Routes,
    EmbedBuilder, ActionRowBuilder, ButtonBuilder, ButtonStyle,
    ModalBuilder, TextInputBuilder, TextInputStyle,
    PermissionFlagsBits, ActivityType
} = require("discord.js");
const { createClient } = require("@supabase/supabase-js");
const crypto = require("crypto");

const sb   = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);
const BASE = process.env.RAILWAY_PUBLIC_DOMAIN
    ? `https://${process.env.RAILWAY_PUBLIC_DOMAIN}`
    : `http://localhost:${process.env.PORT || 8080}`;

const C = { main:0x4f8ef7, ok:0x23d18b, err:0xf75050, warn:0xf5a623 };

// ── Helpers ───────────────────────────────────────────────────────────────────
function genKey(prefix="LUNEX") {
    const s = () => crypto.randomBytes(3).toString("hex").toUpperCase();
    return `${prefix}-${s()}-${s()}-${s()}`;
}

function parseSecs(str) {
    if (!str || str==="lifetime") return null;
    const m={m:60,h:3600,d:86400};
    const x=str.match(/^(\d+)([mhd])$/);
    return x ? parseInt(x[1])*(m[x[2]]||0) : null;
}

function durationLabel(s) {
    return {
        "10m":"10 minutes","1h":"1 hour","6h":"6 hours","12h":"12 hours",
        "1d":"1 day","3d":"3 days","7d":"7 days","14d":"14 days",
        "30d":"30 days","lifetime":"Lifetime"
    }[s] || s;
}

function fmtExpiry(k) {
    if (!k.expires_at) return "♾️ Lifetime";
    const sec = k.expires_at - Math.floor(Date.now()/1000);
    if (sec<=0) return "⛔ Expired";
    const d=Math.floor(sec/86400), h=Math.floor((sec%86400)/3600), mn=Math.floor((sec%3600)/60);
    return d>0?`⏳ ${d}d ${h}h`:h>0?`⏳ ${h}h ${mn}m`:`⏳ ${mn}m`;
}

// Normalise a project ID — accept with or without dashes
function normalizeUUID(raw) {
    if (!raw) return null;
    const c = raw.replace(/-/g,"").toLowerCase();
    if (c.length!==32 || !/^[0-9a-f]+$/.test(c)) return null;
    return `${c.slice(0,8)}-${c.slice(8,12)}-${c.slice(12,16)}-${c.slice(16,20)}-${c.slice(20)}`;
}

// ── Supabase helpers ──────────────────────────────────────────────────────────
async function getCfg(guildId) {
    try {
        const { data } = await sb.from("bot_configs").select("*").eq("guild_id", guildId).single();
        return data || null;
    } catch { return null; }
}

async function setCfg(guildId, updates) {
    // Coerce all values — never pass undefined
    const safe = {};
    for (const [k,v] of Object.entries(updates)) {
        safe[k] = (v === undefined || v === null) ? null : String(v);
    }
    // api_key should stay as-is (don't coerce to "null" string)
    if (updates.api_key !== undefined) safe.api_key = updates.api_key || null;

    const ts = new Date().toISOString();
    const { data: existing } = await sb.from("bot_configs")
        .select("guild_id").eq("guild_id", guildId).single();

    let result, err;
    if (existing) {
        ({ data: result, error: err } = await sb.from("bot_configs")
            .update({ ...safe, updated_at: ts })
            .eq("guild_id", guildId).select().single());
    } else {
        ({ data: result, error: err } = await sb.from("bot_configs")
            .insert({ ...safe, guild_id: guildId, updated_at: ts })
            .select().single());
    }
    if (err) console.error("[Bot] setCfg error:", err.message, JSON.stringify(safe));
    else console.log("[Bot] setCfg saved project_id:", result?.project_id);
    return result;
}

function isManager(member, cfg) {
    if (!member) return false;
    if (member.permissions.has(PermissionFlagsBits.Administrator)) return true;
    if (cfg?.manager_role_id && member.roles.cache.has(cfg.manager_role_id)) return true;
    return false;
}

// ── Reply helpers ─────────────────────────────────────────────────────────────
async function reply(i, desc, color=C.main) {
    const e = new EmbedBuilder().setColor(color).setDescription(desc);
    const m = i.deferred||i.replied ? "editReply" : "reply";
    return i[m]({ embeds:[e], ephemeral:true }).catch(()=>{});
}
async function replyE(i, embed) {
    const m = i.deferred||i.replied ? "editReply" : "reply";
    return i[m]({ embeds:[embed], ephemeral:true }).catch(()=>{});
}

// ── Control panel embed ───────────────────────────────────────────────────────
function buildPanel(cfg) {
    const name = cfg?.project_name || "Script";
    return {
        embeds: [new EmbedBuilder()
            .setColor(C.main)
            .setTitle(`${name} Control Panel`)
            .setDescription(
                `This control panel is for the project: **${name}**\n` +
                `If you're a buyer, use the buttons below to redeem your key, get the script, or manage your access.`
            )
            .setFooter({ text:`Lunex • ${new Date().toLocaleString("en-US",{month:"short",day:"numeric",year:"numeric",hour:"2-digit",minute:"2-digit"})}` })
            .setTimestamp()
        ],
        components: [new ActionRowBuilder().addComponents(
            new ButtonBuilder().setCustomId("panel_redeem").setLabel("Redeem Key").setEmoji("🔑").setStyle(ButtonStyle.Success),
            new ButtonBuilder().setCustomId("panel_script").setLabel("Get Script").setEmoji("📋").setStyle(ButtonStyle.Primary),
            new ButtonBuilder().setCustomId("panel_role")  .setLabel("Get Role")  .setEmoji("🎭").setStyle(ButtonStyle.Secondary),
            new ButtonBuilder().setCustomId("panel_hwid")  .setLabel("Reset HWID").setEmoji("⚙️").setStyle(ButtonStyle.Secondary),
            new ButtonBuilder().setCustomId("panel_stats") .setLabel("My Stats")  .setEmoji("📊").setStyle(ButtonStyle.Secondary)
        )]
    };
}

// ── Duration choices ──────────────────────────────────────────────────────────
const DUR = [
    {name:"10 Minutes",value:"10m"},{name:"1 Hour",value:"1h"},
    {name:"6 Hours",value:"6h"},{name:"12 Hours",value:"12h"},
    {name:"1 Day",value:"1d"},{name:"3 Days",value:"3d"},
    {name:"7 Days",value:"7d"},{name:"14 Days",value:"14d"},
    {name:"30 Days",value:"30d"},{name:"Lifetime",value:"lifetime"}
];

// ── Slash commands ────────────────────────────────────────────────────────────
const commands = [
    new SlashCommandBuilder()
        .setName("login").setDescription("Link this server to your Lunex account")
        .addStringOption(o=>o.setName("api_key").setDescription("Your Lunex API key from the dashboard").setRequired(true))
        .setDefaultMemberPermissions(PermissionFlagsBits.Administrator),

    new SlashCommandBuilder()
        .setName("setup").setDescription("Configure project, buyer role and manager role")
        .addStringOption(o=>o.setName("project_id").setDescription("Project UUID from dashboard").setRequired(true))
        .addRoleOption(o=>o.setName("buyer_role").setDescription("Role given to buyers").setRequired(true))
        .addRoleOption(o=>o.setName("manager_role").setDescription("Role that can run bot commands"))
        .setDefaultMemberPermissions(PermissionFlagsBits.Administrator),

    new SlashCommandBuilder()
        .setName("panel").setDescription("Post the buyer control panel")
        .setDefaultMemberPermissions(PermissionFlagsBits.ManageChannels),

    new SlashCommandBuilder()
        .setName("createkey").setDescription("Whitelist a user and send them their key")
        .addUserOption(o=>o.setName("user").setDescription("User to whitelist").setRequired(true))
        .addStringOption(o=>o.setName("duration").setDescription("Key duration").setRequired(true).addChoices(...DUR))
        .addStringOption(o=>o.setName("note").setDescription("Optional note")),

    new SlashCommandBuilder()
        .setName("genkey").setDescription("Generate unassigned keys for selling")
        .addStringOption(o=>o.setName("duration").setDescription("Key duration").setRequired(true).addChoices(...DUR))
        .addIntegerOption(o=>o.setName("amount").setDescription("How many (1-50)").setMinValue(1).setMaxValue(50))
        .addStringOption(o=>o.setName("note").setDescription("Optional note")),

    new SlashCommandBuilder()
        .setName("revoke").setDescription("Revoke a user's access")
        .addUserOption(o=>o.setName("user").setDescription("User to revoke").setRequired(true)),

    new SlashCommandBuilder()
        .setName("resethwid").setDescription("Reset a user's HWID lock")
        .addUserOption(o=>o.setName("user").setDescription("User to reset").setRequired(true)),

    new SlashCommandBuilder()
        .setName("extend").setDescription("Add days to a user's key")
        .addUserOption(o=>o.setName("user").setDescription("User to extend").setRequired(true))
        .addIntegerOption(o=>o.setName("days").setDescription("Days to add").setRequired(true).setMinValue(1)),

    new SlashCommandBuilder()
        .setName("keyinfo").setDescription("View a user's key details")
        .addUserOption(o=>o.setName("user").setDescription("User to look up").setRequired(true)),

    new SlashCommandBuilder()
        .setName("stats").setDescription("View whitelist stats")
        .setDefaultMemberPermissions(PermissionFlagsBits.ManageGuild),
];

// ── Client ────────────────────────────────────────────────────────────────────
const client = new Client({
    intents:[
        GatewayIntentBits.Guilds,
        GatewayIntentBits.GuildMembers,
        GatewayIntentBits.GuildMessages,
        GatewayIntentBits.DirectMessages,
    ]
});

client.on("interactionCreate", async interaction => {
    try {
        if (interaction.isChatInputCommand()) return handleCommand(interaction);
        if (interaction.isButton())           return handleButton(interaction);
        if (interaction.isModalSubmit())      return handleModal(interaction);
    } catch(e) { console.error("[Bot] Interaction error:", e.message); }
});

// ── Command handler ───────────────────────────────────────────────────────────
async function handleCommand(interaction) {
    const { commandName, guildId, member } = interaction;
    await interaction.deferReply({ ephemeral:true }).catch(()=>{});
    const cfg = await getCfg(guildId);

    // ── /login — only command that works without being logged in ──────────────
    if (commandName === "login") {
        const apiKey = interaction.options.getString("api_key").trim();
        let account;
        try {
            const r = await fetch(`${BASE}/v1/account`, { headers:{"Authorization":`Bearer ${apiKey}`} });
            const j = await r.json();
            if (!j.success || !j.account) return reply(interaction, "❌ Invalid API key — check your Lunex dashboard.", C.err);
            account = j.account;
        } catch(e) {
            return reply(interaction, `❌ Cannot reach Lunex server: ${e.message}`, C.err);
        }
        await setCfg(guildId, { api_key:apiKey, email:account.email||"", plan:account.plan||"starter" });
        return replyE(interaction, new EmbedBuilder().setColor(C.ok).setTitle("✅ Logged In!")
            .setDescription("Server linked to Lunex. Run `/setup` to configure your project and roles.")
            .addFields(
                {name:"Account",value:account.email||"—",inline:true},
                {name:"Plan",value:`\`${account.plan||"starter"}\``,inline:true}
            ));
    }

    // ── All other commands require /login first ───────────────────────────────
    if (!cfg?.api_key) {
        return reply(interaction, "❌ Run `/login <api_key>` first.\nGet your API key from your Lunex dashboard.", C.err);
    }

    // ── /setup ────────────────────────────────────────────────────────────────
    if (commandName === "setup") {
        if (!member.permissions.has(PermissionFlagsBits.Administrator))
            return reply(interaction, "❌ Administrator only.", C.err);

        const rawId       = interaction.options.getString("project_id").trim();
        const buyerRole   = interaction.options.getRole("buyer_role");
        const managerRole = interaction.options.getRole("manager_role");

        const projectId = normalizeUUID(rawId);
        if (!projectId)
            return reply(interaction, "❌ Invalid project ID format. Copy it from Lunex dashboard → Projects.", C.err);

        // Verify the project exists
        let proj = null;
        try {
            const r = await fetch(`${BASE}/v1/projects`, { headers:{"Authorization":`Bearer ${cfg.api_key}`} });
            const j = await r.json();
            proj = (j.projects||[]).find(p=>p.id===projectId);
        } catch(e) {
            return reply(interaction, `❌ Could not reach Lunex server: ${e.message}`, C.err);
        }
        if (!proj) {
            return reply(interaction,
                `❌ Project not found.\nID you entered: \`${projectId}\`\nMake sure you copy the ID from the **Projects** page in your dashboard.`,
                C.err);
        }

        const saved = await setCfg(guildId, {
            project_id:      projectId,
            project_name:    proj.name,
            buyer_role_id:   buyerRole.id,
            manager_role_id: managerRole?.id || null,
        });

        if (!saved?.project_id) {
            return reply(interaction, "❌ Failed to save config — check Railway logs.", C.err);
        }

        return replyE(interaction, new EmbedBuilder().setColor(C.ok).setTitle("✅ Setup Complete")
            .setDescription("Post a buyer panel with `/panel`.")
            .addFields(
                {name:"Project",      value:proj.name,                                         inline:true},
                {name:"Buyer Role",   value:`<@&${buyerRole.id}>`,                             inline:true},
                {name:"Manager Role", value:managerRole?`<@&${managerRole.id}>`:"Not set",     inline:true}
            ));
    }

    // ── /panel ────────────────────────────────────────────────────────────────
    if (commandName === "panel") {
        if (!isManager(member,cfg)) return reply(interaction,"❌ No permission.",C.err);
        await interaction.channel.send(buildPanel(cfg));
        return reply(interaction,"✅ Panel posted!",C.ok);
    }

    // ── /createkey ────────────────────────────────────────────────────────────
    if (commandName === "createkey") {
        if (!isManager(member,cfg)) return reply(interaction,"❌ No permission.",C.err);
        if (!cfg.project_id)        return reply(interaction,"❌ Run `/setup` first to configure a project.",C.err);
        const target   = interaction.options.getUser("user");
        const duration = interaction.options.getString("duration");
        const note     = interaction.options.getString("note")||null;
        const secs     = parseSecs(duration);
        const expires_at = secs ? Math.floor(Date.now()/1000)+secs : null;
        const key = genKey();
        const {error} = await sb.from("keys").insert({
            project_id:cfg.project_id, key_string:key, discord_id:target.id,
            note, active:true, key_days:secs?Math.ceil(secs/86400):null,
            expires_at, total_executions:0, created_at:new Date().toISOString()
        });
        if (error) return reply(interaction,`❌ DB error: ${error.message}`,C.err);
        // Give buyer role
        try {
            if (cfg.buyer_role_id) {
                const gm = await interaction.guild.members.fetch(target.id);
                await gm.roles.add(cfg.buyer_role_id);
            }
        } catch {}
        // DM the user
        try {
            await target.send({embeds:[new EmbedBuilder().setColor(C.ok)
                .setTitle("🔑 You've Been Whitelisted!")
                .setDescription(`Your key for **${cfg.project_name||"the script"}**:`)
                .addFields(
                    {name:"Key",      value:`\`\`\`${key}\`\`\``,                                    inline:false},
                    {name:"Duration", value:durationLabel(duration),                                  inline:true},
                    {name:"How to use",value:`Place \`script_key="${key}"\` above the loader script`, inline:false}
                ).setFooter({text:"Do not share your key — HWID locks on first run"})]});
        } catch {}
        return replyE(interaction, new EmbedBuilder().setColor(C.ok).setTitle("✅ Key Created & DM'd")
            .addFields(
                {name:"User",     value:`<@${target.id}>`, inline:true},
                {name:"Key",      value:`\`${key}\``,      inline:false},
                {name:"Duration", value:durationLabel(duration), inline:true},
                {name:"Note",     value:note||"—",         inline:true}
            ));
    }

    // ── /genkey ───────────────────────────────────────────────────────────────
    if (commandName === "genkey") {
        if (!isManager(member,cfg)) return reply(interaction,"❌ No permission.",C.err);
        if (!cfg.project_id)        return reply(interaction,"❌ Run `/setup` first.",C.err);
        const duration = interaction.options.getString("duration");
        const amount   = Math.min(interaction.options.getInteger("amount")||1,50);
        const note     = interaction.options.getString("note")||null;
        const secs     = parseSecs(duration);
        const expires_at = secs ? Math.floor(Date.now()/1000)+secs : null;
        const rows = Array.from({length:amount},()=>({
            project_id:cfg.project_id, key_string:genKey(), discord_id:null, note,
            active:true, key_days:secs?Math.ceil(secs/86400):null, expires_at,
            total_executions:0, created_at:new Date().toISOString()
        }));
        const {data,error} = await sb.from("keys").insert(rows).select("key_string");
        if (error) return reply(interaction,`❌ DB error: ${error.message}`,C.err);
        const keyList = data.map(k=>k.key_string).join("\n");
        return interaction.editReply({
            embeds:[new EmbedBuilder().setColor(C.ok).setTitle("🗝️ Keys Generated")
                .setDescription(`**${data.length}** key${data.length!==1?"s":""} — ${durationLabel(duration)}`)],
            files:[{attachment:Buffer.from(keyList,"utf8"),name:`keys_${Date.now()}.txt`}],
            ephemeral:true
        });
    }

    // ── /revoke ───────────────────────────────────────────────────────────────
    if (commandName === "revoke") {
        if (!isManager(member,cfg)) return reply(interaction,"❌ No permission.",C.err);
        const target = interaction.options.getUser("user");
        await sb.from("keys").update({active:false}).eq("discord_id",target.id).eq("project_id",cfg.project_id);
        try {
            const gm=await interaction.guild.members.fetch(target.id);
            if (cfg.buyer_role_id) await gm.roles.remove(cfg.buyer_role_id).catch(()=>{});
        } catch {}
        try { await target.send({embeds:[new EmbedBuilder().setColor(C.err)
            .setTitle("🚫 Access Revoked")
            .setDescription("Your whitelist access has been revoked. Contact support if this is a mistake.")]}); } catch {}
        return reply(interaction,`✅ Revoked <@${target.id}>`,C.ok);
    }

    // ── /resethwid ────────────────────────────────────────────────────────────
    if (commandName === "resethwid") {
        if (!isManager(member,cfg)) return reply(interaction,"❌ No permission.",C.err);
        const target = interaction.options.getUser("user");
        const {data} = await sb.from("keys")
            .update({hwid:null,last_hwid_reset:new Date().toISOString()})
            .eq("discord_id",target.id).eq("project_id",cfg.project_id).select("key_string");
        if (!data?.length) return reply(interaction,"❌ No key found for this user.",C.err);
        try { await target.send({embeds:[new EmbedBuilder().setColor(C.main)
            .setTitle("🔓 HWID Reset")
            .setDescription("Your HWID has been cleared. Your new device will lock on next script run.")]}); } catch {}
        return reply(interaction,`✅ HWID reset for <@${target.id}>`,C.ok);
    }

    // ── /extend ───────────────────────────────────────────────────────────────
    if (commandName === "extend") {
        if (!isManager(member,cfg)) return reply(interaction,"❌ No permission.",C.err);
        const target = interaction.options.getUser("user");
        const days   = interaction.options.getInteger("days");
        const {data} = await sb.from("keys").select("*")
            .eq("discord_id",target.id).eq("project_id",cfg.project_id).limit(1);
        if (!data?.length) return reply(interaction,"❌ No key found for this user.",C.err);
        const k=data[0];
        const base=k.expires_at??Math.floor(Date.now()/1000);
        const newExp=base+days*86400;
        await sb.from("keys").update({expires_at:newExp}).eq("key_string",k.key_string);
        const nd=new Date(newExp*1000).toLocaleDateString();
        try { await target.send({embeds:[new EmbedBuilder().setColor(C.ok)
            .setTitle("✅ Key Extended")
            .setDescription(`Extended by **${days} day${days!==1?"s":""}**. New expiry: **${nd}**`)]}); } catch {}
        return reply(interaction,`✅ Extended <@${target.id}>'s key by ${days}d. New expiry: ${nd}`,C.ok);
    }

    // ── /keyinfo ──────────────────────────────────────────────────────────────
    if (commandName === "keyinfo") {
        if (!isManager(member,cfg)) return reply(interaction,"❌ No permission.",C.err);
        const target = interaction.options.getUser("user");
        const {data} = await sb.from("keys").select("*")
            .eq("discord_id",target.id).eq("project_id",cfg.project_id).limit(1);
        if (!data?.length) return reply(interaction,"❌ No key found for this user.",C.err);
        const k=data[0];
        const now=Math.floor(Date.now()/1000);
        const active=k.active&&(!k.expires_at||k.expires_at>now);
        return replyE(interaction, new EmbedBuilder().setColor(active?C.main:C.err)
            .setTitle(`🔑 Key Info — ${target.username}`)
            .setThumbnail(target.displayAvatarURL())
            .addFields(
                {name:"Key",        value:`\`${k.key_string}\``,                                                    inline:false},
                {name:"Status",     value:active?"✅ Active":"❌ Revoked/Expired",                                   inline:true},
                {name:"Expires",    value:fmtExpiry(k),                                                             inline:true},
                {name:"HWID",       value:k.hwid?"🔒 Locked":"🔓 Unlocked",                                         inline:true},
                {name:"Runs",       value:String(k.total_executions||0),                                            inline:true},
                {name:"Last Run",   value:k.last_exec?`<t:${Math.floor(new Date(k.last_exec).getTime()/1000)}:R>`:"Never", inline:true},
                {name:"Note",       value:k.note||"—",                                                              inline:true}
            ).setTimestamp());
    }

    // ── /stats ────────────────────────────────────────────────────────────────
    if (commandName === "stats") {
        if (!isManager(member,cfg)) return reply(interaction,"❌ No permission.",C.err);
        const {data:allKeys} = await sb.from("keys").select("active,expires_at,total_executions")
            .eq("project_id",cfg.project_id);
        const now=Math.floor(Date.now()/1000);
        const active  = (allKeys||[]).filter(k=>k.active&&(!k.expires_at||k.expires_at>now)).length;
        const expired = (allKeys||[]).filter(k=>k.expires_at&&k.expires_at<=now).length;
        const revoked = (allKeys||[]).filter(k=>!k.active).length;
        const runs    = (allKeys||[]).reduce((s,k)=>s+(k.total_executions||0),0);
        return replyE(interaction, new EmbedBuilder().setColor(C.main)
            .setTitle(`📊 Stats — ${cfg.project_name||"Project"}`)
            .addFields(
                {name:"🟢 Active",    value:String(active),              inline:true},
                {name:"⛔ Expired",   value:String(expired),             inline:true},
                {name:"🔴 Revoked",   value:String(revoked),             inline:true},
                {name:"⚡ Total Runs",value:String(runs),                inline:true},
                {name:"📦 Total Keys",value:String((allKeys||[]).length),inline:true}
            ).setTimestamp());
    }
}

// ── Button handler ────────────────────────────────────────────────────────────
async function handleButton(interaction) {
    const {customId,guildId,user} = interaction;
    const cfg = await getCfg(guildId);

    // Redeem key — show modal
    if (customId==="panel_redeem") {
        const modal = new ModalBuilder().setCustomId("modal_redeem").setTitle("Redeem a Key");
        modal.addComponents(new ActionRowBuilder().addComponents(
            new TextInputBuilder().setCustomId("key_input")
                .setLabel("Enter your script key below:")
                .setPlaceholder("LUNEX-XXXXXX-XXXXXX-XXXXXX")
                .setStyle(TextInputStyle.Short).setRequired(true).setMinLength(10).setMaxLength(80)
        ));
        return interaction.showModal(modal);
    }

    await interaction.deferReply({ephemeral:true}).catch(()=>{});

    // Find user's key (try project-specific first, fallback to any active key)
    async function findKey(uid) {
        if (cfg?.project_id) {
            const {data} = await sb.from("keys").select("*")
                .eq("discord_id",uid).eq("project_id",cfg.project_id).eq("active",true).limit(1);
            if (data?.length) return data[0];
        }
        const {data} = await sb.from("keys").select("*")
            .eq("discord_id",uid).eq("active",true).limit(1);
        return data?.[0]||null;
    }

    if (customId==="panel_script") {
        const k = await findKey(user.id);
        if (!k) return reply(interaction,
            "❌ **Not whitelisted!**\n\nYou need a key to access this script.\nClick **Redeem Key** if you have one.",C.err);
        const now=Math.floor(Date.now()/1000);
        if (k.expires_at&&k.expires_at<=now) return reply(interaction,"❌ Your key has expired. Contact support.",C.err);
        if (k.discord_id&&k.discord_id!==user.id) return reply(interaction,"❌ This key belongs to another account.",C.err);
        const loader=`script_key="${k.key_string}"\nloadstring(game:HttpGet("${BASE}/v1/auth?key="..script_key.."&hwid="..game:GetService("RbxAnalyticsService"):GetClientId()))()`;
        try {
            await user.send({embeds:[new EmbedBuilder().setColor(C.main)
                .setTitle("📋 Your Script Loader")
                .setDescription("Execute this in your Roblox executor.")
                .addFields(
                    {name:"Loader",    value:`\`\`\`lua\n${loader}\n\`\`\``},
                    {name:"Expires",   value:fmtExpiry(k),          inline:true},
                    {name:"Total Runs",value:String(k.total_executions||0),inline:true}
                ).setFooter({text:"Keep this private — HWID locks on first run"})]});
            return reply(interaction,"✅ Loader sent to your DMs!",C.ok);
        } catch {
            return reply(interaction,"❌ Couldn't DM you. Enable **Allow DMs from server members** in your Discord privacy settings.",C.err);
        }
    }

    if (customId==="panel_role") {
        if (!cfg?.buyer_role_id) return reply(interaction,"❌ No buyer role configured.",C.err);
        const k=await findKey(user.id);
        if (!k) return reply(interaction,"❌ No active key found. Redeem a key first.",C.err);
        const now=Math.floor(Date.now()/1000);
        if (k.expires_at&&k.expires_at<=now) return reply(interaction,"❌ Your key has expired.",C.err);
        try {
            const gm=await interaction.guild.members.fetch(user.id);
            if (gm.roles.cache.has(cfg.buyer_role_id)) return reply(interaction,"✅ You already have the buyer role!",C.ok);
            await gm.roles.add(cfg.buyer_role_id);
            return reply(interaction,`✅ You now have <@&${cfg.buyer_role_id}>!`,C.ok);
        } catch { return reply(interaction,"❌ Failed to assign role — bot needs **Manage Roles** above the buyer role.",C.err); }
    }

    if (customId==="panel_hwid") {
        const k=await findKey(user.id);
        if (!k) return reply(interaction,"❌ No key found for your account.",C.err);
        await sb.from("keys").update({hwid:null,last_hwid_reset:new Date().toISOString()}).eq("key_string",k.key_string);
        return replyE(interaction, new EmbedBuilder().setColor(C.ok).setTitle("🔓 HWID Reset")
            .setDescription("Your HWID has been cleared. Your new device locks on next script run."));
    }

    if (customId==="panel_stats") {
        const k=await findKey(user.id);
        if (!k) return reply(interaction,"❌ No key found. Redeem a key first.",C.err);
        const now=Math.floor(Date.now()/1000);
        const active=k.active&&(!k.expires_at||k.expires_at>now);
        return replyE(interaction, new EmbedBuilder().setColor(C.main).setTitle("📊 Your Stats")
            .addFields(
                {name:"Status",    value:active?"✅ Active":"❌ Expired/Revoked",                                    inline:true},
                {name:"Expires",   value:fmtExpiry(k),                                                              inline:true},
                {name:"HWID",      value:k.hwid?"🔒 Locked":"🔓 Not locked",                                        inline:true},
                {name:"Total Runs",value:String(k.total_executions||0),                                             inline:true},
                {name:"Last Run",  value:k.last_exec?`<t:${Math.floor(new Date(k.last_exec).getTime()/1000)}:R>`:"Never",inline:true},
                {name:"Key",       value:`\`${k.key_string.slice(0,18)}...\``,                                      inline:true}
            ).setFooter({text:cfg?.project_name||"Lunex"}).setTimestamp());
    }
}

// ── Modal handler ─────────────────────────────────────────────────────────────
async function handleModal(interaction) {
    const {customId,guildId,user} = interaction;
    const cfg = await getCfg(guildId);

    if (customId==="modal_redeem") {
        await interaction.deferReply({ephemeral:true}).catch(()=>{});
        const keyStr = interaction.fields.getTextInputValue("key_input").trim().toUpperCase();
        const {data:k} = await sb.from("keys").select("*").eq("key_string",keyStr).single();
        if (!k)          return reply(interaction,"❌ Invalid key — double check and try again.",C.err);
        if (!k.active)   return reply(interaction,"❌ This key has been revoked.",C.err);
        if (k.expires_at&&k.expires_at<=Math.floor(Date.now()/1000))
            return reply(interaction,"❌ This key has expired.",C.err);
        if (k.discord_id&&k.discord_id!==user.id)
            return reply(interaction,"❌ This key is already claimed by another account.",C.err);
        if (!k.discord_id)
            await sb.from("keys").update({discord_id:user.id}).eq("key_string",keyStr);
        try {
            if (cfg?.buyer_role_id) {
                const gm=await interaction.guild.members.fetch(user.id);
                await gm.roles.add(cfg.buyer_role_id);
            }
        } catch {}
        return replyE(interaction, new EmbedBuilder().setColor(C.ok).setTitle("✅ Key Redeemed!")
            .setDescription("Your key is now linked to your account.\nClick **Get Script** to get your loader.")
            .addFields(
                {name:"Key",    value:`\`${keyStr}\``,  inline:false},
                {name:"Expires",value:fmtExpiry(k),     inline:true}
            ).setFooter({text:"Do NOT share your key"}));
    }
}

// ── Ready ─────────────────────────────────────────────────────────────────────
client.once("clientReady", async () => {
    console.log(`[Bot] Online as ${client.user.tag}`);
    client.user.setActivity("Lunex Whitelist", {type:ActivityType.Watching});
    try {
        await new REST({version:"10"}).setToken(process.env.DISCORD_BOT_TOKEN)
            .put(Routes.applicationCommands(process.env.DISCORD_CLIENT_ID), {body:commands.map(c=>c.toJSON())});
        console.log("[Bot] Commands registered");
    } catch(e) { console.error("[Bot] Command registration failed:", e.message); }
});

client.on("error", e => console.error("[Bot] Error:", e.message));
client.on("warn",  m => console.warn("[Bot] Warn:", m));
process.on("uncaughtException",  e => console.error("[Bot] Uncaught:", e.message));
process.on("unhandledRejection", e => console.error("[Bot] Unhandled:", e));

function startBot() {
    client.login(process.env.DISCORD_BOT_TOKEN).catch(e => {
        console.error("[Bot] Login failed:", e.message, "— retrying in 10s");
        setTimeout(startBot, 10000);
    });
}
startBot();
