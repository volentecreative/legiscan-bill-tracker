// /api/sync-bills.js
const crypto = require('crypto');

// Session verification (duplicated from auth.js to avoid import issues)
function verifySessionToken(token, password) {
  try {
    const [dataBase64, signature] = token.split('.');
    if (!dataBase64 || !signature) return { valid: false };
    
    const data = Buffer.from(dataBase64, 'base64').toString('utf8');
    
    // Verify signature
    const hmac = crypto.createHmac('sha256', password);
    hmac.update(data);
    const expectedSignature = hmac.digest('hex');
    
    if (signature !== expectedSignature) {
      return { valid: false, error: 'Invalid signature' };
    }
    
    // Check expiry
    const parsed = JSON.parse(data);
    if (Date.now() > parsed.exp) {
      return { valid: false, error: 'Session expired' };
    }
    
    return { valid: true };
  } catch (error) {
    return { valid: false, error: 'Invalid token format' };
  }
}

function verifySession(req) {
  const validPassword = process.env.DASHBOARD_PASSWORD;
  
  if (!validPassword) {
    return { valid: false, error: 'Server configuration error' };
  }
  
  const cookies = req.headers.cookie || '';
  const sessionMatch = cookies.match(/session=([^;]+)/);
  
  if (!sessionMatch) {
    return { valid: false, error: 'No session cookie' };
  }
  
  return verifySessionToken(sessionMatch[1], validPassword);
}

module.exports = async function handler(req, res) {
  try {
    // Check if this is a webhook call (Webflow webhooks won't have session cookies)
    const webhookItemId = req.body?._id || req.body?.itemId || req.query?.itemId;
    const isWebhookCall = !!webhookItemId;
    
    // For manual/non-webhook calls, require authentication
    if (!isWebhookCall) {
      const authCheck = verifySession(req);
      if (!authCheck.valid) {
        return res.status(401).json({ 
          success: false, 
          error: 'Authentication required',
          message: 'Please log in to the dashboard to run manual syncs'
        });
      }
    }

    const WEBFLOW_TOKEN = process.env.WEBFLOW_API_TOKEN;
    const LEGISCAN_API_KEY = process.env.LEGISCAN_API_KEY;
    const COLLECTION_ID = process.env.WEBFLOW_BILLS_COLLECTION_ID; // required

    if (!WEBFLOW_TOKEN || !LEGISCAN_API_KEY || !COLLECTION_ID) {
      return res.status(400).json({ success: false, error: "Missing environment variables" });
    }

    const results = {
      timestamp: new Date().toISOString(),
      webhookMode: !!webhookItemId,
      targetItemId: webhookItemId || null,
      processed: 0,
      updated: 0,
      skipped: 0,
      skipReasons: [],
      errors: [],
      bills: []
    };
    const toPublish = [];
    const sleep = (ms) => new Promise(r => setTimeout(r, ms));

    // Session status cache for dynamic session detection
    const sessionStatusCache = new Map();

    // --- Fetch collection schema and build option maps dynamically
    async function getOptionIdMaps() {
      const u = `https://api.webflow.com/v2/collections/${COLLECTION_ID}`;
      const r = await fetch(u, { headers: { Authorization: `Bearer ${WEBFLOW_TOKEN}` } });
      if (!r.ok) throw new Error(`Failed to load collection schema: ${r.status}`);
      const col = await r.json();

      const bySlug = Object.fromEntries((col.fields || []).map(f => [f.slug, f]));

      function makeMap(slug, names) {
        const f = bySlug[slug];
        if (!f) throw new Error(`Field not found: ${slug}`);
        if (f.type !== "Option") throw new Error(`Field ${slug} is not Option type`);
        const opts = f.validations?.options || [];
        const map = {};
        names.forEach(name => {
          const opt = opts.find(o => o.name.toLowerCase() === name.toLowerCase());
          if (!opt) throw new Error(`Option "${name}" not found on ${slug}`);
          map[name] = opt.id;
        });
        return map;
      }

      return {
        bySlug,
        houseStatusIds: makeMap("house-file-status", ["Active","Tabled","Failed","Passed"]),
        senateStatusIds: makeMap("senate-file-status", ["Active","Tabled","Failed","Passed"]),
        jurisdictionIds: (() => { try { return makeMap("jurisdiction", ["Minnesota","Federal"]); } catch { return {}; } })(),
      };
    }

    // Coerce/strip fields not present in the schema to prevent 400s
    function cleanFieldData(fieldData, bySlug) {
      const out = {};
      const dropped = [];
      for (const [k, v] of Object.entries(fieldData || {})) {
        const def = bySlug[k];
        if (!def) { dropped.push(k); continue; }

        // Webflow v2: for text/richtext/link-like fields use empty string to clear
        if (v == null) {
          if (["PlainText","RichText","Link","Email","Phone","Url","Number","Color"].includes(def.type)) {
            out[k] = "";
          } else {
            out[k] = null; // allowed for e.g. References, Images, Options, etc.
          }
        } else {
          out[k] = v;
        }
      }
      return { cleaned: out, dropped };
    }

    // --- Webflow Option IDs (Jurisdiction) - static → state code
    const JURISDICTION_MAP = {
      "3b566a1d5376e736be044c288bb44017": "MN", // Minnesota
      "87a300e03b5ad785b240294477aaaf35": "US", // Federal
    };

    // --- Enhanced Status Detection Functions -----------------------------------

    // New function to check if session has ended using LegiScan data
    async function isSessionEnded(state, legislativeYear) {
      const cacheKey = `${state}-${legislativeYear}`;
      
      // Return cached result if available
      if (sessionStatusCache.has(cacheKey)) {
        return sessionStatusCache.get(cacheKey);
      }

      try {
        // Get session list for the state
        const sessionUrl = `https://api.legiscan.com/?key=${encodeURIComponent(LEGISCAN_API_KEY)}&op=getSessionList&state=${encodeURIComponent(state)}`;
        const response = await fetch(sessionUrl);
        const data = await response.json();
        
        if (data.status !== "OK" || !data.sessions) {
          // Fallback to original date-based logic for MN
          if (state === "MN" && legislativeYear) {
            const year = Number(legislativeYear);
            const cutoff = new Date(year, 5, 1); // June 1
            const ended = new Date() >= cutoff;
            sessionStatusCache.set(cacheKey, ended);
            return ended;
          }
          return false;
        }

        // Find the session for the specified year
        const targetSession = data.sessions.find(session => {
          const yearStart = session.year_start;
          const yearEnd = session.year_end;
          const year = Number(legislativeYear);
          
          // Handle both single-year and multi-year sessions
          return year >= yearStart && year <= yearEnd;
        });

        if (!targetSession) {
          // No session found for this year - assume ended
          sessionStatusCache.set(cacheKey, true);
          return true;
        }

        // Check session status flags
        const ended = targetSession.sine_die === 1 || targetSession.prior === 1;
        
        // Cache the result to avoid repeated API calls
        sessionStatusCache.set(cacheKey, ended);
        
        return ended;
      } catch (error) {
        console.warn(`Failed to get session status for ${state}-${legislativeYear}:`, error);
        
        // Fallback to original date-based logic for MN
        if (state === "MN" && legislativeYear) {
          const year = Number(legislativeYear);
          const cutoff = new Date(year, 5, 1); // June 1
          const ended = new Date() >= cutoff;
          sessionStatusCache.set(cacheKey, ended);
          return ended;
        }
        
        return false;
      }
    }

    function getStatusFromTimeline(billInfo) {
      const hist = Array.isArray(billInfo?.history) ? [...billInfo.history] : [];
      if (!hist.length) {
        const lastAction = (billInfo?.last_action || "").toLowerCase();
        return analyzeActionText(lastAction);
      }

      hist.sort((a, b) => new Date(b.date || b.action_date || 0) - new Date(a.date || a.action_date || 0));
      const recentEntries = hist.slice(0, 5);
      
      for (const entry of recentEntries) {
        const action = (entry.action || "").toLowerCase();
        const status = analyzeActionText(action);
        if (status) {
          return status;
        }
      }

      return null;
    }

    function analyzeActionText(actionText) {
      if (!actionText) return null;
      
      const text = actionText.toLowerCase();
      
      // Failed/Defeated patterns (most specific first)
      const failedPatterns = [
        /bill was not passed/,
        /motion.*failed/,
        /failed/,
        /defeated/,
        /rejected/,
        /killed/,
        /motion.*not agreed to/,
        /amendment.*not agreed to/,
        /vote.*failed/,
        /motion.*lost/,
        /do not pass/,
        /inexpedient/
      ];
      
      for (const pattern of failedPatterns) {
        if (pattern.test(text)) {
          return "Failed";
        }
      }
      
      // Passed patterns
      const passedPatterns = [
        /bill passed/,
        /passed/,
        /enacted/,
        /signed.*governor/,
        /signed.*president/,
        /approved/,
        /adopted/,
        /concurred/,
        /motion.*agreed to/,
        /vote.*passed/,
        /do pass/
      ];
      
      for (const pattern of passedPatterns) {
        if (pattern.test(text)) {
          return "Passed";
        }
      }
      
      // Tabled/Postponed patterns
      const tabledPatterns = [
        /tabled/,
        /laid on the? table/,
        /postponed/,
        /indefinitely postponed/,
        /sine die/,
        /died/,
        /withdrawn/,
        /stricken/,
        /held.*committee/,
        /laid over/,
        /laid on.*desk/
      ];
      
      for (const pattern of tabledPatterns) {
        if (pattern.test(text)) {
          return "Tabled";
        }
      }
      
      return null;
    }

    // Enhanced status computation with timeline analysis and dynamic session detection
    async function computeStatusKey(billInfo, { state, legislativeYear }) {
      const code = billInfo.status;
      
      // First check definitive status codes
      if (code === 4) return "Passed";
      if (code === 5 || code === 6) return "Failed";

      // Then try to determine status from timeline/history entries
      const timelineStatus = getStatusFromTimeline(billInfo);
      if (timelineStatus) {
        return timelineStatus;
      }

      // Use dynamic session status instead of hard-coded cutoff
      const sessionEnded = await isSessionEnded(state, legislativeYear);
      if (sessionEnded && (code === 1 || code === 2 || code === 3)) {
        return "Tabled";
      }

      // Check last_action for dead bill indicators
      const la = (billInfo?.last_action || "").toLowerCase();
      const looksDead = /tabled|laid on the? table|postponed|indefinitely|sine die|died|withdrawn|stricken/.test(la);
      if (looksDead) return "Tabled";

      return "Active";
    }

    // --- Helpers ------------------------------------------------------------
    const isPlaceholderName = (name, billNum) => {
      const n = (name || "").trim();
      return !n
        || (billNum && n.toUpperCase() === billNum.toUpperCase())
        || /^[HS]F[-\s]?\d+$/i.test(n)
        || /^(untitled|tbd|placeholder)$/i.test(n);
    };

    function normalizeNumbers(rawHouse, rawSenate) {
      const norm = v => (v || "").toUpperCase().replace(/[\s-]+/g, "");
      let h = norm(rawHouse), s = norm(rawSenate);
      const corrections = {};
      if (!h && /^HF\d+$/.test(s)) { h = s; s = ""; corrections["house-file-number"] = h; corrections["senate-file-number"] = ""; }
      if (!s && /^SF\d+$/.test(h)) { s = h; h = ""; corrections["senate-file-number"] = s; corrections["house-file-number"] = ""; }
      return { houseNumber: h || "", senateNumber: s || "", corrections };
    }

    async function fetchLegiScanBill({ state, billNumber, year }) {
      let searchNumber = billNumber;

      if (state === "US") {
        if (/^HR\d+$/i.test(billNumber)) {
          try {
            searchNumber = billNumber.replace(/^HR/i, "HB");
            let url = `https://api.legiscan.com/?key=${encodeURIComponent(LEGISCAN_API_KEY)}&op=getBill&state=${encodeURIComponent(state)}&bill=${encodeURIComponent(searchNumber)}`;
            if (year) url += `&year=${encodeURIComponent(year)}`;
            const r = await fetch(url);
            const data = await r.json();
            if (data.status === "OK" && data.bill) return data.bill;
          } catch {}
          searchNumber = billNumber;
        } else if (/^S\d+$/i.test(billNumber)) {
          searchNumber = billNumber.replace(/^S/i, "SB");
        }
      }

      let url = `https://api.legiscan.com/?key=${encodeURIComponent(LEGISCAN_API_KEY)}&op=getBill&state=${encodeURIComponent(state)}&bill=${encodeURIComponent(searchNumber)}`;
      if (year) url += `&year=${encodeURIComponent(year)}`;
      const r = await fetch(url);
      const data = await r.json();
      if (data.status !== "OK" || !data.bill) throw new Error(data.alert?.message || `Bill not found: ${searchNumber}`);
      return data.bill;
    }

    function pickBestTextUrl(info) {
      if (!info) return null;
      const texts = Array.isArray(info.texts) ? info.texts.slice() : [];
      if (texts.length) {
        texts.sort((a, b) => new Date(b.date || b.action_date || 0) - new Date(a.date || a.action_date || 0));
        const pdf = texts.find(t => /pdf/i.test(t?.mime || "") || /\.pdf($|\?)/i.test(t?.state_link || t?.url || ""));
        if (pdf) return pdf.state_link || pdf.url || null;
        const first = texts[0];
        if (first) return first.state_link || first.url || null;
      }
      return info.state_link || info.url || null;
    }

    const esc = (s='') => s.replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
    const fmt = (d) => {
      if (!d) return '';
      const [y,m,day] = (d.split('T')[0] || '').split('-');
      const dt = (y && m && day) ? new Date(+y, +m-1, +day) : new Date(d);
      return isNaN(dt) ? esc(d) : dt.toLocaleDateString('en-US', { month:'short', day:'numeric', year:'numeric' });
    };

    function buildTimelineHtml(info) {
      const hist = Array.isArray(info?.history) ? [...info.history] : [];
      if (!hist.length) {
        const d = info?.last_action_date || info?.status_date || '';
        const a = info?.last_action || 'No recent actions recorded';
        if (!d && !a) return '';
        const dateText = fmt(d);
        return dateText ? `<p><strong>${esc(dateText)}</strong><br>${esc(a)}</p>` : `<p>${esc(a)}</p>`;
      }

      hist.sort((a,b) => new Date(b.date || b.action_date || 0) - new Date(a.date || a.action_date || 0));

      const groupedByDate = new Map();
      hist.forEach(item => {
        const dateKey = item.date || item.action_date || '';
        const action = item.action || '';
        if (!groupedByDate.has(dateKey)) groupedByDate.set(dateKey, []);
        groupedByDate.get(dateKey).push(action);
      });

      const rows = Array.from(groupedByDate.entries()).map((entry, index) => {
        const [dateKey, actions] = entry;
        const dateText = fmt(dateKey);
        if (actions.length === 1) {
          const html = dateText ? `<p><strong>${esc(dateText)}</strong><br>${esc(actions[0])}</p>` : `<p>${esc(actions[0])}</p>`;
          return index < groupedByDate.size - 1 ? html + '<br>' : html;
        } else {
          const actionItems = actions.map(action => `• ${esc(action)}`).join('<br>');
          const html = dateText ? `<p><strong>${esc(dateText)}</strong><br>${actionItems}</p>` : `<p>${actionItems}</p>`;
          return index < groupedByDate.size - 1 ? html + '<br>' : html;
        }
      }).join('');

      return rows;
    }

    function buildSponsorsHtml(info, { state = "MN" } = {}) {
      const list = Array.isArray(info?.sponsors) ? [...info.sponsors] : [];
      if (!list.length) return "";

      const sponsorTypeRank = (typeId) => {
        if (typeId === 1) return 0; // Primary
        if (typeId === 3) return 1; // Joint
        return 999;                // Skip others
      };

      const prefixFor = (s) => {
        const roleId = Number(s?.role_id ?? 0);
        if (roleId === 1) return "Rep.";
        if (roleId === 2) return "Sen.";

        const roleText = String(s?.role ?? "").toLowerCase();
        if (roleText === "sen" || roleText === "senator") return "Sen.";
        if (roleText === "rep" || roleText === "representative") return "Rep.";

        const ch = String(s?.chamber ?? s?.chamber_id ?? s?.type ?? "").toLowerCase();
        if (ch === "s" || ch === "senate" || ch === "upper") return "Sen.";
        if (ch === "h" || ch === "house"  || ch === "lower") return "Rep.";

        const dist = String(s?.district ?? "");
        if (state === "MN") {
          if (/^\d{1,3}[A-B]$/i.test(dist)) return "Rep.";
          if (/^\d{1,3}$/.test(dist))       return "Sen.";
        }
        return "";
      };

      const filteredList = list.filter(s => sponsorTypeRank(s?.sponsor_type_id) < 999);
      filteredList.sort(
        (a, b) => sponsorTypeRank(a?.sponsor_type_id) - sponsorTypeRank(b?.sponsor_type_id) ||
                  (a?.name || "").localeCompare(b?.name || "")
      );

      const seen = new Set();
      const items = filteredList.filter((s) => {
        const key = [s?.name, s?.sponsor_type_id, s?.party, s?.district].join("|");
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
      });

      return items.map((s, i) => {
        const pref  = prefixFor(s);
        const name  = s?.name ? esc(s.name) : "";
        const party = s?.party ? ` (${esc(String(s.party))})` : "";
        const line  = `${pref} ${name}${party}`.trim();
        return i < items.length - 1 ? `<p>${line}</p><br>` : `<p>${line}</p>`;
      }).join("");
    }

    const createSlug = (text) =>
      text.toLowerCase()
        .replace(/[^a-z0-9\s-]/g, '')
        .replace(/\s+/g, '-')
        .replace(/-+/g, '-')
        .replace(/^-|-$/g, '')
        .substring(0, 80);

    async function patchStaging(itemId, data) {
      const u = `https://api.webflow.com/v2/collections/${COLLECTION_ID}/items/${itemId}`;
      return fetch(u, {
        method: "PATCH",
        headers: { Authorization: `Bearer ${WEBFLOW_TOKEN}`, "Content-Type": "application/json" },
        body: JSON.stringify(data),
      });
    }

    async function publishItems(itemIds) {
      const u = `https://api.webflow.com/v2/collections/${COLLECTION_ID}/items/publish`;
      return fetch(u, {
        method: "POST",
        headers: { Authorization: `Bearer ${WEBFLOW_TOKEN}`, "Content-Type": "application/json" },
        body: JSON.stringify({ itemIds }),
      });
    }

    // --- Fetch items --------------------------------------------------------
    let bills = [];
    
    if (webhookItemId) {
      // Webhook mode: fetch single item
      try {
        const itemRes = await fetch(`https://api.webflow.com/v2/collections/${COLLECTION_ID}/items/${webhookItemId}`, {
          headers: { Authorization: `Bearer ${WEBFLOW_TOKEN}` },
        });
        if (!itemRes.ok) throw new Error(`Webflow API error fetching item: ${itemRes.status}`);
        bills = [await itemRes.json()];
      } catch (err) {
        return res.status(500).json({ 
          success: false, 
          error: `Failed to fetch webhook item: ${err.message}`,
          webhookItemId 
        });
      }
    } else {
      // Manual/cron mode: fetch all items
      const listRes = await fetch(`https://api.webflow.com/v2/collections/${COLLECTION_ID}/items`, {
        headers: { Authorization: `Bearer ${WEBFLOW_TOKEN}` },
      });
      if (!listRes.ok) throw new Error(`Webflow API error: ${listRes.status}`);
      bills = (await listRes.json()).items || [];
    }

    // Get dynamic option ID mappings from schema
    const { bySlug, houseStatusIds, senateStatusIds } = await getOptionIdMaps();

    // --- Process items ------------------------------------------------------
    for (const bill of bills) {
      results.processed++;

      // Manual override
      if (bill.fieldData["manual-override"] === true) {
        results.skipped++;
        results.skipReasons.push({ id: bill.id, reason: "Manual override enabled" });
        continue;
      }

      const rawHouse = bill.fieldData["house-file-number"] || "";
      const rawSenate = bill.fieldData["senate-file-number"] || "";
      const currentName = bill.fieldData["name"]?.trim() || "";
      const jurisdictionId = bill.fieldData["jurisdiction"];
      const legislativeYear = bill.fieldData["legislative-year"]?.toString().trim();

      const { houseNumber, senateNumber, corrections } = normalizeNumbers(rawHouse, rawSenate);

      if (!houseNumber && !senateNumber) {
        results.skipped++; 
        results.skipReasons.push({ id: bill.id, reason: "No HF/SF number" });
        continue;
      }

      function inferStateFromNumber(h, s) {
        const n = String(h || s || "").toUpperCase();
        if (/^(HF|SF)\d+$/.test(n)) return "MN";
        if (/^(HB|SB|HR|SR|HJ|SJ|HC|SC)\d+$/.test(n)) return "US";
        return "MN";
      }

      const state = JURISDICTION_MAP[jurisdictionId] || inferStateFromNumber(houseNumber, senateNumber);

      try {
        const primaryNumber = houseNumber || senateNumber;
        const primaryInfo = await fetchLegiScanBill({ state, billNumber: primaryNumber, year: legislativeYear });

        let houseInfo = null, senateInfo = null;
        if (houseNumber && primaryNumber !== houseNumber) {
          await sleep(150);
          houseInfo = await fetchLegiScanBill({ state, billNumber: houseNumber, year: legislativeYear });
        } else {
          houseInfo = primaryInfo;
        }
        if (senateNumber && primaryNumber !== senateNumber) {
          await sleep(150);
          senateInfo = await fetchLegiScanBill({ state, billNumber: senateNumber, year: legislativeYear });
        } else {
          senateInfo = primaryInfo;
        }

        const updateData = { fieldData: {} };

        // Corrections
        Object.assign(updateData.fieldData, corrections);

        // Title
        let billTitle = currentName;
        if (isPlaceholderName(currentName, primaryNumber)) {
          billTitle = primaryInfo.title || primaryNumber;
          updateData.fieldData["name"] = billTitle;
        }

        // Status (separate) - now using enhanced detection with timeline analysis and dynamic session status
        if (houseNumber && houseInfo) {
          const statusKey = await computeStatusKey(houseInfo, { state, legislativeYear });
          updateData.fieldData["house-file-status"] = houseStatusIds[statusKey];
        }
        if (senateNumber && senateInfo) {
          const statusKey = await computeStatusKey(senateInfo, { state, legislativeYear });
          updateData.fieldData["senate-file-status"] = senateStatusIds[statusKey];
        }

        // --- Timelines -------------------------------------------------------------
        const houseTimelineHtml  = houseInfo  ? buildTimelineHtml(houseInfo)  : "";
        const senateTimelineHtml = senateInfo ? buildTimelineHtml(senateInfo) : "";

        // Combined (main timeline)
        const combinedTimelineHtml = buildTimelineHtml(primaryInfo);
        updateData.fieldData["timeline"] = combinedTimelineHtml || "";

        // Chamber-specific timelines
        updateData.fieldData["house-file-timeline"]  = houseNumber  ? (houseTimelineHtml  || "") : null;
        updateData.fieldData["senate-file-timeline"] = senateNumber ? (senateTimelineHtml || "") : null;

        // --- Sponsors (primary + per chamber) -------------------------------------
        const sponsorsHtml       = buildSponsorsHtml(primaryInfo, { state });
        const houseSponsorsHtml  = houseInfo  ? buildSponsorsHtml(houseInfo,  { state }) : "";
        const senateSponsorsHtml = senateInfo ? buildSponsorsHtml(senateInfo, { state }) : "";

        // Write ALL sponsor fields - combined and chamber-specific
        updateData.fieldData["sponsors"] = sponsorsHtml || "";
        updateData.fieldData["house-file-sponsors"] = houseNumber ? (houseSponsorsHtml || "") : null;
        updateData.fieldData["senate-file-sponsors"] = senateNumber ? (senateSponsorsHtml || "") : null;

        // Links
        if (houseNumber) {
          const link = pickBestTextUrl(houseInfo);
          if (link) updateData.fieldData["house-file-link"] = link;
        } else if (corrections["house-file-number"] === "") {
          updateData.fieldData["house-file-link"] = null;
        }

        if (senateNumber) {
          const link = pickBestTextUrl(senateInfo);
          if (link) updateData.fieldData["senate-file-link"] = link;
        } else if (corrections["senate-file-number"] === "") {
          updateData.fieldData["senate-file-link"] = null;
        }

        // Slug (top-level)
        if (legislativeYear && billTitle) {
          const billNumbers = [houseNumber, senateNumber].filter(Boolean).join('-').toLowerCase();
          const headlineSlug = createSlug(billTitle);
          const structuredSlug = `${legislativeYear}--${billNumbers || 'bill'}--${headlineSlug}`;
          updateData.slug = structuredSlug;
        }

        // Clean fieldData to only include fields that exist in schema
        const { cleaned, dropped } = cleanFieldData(updateData.fieldData, bySlug);
        if (dropped.length) {
          results.skipReasons.push({ id: bill.id, reason: `Dropped unknown fields: ${dropped.join(", ")}` });
        }

        if (!Object.keys(cleaned).length && !updateData.slug) {
          results.skipped++;
          results.skipReasons.push({ id: bill.id, reason: "No changes to apply" });
          continue;
        }

        const staging = await patchStaging(bill.id, { 
          fieldData: cleaned, 
          ...(updateData.slug ? { slug: updateData.slug } : {}) 
        });

        if (!staging.ok) {
          const body = await staging.json().catch(() => ({}));
          results.errors.push({
            billId: bill.id,
            error: `Staging update failed`,
            status: staging.status,
            message: body.message || staging.statusText,
            details: body.details || body,
            sentData: { fieldData: cleaned, slug: updateData.slug }
          });
          continue;
        }

        toPublish.push(bill.id);

        // Log-friendly summary (now with enhanced status detection)
        const houseStatusText = houseNumber ? await computeStatusKey(houseInfo, { state, legislativeYear }) : null;
        const senateStatusText = senateNumber ? await computeStatusKey(senateInfo, { state, legislativeYear }) : null;

        results.updated++;
        results.bills.push({
          id: bill.id,
          houseNumber,
          senateNumber,
          headline: updateData.fieldData.name || currentName,
          status: "staged",
          houseStatus: houseStatusText,
          senateStatus: senateStatusText,
          houseStatusCode: houseNumber && houseInfo ? houseInfo.status : null,
          senateStatusCode: senateNumber && senateInfo ? senateInfo.status : null,
          houseTimelinePreview: houseTimelineHtml ? "Timeline generated" : "No house timeline",
          senateTimelinePreview: senateTimelineHtml ? "Timeline generated" : "No senate timeline",
          sponsorsPreview: sponsorsHtml ? "Sponsors generated" : "No sponsors",
          houseSponsorsPreview: houseSponsorsHtml ? "House sponsors generated" : "No house sponsors",
          senateSponsorsPreview: senateSponsorsHtml ? "Senate sponsors generated" : "No senate sponsors",
          droppedFields: dropped.length ? dropped : undefined,
        });

        await sleep(120);
      } catch (err) {
        results.errors.push({ billId: bill.id, error: err.message });
      }
    }

    // --- Publish to LIVE in batches ----------------------------------------
    let publishedOk = 0;
    const CHUNK = 100;
    for (let i = 0; i < toPublish.length; i += CHUNK) {
      const slice = toPublish.slice(i, i + CHUNK);
      const pub = await publishItems(slice);
      const body = await pub.json().catch(() => ({}));

      if (!pub.ok) {
        results.errors.push({
          error: `Publish failed: ${body.message || body.error || pub.statusText}`,
          details: body,
          affectedItems: slice,
        });
      } else {
        const ids = Array.isArray(body.itemIds) ? body.itemIds
                 : Array.isArray(body.items) ? body.items.map(x => x.id)
                 : [];
        publishedOk += ids.length;
        results.bills.push({
          publishedCount: ids.length,
          itemIds: ids.length ? ids : slice
        });
      }
      await sleep(700);
    }

    return res.status(200).json({
      success: true,
      timestamp: results.timestamp,
      webhookMode: results.webhookMode,
      targetItemId: results.targetItemId,
      summary: {
        totalBills: bills.length,
        processed: results.processed,
        updated: results.updated,
        skipped: results.skipped,
        published: publishedOk,
        errors: results.errors.length
      },
      updatedBills: results.bills,
      skipReasons: results.skipReasons.length ? results.skipReasons : undefined,
      errors: results.errors.length ? results.errors : undefined,
    });
  } catch (error) {
    return res.status(500).json({ success: false, error: error.message, message: "Bills sync failed" });
  }
}
