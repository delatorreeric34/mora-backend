const functions = require("firebase-functions");
const admin = require("firebase-admin");
const axios = require("axios");
const cors = require("cors")({ origin: true });
const nodemailer = require("nodemailer");
const Fuse = require('fuse.js');
const constants = require('./constants');
const { getSynonymMap } = require("./helpers/synonymHelper");

// 🧩 Initialize Firebase Admin (required for Firestore access)
if (!admin.apps.length) {
    admin.initializeApp();
}
const db = admin.firestore();

function fuzzyMatchModifier(userInput, modifiers) {
    if (typeof userInput !== "string") {
        console.error("🚨 fuzzyMatchModifier called with non-string input:", userInput);
        return null;
    }
    const fuse = new Fuse(modifiers, { keys: ["name"], threshold: 0.4 });
    const result = fuse.search(userInput);
    return result.length ? result[0].item : null;
}

const {
    itemAliasMap,
    sizeAliasMap,
    variationAliasMap,
    modifierAliasMap,
    normalizedModifierAliasMap
} = constants;


function safeLower(input, context = "unknown") {
    if (typeof input !== "string") {
        console.warn(`⚠️ safeLower: expected string in ${context}, got type=${typeof input}, value=`, input);

        // 🟢 Emit consolidated snapshot if null source appears
        if (global.parsedItemsOrdered && Array.isArray(global.parsedItemsOrdered)) {
            console.error("📋 Null Source Debug Log — parsedItemsOrdered snapshot:", JSON.stringify(global.parsedItemsOrdered));
        } else {
            console.error("📋 Null Source Debug Log — parsedItemsOrdered snapshot unavailable");
        }

        // 🚫 Never crash: return empty string placeholder
        return "";
    }

    try {
        return input.toLowerCase();
    } catch (err) {
        console.error(`🚨 safeLower: failed to lower-case in ${context}`, err);
        return "";
    }
}

async function loadFuzzyItemAliases(clientId) {
    const aliasDocRef = db
        .collection("clients")
        .doc(clientId)
        .collection("aliases")
        .doc("item_aliases");

    const docSnap = await aliasDocRef.get();

    if (!docSnap.exists) {
        console.log(`⚠️ No alias document found for client ${clientId}`);
        return {};
    }

    const aliases = docSnap.data();
    console.log("🧠 Loaded fuzzy item aliases (from doc):", aliases);
    return aliases;
}

async function refreshSquareToken(client_id, refreshToken) {
    try {
        // 🧩 Determine correct Square environment for this client
        const envCfg = await getClientEnvironment(client_id, admin);
        const baseUrl = envCfg.square_environment === "production"
            ? "https://connect.squareup.com"
            : "https://connect.squareupsandbox.com";

        console.log(`🔁 [refreshSquareToken] Using baseUrl=${baseUrl} for client ${client_id}`);

        // 🔐 Determine correct client_id + client_secret from Firebase config
        const clientId = envCfg.square_environment === "production"
            ? functions.config().square.prod_client_id
            : (functions.config().square.sandbox_client_id || functions.config().square.client_id);

        const clientSecret = envCfg.square_environment === "production"
            ? functions.config().square.prod_client_secret
            : (functions.config().square.sandbox_client_secret || functions.config().square.client_secret);

        console.log(`🔐 [refreshSquareToken] Using client_id=${clientId ? "✅" : "❌"}, client_secret=${clientSecret ? "✅" : "❌"}`);

        // 🧠 Use dynamic credentials + environment for token refresh
        const res = await axios.post(`${baseUrl}/oauth2/token`, {
            client_id: clientId,
            client_secret: clientSecret,
            grant_type: "refresh_token",
            refresh_token: refreshToken,
        });

        const { access_token, refresh_token, expires_at } = res.data;

        await admin.firestore().collection("square_tokens").doc(client_id).update({
            access_token,
            refresh_token,
            expires_at,
            updated_at: admin.firestore.FieldValue.serverTimestamp(),
        });

        console.log(`✅ Token refreshed for ${client_id}`);
        return access_token;
    } catch (err) {
        console.error(`❌ Failed to refresh token for ${client_id}:`, err.response?.data || err.message);
        await sendFailureEmail(err);
        throw err;
    }
}


// 🧩 Per-client Square environment loader (sandbox / production)
async function getClientEnvironment(clientId) {
    try {
        // 🧩 Self-contained guard
        const adminLib = require("firebase-admin");
        if (!adminLib.apps.length) adminLib.initializeApp();
        const db = adminLib.firestore();

        console.log(`🧠 [getClientEnvironment] Loading environment for clientId="${clientId}"`);

        if (!clientId) {
            console.warn("🟡 [getClientEnvironment] Missing clientId — defaulting to sandbox");
            return { square_environment: "sandbox", is_demo: true, source: "default_missing_clientId" };
        }

        const snap = await db
            .collection("clients")
            .doc(clientId)
            .collection("config")
            .doc("env")
            .get();

        if (!snap.exists) {
            console.warn(`🟡 [getClientEnvironment] No env doc for ${clientId} — defaulting to sandbox`);
            return { square_environment: "sandbox", is_demo: true, source: "default_missing_doc" };
        }

        const data = snap.data() || {};
        const env = (data.square_environment || "sandbox").toLowerCase();
        const isDemo = typeof data.is_demo === "boolean" ? data.is_demo : (env === "sandbox");

        const normalized = {
            square_environment: env === "production" ? "production" : "sandbox",
            is_demo: isDemo,
            connected_at: data.connected_at || null,
            source: "firestore"
        };

        console.log(`✅ [getClientEnvironment] Resolved { env: ${normalized.square_environment}, is_demo: ${normalized.is_demo}, source: ${normalized.source} }`);
        return normalized;
    } catch (err) {
        console.error("🛑 [getClientEnvironment] Error loading env, defaulting to sandbox:", err?.message || err);
        return { square_environment: "sandbox", is_demo: true, source: "default_error" };
    }
}

const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: "delatorre.eric34@gmail.com",       // change this
        pass: "hdfbiqbaocnbpyvw",                  // use your Gmail App Password
    },
});

function sendFailureEmail(error) {
    const mailOptions = {
        from: "delatorre.eric34@gmail.com",       // same as above
        to: "delatorre.eric34@gmail.com",
        subject: "🚨 Square Token Refresh Failed",
        text: `The Square OAuth token refresh failed:\n\n${error.stack || error.message || error}`,
    };

    return transporter.sendMail(mailOptions);
}

exports.refreshSquareTokens = functions.pubsub
    .schedule("every 600 hours") // ✅ 25 days
    .timeZone("America/Los_Angeles")
    .onRun(async (context) => {
        try {
            const snapshot = await db.collection("tokens").get();

            if (snapshot.empty) {
                console.log("⚠️ No client documents found in square_tokens.");
                return null;
            }

            const refreshTasks = snapshot.docs.map(async (doc) => {
                const data = doc.data();
                if (!data?.refresh_token) {
                    console.warn(`⚠️ No refresh_token for ${doc.id}`);
                    return;
                }

                const result = await refreshSquareToken(doc.id, data.refresh_token);

                // 📝 Added log so you can track each token’s new expiry
                if (result?.expires_at) {
                    console.log(`✅ Token refreshed for client_id=${doc.id}, new expires_at=${result.expires_at}`);
                } else {
                    console.warn(`⚠️ Token refresh for client_id=${doc.id} returned no expires_at`);
                }

                return result;
            });

            await Promise.all(refreshTasks);
            console.log("✅ All tokens refreshed successfully.");
        } catch (err) {
            console.error("❌ Error refreshing Square tokens:", err);
            await sendFailureEmail(err);
        }
    });

exports.manualRefreshToken = functions.https.onRequest(async (req, res) => {
    const client_id = req.query.client_id;
    if (!client_id) {
        return res.status(400).send("Missing client_id in query params.");
    }

    try {
        // 🧠 Step 1 — Try primary tokens collection
        let doc = await db.collection("tokens").doc(client_id).get();

        // 🧩 Step 2 — Fallback to legacy collection if not found
        if (!doc.exists) {
            console.warn(`🟡 No token in /tokens, checking /square_tokens for ${client_id}...`);
            doc = await db.collection("square_tokens").doc(client_id).get();
        }

        // 🧩 Step 3 — Still nothing? Look up by merchant_id field in both collections
        if (!doc.exists) {
            console.warn(`🟡 No direct doc found, searching by merchant_id field...`);
            const tokensRef = db.collection("tokens");
            const querySnap = await tokensRef.where("merchant_id", "==", client_id).limit(1).get();
            if (!querySnap.empty) {
                doc = querySnap.docs[0];
                console.log(`✅ Found token via merchant_id match: ${doc.id}`);
            }
        }

        if (!doc.exists) {
            console.error(`❌ No token found for client_id or merchant_id: ${client_id}`);
            return res.status(404).send(`No token found for client_id: ${client_id}`);
        }

        const data = doc.data();

        // 🧩 Dynamically find which client this merchant_id belongs to
        const mappingSnap = await admin.firestore()
            .collection("clients")
            .where("merchant_id", "==", client_id)
            .limit(1)
            .get();

        let resolvedClientId;
        if (!mappingSnap.empty) {
            resolvedClientId = mappingSnap.docs[0].id;
            console.log(`🔍 Found client mapping: merchant_id=${client_id} → clientId=${resolvedClientId}`);
        } else {
            console.warn(`⚠️ No client mapping found for merchant_id=${client_id}, defaulting to 'default'`);
            resolvedClientId = "default"; // fallback
        }

        // 🧭 Now load the right environment dynamically
        const envCfg = await getClientEnvironment(resolvedClientId, admin);
        const baseUrl =
            envCfg.square_environment === "production"
                ? "https://connect.squareup.com"
                : "https://connect.squareupsandbox.com";

        console.log(`🔁 [manualRefreshToken] Using baseUrl=${baseUrl} for client ${client_id}`);

        // 🧭 Choose correct credentials based on environment
        const creds =
            envCfg.square_environment === "production"
                ? {
                    id: functions.config().square.prod_client_id,
                    secret: functions.config().square.prod_client_secret,
                }
                : {
                    id: functions.config().square.client_id,
                    secret: functions.config().square.client_secret,
                };

        const response = await axios.post(`${baseUrl}/oauth2/token`, {
            client_id: creds.id,
            client_secret: creds.secret,
            grant_type: "refresh_token",
            refresh_token: data.refresh_token,
        });

        const { access_token, refresh_token, expires_at } = response.data;

        // 🧩 Step 4 — Write token update with backward compatibility
        const targetCollection = doc.ref.path.includes("/square_tokens")
            ? "square_tokens"
            : "tokens";

        await db.collection(targetCollection).doc(doc.id).update({
            access_token,
            refresh_token,
            expires_at,
            updated_at: admin.firestore.FieldValue.serverTimestamp(),
        });

        console.log(`✅ Token refreshed and updated for client_id: ${client_id}`);
        res.send(`✅ Token refreshed for client_id: ${client_id}`);
    } catch (err) {
        console.error(`❌ Error refreshing token for client_id: ${client_id}`, err.response?.data || err.message);
        res.status(500).send("❌ Token refresh failed.");
    }
});

exports.squareProxy = functions.https.onRequest(async (req, res) => {
    try {
        // 🧠 Accept either ?client_id= or ?merchant_id=
        let clientId = req.query.client_id || null;
        const merchantId = req.query.merchant_id || null;

        if (!clientId && !merchantId) {
            return res.status(400).json({ error: "Missing client_id or merchant_id query param" });
        }

        // 🔁 If only merchant_id provided, resolve to clientId via mapping
        if (!clientId && merchantId) {
            const mappingSnap = await db.collection("mappings").doc(merchantId).get();
            if (mappingSnap.exists) {
                clientId = mappingSnap.data().clientId;
                console.log(`🧩 [squareProxy] Resolved clientId "${clientId}" from merchant_id "${merchantId}"`);
            } else {
                console.warn(`⚠️ [squareProxy] No mapping found for merchant_id "${merchantId}" — using same ID`);
                clientId = merchantId;
            }
        }

        // 🧩 Step 1: Get access token for merchant_id (preferred)
        let tokenDoc = await db.collection("tokens").doc(merchantId || clientId).get();
        if (!tokenDoc.exists) {
            console.warn(`🟡 No token in /tokens for ${merchantId || clientId}, checking /square_tokens...`);
            tokenDoc = await db.collection("square_tokens").doc(merchantId || clientId).get();
        }

        if (!tokenDoc.exists) {
            return res.status(404).json({ error: "Merchant/client ID not found in database" });
        }

        const { access_token } = tokenDoc.data();

        // 🧭 Step 2: Resolve true clientId (used for environment)
        let resolvedClientId = merchantId;
        const mappingSnap = await db.collection("mappings").doc(merchantId).get();
        if (mappingSnap.exists) {
            resolvedClientId = mappingSnap.data().clientId;
            console.log(`🧠 [squareProxy] Resolved clientId "${resolvedClientId}" from merchant_id "${merchantId}"`);
        } else {
            console.warn(`⚠️ [squareProxy] No mapping found for merchant_id "${merchantId}" — using same ID`);
        }

        // 🧩 Step 3: Load environment for the resolved clientId
        const envCfg = await getClientEnvironment(resolvedClientId);
        console.log(`🌍 [squareProxy] Environment resolved: ${envCfg.square_environment}`);

        // 🧱 Step 4: Build full Square API URL
        const urlObj = new URL(req.url, `https://${req.headers.host}`);
        const squarePath = urlObj.searchParams.get("path") || req.path.replace(/^\/squareProxy/, "");
        const baseUrl =
            envCfg.square_environment === "production"
                ? "https://connect.squareup.com"
                : "https://connect.squareupsandbox.com";

        const squareApiUrl = `${baseUrl}${squarePath}`;
        console.log("🌐 Square API URL:", squareApiUrl);
        console.log("🔁 Proxying request with method:", req.method);

        // 📨 Step 5: Forward request to Square
        const squareRes = await axios({
            method: req.method,
            url: squareApiUrl,
            headers: {
                Authorization: `Bearer ${access_token}`,
                "Content-Type": req.get("Content-Type") || "application/json",
            },
            ...(req.method !== "GET" && { data: req.body }),
        });

        // 🧩 Step 6: Optional log for catalog responses
        if (squarePath.startsWith("/v2/catalog/list") || squarePath.startsWith("/v2/catalog/search")) {
            const count = squareRes.data?.objects?.length || 0;
            console.log(`📦 Returning catalog with ${count} items`);
        }

        return res.status(squareRes.status).json(squareRes.data);

    } catch (err) {
        console.error("❌ Proxy error:", {
            message: err.message,
            status: err.response?.status,
            data: err.response?.data
        });

        return res.status(500).json({
            error: "Proxy request failed",
            message: err.message,
            square_error: err.response?.data || null
        });
    }
});


exports.selfTest = functions.https.onRequest(async (req, res) => {
    try {
        let client_id = req.query.client_id || req.body.client_id;

        if (!client_id) {
            console.warn("⚠️ No client_id provided. Falling back to MLGFXWAYKSXM6 (dev mode).");
            client_id = "MLGFXWAYKSXM6";
        }

        const tokenSnap = await admin.firestore().collection("tokens").doc(client_id).get();

        if (!tokenSnap.exists) {
            throw new Error(`Token not found for client_id: ${client_id}`);
        }

        res.send(`✅ Self-test passed for client_id: ${client_id}`);
    } catch (error) {
        console.error("❌ Self-test failure:", error.message || error);
        await sendFailureEmail(error);
        res.status(500).send("❌ Self-test failed and email sent.");
    }
});

exports.handleRedirect = functions.https.onRequest(async (req, res) => {
    // ✅ Parse query parameters
    const authCode = req.query.code;
    const error = req.query.error;

    // 🧠 Added — Define redirect destinations
    const SUCCESS_PAGE = '/oauth-success.html';
    const FAILURE_PAGE = '/oauth-failed.html';

    // 🚫 Handle error returned from Square (user denied access, etc.)
    if (error) {
        console.error("❌ OAuth error:", error);
        return res.redirect(`${FAILURE_PAGE}?reason=${encodeURIComponent(error)}`); // 🧠 Added
    }

    // ⚠️ Handle missing authorization code
    if (!authCode) {
        console.error("❌ No authorization code found.");
        return res.redirect(`${FAILURE_PAGE}?reason=missing_code`); // 🧠 Added
    }

    // Optional: Store the code temporarily in Firestore
    await db.collection("square_oauth_codes").add({
        code: authCode,
        received_at: admin.firestore.FieldValue.serverTimestamp(),
    });

    console.log("✅ Received OAuth code:", authCode);

    // 🧠 Redirect to hosted success page (instead of inline HTML)
    return res.redirect(SUCCESS_PAGE); // 🧠 Added
});

// Firebase Cloud Function: exchangeCodeForToken
exports.exchangeCodeForToken = functions.https.onRequest(async (req, res) => {
    try {
        // Step 1: Get the latest auth code from Firestore
        const snapshot = await db
            .collection("square_auth_codes")
            .orderBy("timestamp", "desc")
            .limit(1)
            .get();

        if (snapshot.empty) {
            return res.status(404).send("❌ No authorization codes found.");
        }

        const codeDoc = snapshot.docs[0].data();
        const authCode = codeDoc.authorization_code;
        const clientId = functions.config().square.client_id;
        const clientSecret = functions.config().square.client_secret;

        // Step 2: Send code to Square to get tokens
        // 🧩 Determine correct environment for this OAuth exchange
        // Try to infer the client ID from the latest auth code doc if stored, otherwise default to sandbox
        const inferredClientId = codeDoc.client_id || "default";
        const envCfg = await getClientEnvironment(inferredClientId, admin);

        const baseUrl =
            envCfg.square_environment === "production"
                ? "https://connect.squareup.com"
                : "https://connect.squareupsandbox.com";

        console.log(`🧭 [exchangeCodeForToken] Using ${envCfg.square_environment.toUpperCase()} | baseUrl=${baseUrl}`);

        const response = await axios.post(`${baseUrl}/oauth2/token`, {
            client_id: clientId,
            client_secret: clientSecret,
            code: authCode,
            grant_type: "authorization_code",
        });


        const {
            access_token,
            refresh_token,
            expires_at,
            merchant_id,
        } = response.data;

        // Step 3: Save tokens to Firestore
        await db.collection("tokens").doc(merchant_id).set({
            access_token,
            refresh_token,
            expires_at,
            merchant_id,
            updated_at: admin.firestore.FieldValue.serverTimestamp(),
        });

        console.log("✅ Token exchange successful for:", merchant_id);
        res.send("✅ Successfully exchanged code for tokens.");
    } catch (err) {
        console.error("❌ Token exchange failed:", err.response?.data || err.message);
        res.status(500).send("❌ Token exchange failed.");
    }
});

exports.getToken = functions.https.onRequest(async (req, res) => {
    const { id } = req.query;

    if (!id) {
        return res.status(400).json({ error: "Missing client ID (?id=...)" });
    }

    try {
        const doc = await admin.firestore().collection("square_tokens").doc(id).get();

        if (!doc.exists) {
            return res.status(404).json({ error: "No token found for this client ID" });
        }

        const data = doc.data();
        return res.status(200).json({ access_token: data.access_token });
    } catch (err) {
        console.error("❌ Proxy error:", JSON.stringify(err.response?.data || err.message));
        return res.status(500).json({ error: "Proxy request failed", details: err.response?.data || err.message });
    }
});

exports.handleOAuthRedirect = functions.https.onRequest(async (req, res) => {
    const code = req.query.code;
    if (!code) return res.status(400).send("Missing authorization code");

    try {
        // 🧩 Determine correct Square environment
        const inferredClientId = req.query.state || req.query.client_id || "default";

        const envCfg = await getClientEnvironment(inferredClientId, admin);

        const isProduction = envCfg.square_environment === "production";
        const baseUrl = isProduction
            ? "https://connect.squareup.com"
            : "https://connect.squareupsandbox.com";

        // 🧩 Unified credential loader (handles both sandbox + production)
        const clientId =
            envCfg.square_environment === "production"
                ? functions.config().square.prod_client_id
                : (functions.config().square.sandbox_client_id || functions.config().square.client_id);

        const clientSecret =
            envCfg.square_environment === "production"
                ? functions.config().square.prod_client_secret
                : (functions.config().square.sandbox_client_secret || functions.config().square.client_secret);

        console.log(`🔑 [handleOAuthRedirect] Loaded client_id=${clientId ? "✅" : "❌"}, client_secret=${clientSecret ? "✅" : "❌"}`);

        const redirect_uri =
            "https://us-central1-ai-voice-agent-14f7e.cloudfunctions.net/handleOAuthRedirect";

        // 🧠 Debug info
        console.log("🔑 OAuth Debug – client_id:", clientId);
        console.log("🔑 OAuth Debug – client_secret:", clientSecret);
        console.log("📦 OAuth Debug – code:", code);
        console.log("↩️ OAuth Debug – redirect_uri:", redirect_uri);
        console.log(`🧭 [handleOAuthRedirect] Using ${envCfg.square_environment.toUpperCase()} | baseUrl=${baseUrl}`);

        // 🔁 Exchange code for access token
        const response = await axios.post(`${baseUrl}/oauth2/token`, {
            client_id: clientId,
            client_secret: clientSecret,
            code,
            grant_type: "authorization_code",
            redirect_uri
        });

        console.log("✅ OAuth Success Response:", response.data);
        const { access_token, refresh_token, expires_at, merchant_id } = response.data;

        await admin.firestore().collection("tokens").doc(merchant_id).set({
            access_token,
            refresh_token,
            expires_at,
            merchant_id,
            created_at: new Date().toISOString(),
        });

        // 📦 Pull catalog data
        const catalogResponse = await axios.get(`${baseUrl}/v2/catalog/list?types=ITEM`, {
            headers: {
                Authorization: `Bearer ${access_token}`,
                "Square-Version": "2023-12-13",
                "Content-Type": "application/json",
            },
        });

        await admin.firestore().collection("catalogs").doc(merchant_id).set({
            catalog_debug_json: catalogResponse.data,
            updated_at: new Date().toISOString(),
        });

        // 🧩 Trigger automatic catalog ingestion after successful OAuth
        try {
            console.log(`🚀 [handleOAuthRedirect] Triggering automatic catalog ingestion for ${merchant_id}`);

            // 🔁 Call the ingestCatalog function to pull the restaurant's menu
            await axios.post(
                "https://us-central1-ai-voice-agent-14f7e.cloudfunctions.net/ingestCatalog",
                { client_id: merchant_id }
            );

            console.log(`✅ [handleOAuthRedirect] Catalog ingestion triggered successfully for ${merchant_id}`);
        } catch (ingestErr) {
            console.error("⚠️ [handleOAuthRedirect] Failed to trigger catalog ingestion:", ingestErr.message);

            // 📧 Email alert if ingestion fails
            try {
                const envLabel = envCfg.square_environment?.toUpperCase() || "UNKNOWN";
                console.log(`🧠 [handleOAuthRedirect] Email alert context → client_id=${merchant_id}, env=${envLabel}`);

                await sendAlertEmail(
                    `🚨 ${envLabel} Catalog Ingestion Failed`,
                    `Automatic ingestion failed for client_id: ${merchant_id}\nEnvironment: ${envLabel}\n\nError: ${ingestErr.message}`
                );

                console.log(`📧 [handleOAuthRedirect] Alert email sent for failed ingestion (${envLabel}).`);
            } catch (emailErr) {
                console.error("⚠️ [handleOAuthRedirect] Failed to send ingestion alert email:", emailErr.message);
            }
        }

        // ✅ Redirect on success
        return res.redirect("https://ai-voice-agent-14f7e.web.app/success.html");

    } catch (err) {
        console.error("❌ OAuth redirect error:", err.response?.data || err.message);
        return res.status(500).send("OAuth setup failed. Check logs.");
    }
});


exports.handleSquareDisconnect = functions.https.onRequest(async (req, res) => {
    try {
        const { merchant_id, client_id } = req.body;

        console.log("🔌 Square Disconnect received:", { merchant_id, client_id });

        if (!merchant_id) {
            console.error("❌ Missing merchant_id in disconnect payload");
            return res.status(400).send("Missing merchant_id");
        }

        // Delete merchant tokens from Firestore
        await admin.firestore().collection("tokens").doc(merchant_id).delete();

        // Optionally also delete catalog data (cleanup)
        await admin.firestore().collection("catalogs").doc(merchant_id).delete();

        console.log(`✅ Successfully removed tokens and catalog for merchant ${merchant_id}`);

        // Redirect to your hosted Disconnect confirmation page
        return res.redirect("https://conversight-ai.web.app/oauth/disconnect");
    } catch (error) {
        console.error("❌ Disconnect handler error:", error.message);
        return res.status(500).send("Disconnect handler failed");
    }
});

// 🧩 --- Verify intents_config Import ---
exports.checkIntentsConfig = functions.https.onRequest(async (req, res) => {
    try {
        const clientId = req.query.client_id;
        if (!clientId) return res.status(400).send("Missing client_id");

        const docRef = db.collection("clients").doc(clientId).collection("config").doc("env");
        const intentsRef = db.collection("clients").doc(clientId).collection("intents_config");
        // Allow both document or subcollection storage styles
        let data;

        // Try as single document first
        const directDoc = await db.collection("clients").doc(clientId).collection("intents_config").get();
        if (!directDoc.empty) {
            data = {};
            directDoc.forEach(d => (data[d.id] = d.data()));
        } else {
            const alt = await db.collection("clients").doc(clientId).get();
            if (alt.exists && alt.data().intents_config) data = alt.data().intents_config;
        }

        if (!data) return res.status(404).send("intents_config not found for this client");

        console.log(`✅ [checkIntentsConfig] Found intents_config for ${clientId}`);
        return res.status(200).json({ client_id: clientId, intents_config: data });
    } catch (err) {
        console.error("❌ [checkIntentsConfig] Error:", err.message);
        return res.status(500).send(`Error: ${err.message}`);
    }
});



// 🧩 --- Seed default intents_config into Firestore ---
const defaultIntentsConfig = require("./intents_config_default.json");

exports.seedIntentsConfig = functions.https.onRequest(async (req, res) => {
    try {
        const clientId = req.query.client_id;
        if (!clientId) return res.status(400).send("Missing client_id");

        await db.collection("clients").doc(clientId).set(
            { intents_config: defaultIntentsConfig },
            { merge: true }
        );

        console.log(`✅ [seedIntentsConfig] Seeded intents_config for ${clientId}`);
        res.status(200).send(`Seeded intents_config for ${clientId}`);
    } catch (err) {
        console.error("❌ [seedIntentsConfig] Error:", err.message);
        res.status(500).send(`Error: ${err.message}`);
    }
});

// 🧠 --- Get AI FAQ Response ---
exports.getAIResponse = functions.https.onRequest(async (req, res) => {
    try {
        const clientId = req.body?.client_id;
        const user_input = req.body?.user_input?.toLowerCase();

        if (!clientId || !user_input) {
            return res.status(400).json({
                success: false,
                message: "Missing client_id or user_input"
            });
        }

        console.log(`💬 [getAIResponse] Looking up FAQ for client: ${clientId}`);

        // --- Fetch client's FAQ config ---
        const clientDoc = await db.collection("clients").doc(clientId).get();
        const config = clientDoc.data()?.intents_config;
        if (!config?.ai_faqs) {
            console.warn(`⚠️ [getAIResponse] No ai_faqs found for ${clientId}`);
            return res.status(404).json({
                success: false,
                message: "No FAQs configured for this client"
            });
        }

        const ai_faqs = config.ai_faqs;

        // 🧠 Load universal synonym map
        const synonymMap = await getSynonymMap(clientId);

        // 🔍 Try to find a match via key or any synonym
        const matchKey = Object.keys(ai_faqs).find(key => {
            const synonyms = synonymMap[key] || [];
            return [key.toLowerCase(), ...synonyms.map(s => s.toLowerCase())]
                .some(term => user_input.includes(term));
        });

        // ⚠️ Fallback — if no FAQ matched
        if (!matchKey) {
            console.log(`🟡 [getAIResponse] No FAQ match found for: "${user_input}"`);
            return res.status(200).json({
                success: true,
                faq_found: false,
                response_text: "I'm sorry, I don’t have that information right now."
            });
        }

        const responseText = ai_faqs[matchKey];
        console.log(`✅ [getAIResponse] Matched "${matchKey}" → "${responseText}"`);

        return res.status(200).json({
            success: true,
            faq_found: true,
            faq_key: matchKey,
            response_text: responseText
        });

    } catch (err) {
        console.error("❌ [getAIResponse] Error:", err.message);
        return res.status(500).json({
            success: false,
            message: `Error: ${err.message}`
        });
    }
});

// functions/helpers/synonymHelper.js

// 🔁 Shared synonym map logic for AI FAQ and Intent detection
exports.getSynonymMap = async () => {
    return {
        hours: ["hour", "hours", "open", "close", "closing", "opening", "what time"],
        wifi: ["wi-fi", "internet", "wifi access"],
        parking: ["parking", "lot", "car", "garage"],
        delivery: ["delivery", "deliver", "door dash", "uber eats", "grubhub"],
        payment_methods: ["apple pay", "credit", "debit", "cash", "contactless"],
        location: ["address", "where are you", "location", "nearby"],
        takeout: ["takeout", "pick up", "to go", "carryout"],
        pet_policy: ["dog", "pet", "animal"],
        family_friendly: ["kids", "child", "family"],
        catering: ["catering", "large order", "event", "party", "bulk"]
    };
};

// 🕓 --- Check Business Hours (Multi-tenant real-time check) ---
exports.checkBusinessHours = functions.https.onRequest(async (req, res) => {
    console.log("🧠 [checkBusinessHours] Request received:", req.body);

    try {
        const { client_id } = req.body;
        if (!client_id) {
            console.log("🚫 [checkBusinessHours] Missing client_id");
            return res.status(400).json({ success: false, error: "Missing client_id" });
        }

        const clientDoc = await db.collection("clients").doc(client_id).get();
        if (!clientDoc.exists) {
            console.log(`🚫 [checkBusinessHours] Client ${client_id} not found`);
            return res.status(404).json({ success: false, error: "Client not found" });
        }

        // --- Load normal hours first ---
        const configDoc = await db
            .collection("clients")
            .doc(client_id)
            .collection("config")
            .doc("business_hours")
            .get();

        if (!configDoc.exists) {
            console.log(`🚫 [checkBusinessHours] No business_hours doc found for client ${client_id}`);
            return res.status(200).json({
                success: true,
                after_hours: false,
                note: "Missing business_hours doc"
            });
        }

        // Extract standard hours
        let { open_hour, close_hour, timezone } = configDoc.data();
        if (open_hour === undefined || close_hour === undefined || !timezone) {
            console.log("⚠️ [checkBusinessHours] Missing business_hours data in config");
            return res.status(200).json({ success: true, after_hours: false, note: "Missing hours config" });
        }

        // 🗓️ --- Holiday override check ---
        const todayDate = new Date().toLocaleDateString("en-CA", { timeZone: timezone }); // YYYY-MM-DD
        const holidayDoc = await db
            .collection("clients")
            .doc(client_id)
            .collection("config")
            .doc("holiday_hours")
            .collection("date")
            .doc(todayDate)
            .get();

        if (holidayDoc.exists) {
            const holiday = holidayDoc.data();
            console.log(`🎄 [checkBusinessHours] Holiday override found: ${holiday.label}`);

            // Full-day closure
            if (holiday.is_closed) {
                return res.status(200).json({
                    success: true,
                    after_hours: true,
                    note: `Closed for ${holiday.label}`
                });
            }

            // Override regular hours if provided
            if (holiday.open_hour !== undefined) open_hour = holiday.open_hour;
            if (holiday.close_hour !== undefined) close_hour = holiday.close_hour;
        }

        // --- Determine open/closed state ---
        const now = new Date();
        const localHour = parseInt(
            now.toLocaleString("en-US", { timeZone: timezone, hour: "numeric", hour12: false })
        );

        const afterHours = localHour < open_hour || localHour >= close_hour;

        console.log(
            `🧩 [checkBusinessHours] Client ${client_id} local hour: ${localHour} (${timezone}) — Open: ${open_hour}, Close: ${close_hour} — After Hours: ${afterHours}`
        );

        res.status(200).json({
            success: true,
            after_hours: afterHours,
            local_hour: localHour,
            timezone,
        });
    } catch (err) {
        console.error("❌ [checkBusinessHours] Error:", err.message);
        res.status(500).json({ success: false, error: err.message });
    }
});


function normalizeSize(size, item = {}, descriptorTerms = new Set()) {
    if (size == null || typeof size !== "string") {
        console.warn("⚠️ normalizeSize received non-string input:", size);
        return "";
    }

    let normalized = size
        .toLowerCase()
        .replace(/\bounces?\b/g, "oz")
        .replace(/\s+/g, "")
        .replace(/[^a-z0-9]/g, "")
        .trim();

    // 🧩 Preserve common mixed tokens like "20oz", "16oz", "24oz"
    const numericOzMatch = normalized.match(/^(\d{1,2})oz$/);
    if (numericOzMatch) {
        const final = numericOzMatch[0];
        console.log(`🧪 normalizeSize("${size}") → "${final}" (numeric-oz match)`);
        return final;
    }

    // 🧊 Dynamically detect and extract descriptors from catalog-driven set
    if (descriptorTerms && descriptorTerms.size > 0) {
        for (const term of descriptorTerms) {
            if (!term) continue;
            const cleanTerm = term.replace(/[^a-z0-9]/g, "");
            if (!cleanTerm) continue;

            if (normalized.includes(cleanTerm)) {
                normalized = normalized.replace(cleanTerm, "");
                item.detectedDescriptors = item.detectedDescriptors || [];
                if (!item.detectedDescriptors.includes(term)) {
                    item.detectedDescriptors.push(term);
                    console.log(`🧊 Extracted descriptor "${term}" from size for "${item.name || 'unknown'}"`);
                }
            }
        }
        normalized = normalized.trim();
    }

    const final =
        sizeAliasMap[normalized] ||
        (/^\d+$/.test(normalized) ? `${normalized}oz` : normalized);

    console.log(`🧪 normalizeSize("${size}") → "${final}" (normalized="${normalized}")`);
    return final;
}


function fixDetachedModifiers(items, original_user_input = "") {
    const correctedItems = [];
    const lowerInput = safeLower(original_user_input || "", "fixDetachedModifiers.original_user_input");

    console.log("🟡 [fixDetachedModifiers] incoming items:", JSON.stringify(items));

    for (let i = 0; i < items.length; i++) {
        const item = items[i];
        console.log(`🔍 [fixDetachedModifiers] inspecting item[${i}]:`, JSON.stringify(item));

        const isDetachedModifier = !item.name && item.modifiers;
        const isMisparsedModifierOnly = typeof item === "string" && i > 0;

        if (isDetachedModifier && correctedItems.length > 0) {
            const prevItem = correctedItems[correctedItems.length - 1];
            const mods = Array.isArray(item.modifiers) ? item.modifiers : [item.modifiers];

            console.log(`⚠️ [fixDetachedModifiers] Detected detached modifier(s):`, mods);

            // ✅ Only attach if customer explicitly said it
            const attached = mods.filter(m => lowerInput.includes(safeLower(m, "fixDetachedModifiers.detachedMod")));
            console.log(`👉 [fixDetachedModifiers] Attaching to prevItem "${prevItem.name}" →`, attached);

            prevItem.modifiers = [
                ...(prevItem.modifiers || []),
                ...attached
            ];
        } else if (isMisparsedModifierOnly && correctedItems.length > 0) {
            const prevItem = correctedItems[correctedItems.length - 1];
            const lower = safeLower(item, "fixDetachedModifiers.stringOnlyMod").trim();

            console.log(`⚠️ [fixDetachedModifiers] Misparsed string-only modifier: "${lower}"`);

            // ✅ Only attach if explicitly spoken
            if (lowerInput.includes(lower)) {
                console.log(`👉 [fixDetachedModifiers] Attaching "${lower}" to prevItem "${prevItem.name}"`);
                prevItem.modifiers = [...(prevItem.modifiers || []), item];
            }
        } else {
            correctedItems.push(item);
        }
    }

    // 🧹 Final sweep: strip only rogue/unspoken mods
    const fullyCorrected = correctedItems.map(it => {
        if (!it.modifiers || !Array.isArray(it.modifiers)) return it;

        // 🔑 Catalog-driven trust: if item has allowed modifier lists,
        // we assume its modifiers are valid (Square catalog enforces them).
        const allowedFromCatalog = new Set(it.allowed_modifier_lists || []);

        const filtered = it.modifiers.filter(m => {
            if (!m || typeof m !== "string") return false;
            const modNorm = safeLower(m, "fixDetachedModifiers.finalSweep").trim();

            if (allowedFromCatalog.size > 0) {
                // ✅ TRUST CATALOG: keep all modifiers for items that declare allowed lists
                return true;
            }

            // 🛡️ If Blend already passed this modifier in the payload, trust it
            if (Array.isArray(it.modifiers) && it.modifiers.includes(m)) {
                console.log(`✅ Keeping "${m}" for "${it.name}" (trusted from Blend payload)`);
                return true;
            }

            // 🛡️ FALLBACK: only keep if explicitly spoken by the customer
            const lowerInput = (original_user_input && typeof original_user_input === "string")
                ? safeLower(original_user_input, "fixDetachedModifiers.finalSweepInput")
                : "";
            const spoken = lowerInput.includes(modNorm);

            console.log(
                `${spoken ? "🗣️ Keeping" : "🚫 Dropping"} "${m}" for "${it.name}" (spoken match=${spoken})`
            );
            return spoken;
        });

        // 📝 Diagnostic: log when something gets stripped
        if (filtered.length !== it.modifiers.length) {
            console.log(
                `🧹 fixDetachedModifiers → Stripped unspoken mods for "${it.name}" | before=[${it.modifiers.join(", ")}] after=[${filtered.join(", ")}]`
            );
        }

        return { ...it, modifiers: filtered };
    });

    return fullyCorrected;
}

// 🔬 Global monkey patch to catch all null.toLowerCase crashes
const originalToLowerCase = String.prototype.toLowerCase;
String.prototype.toLowerCase = function (...args) {
    if (this == null) {
        console.error("🚨 GLOBAL PATCH: toLowerCase called on null or undefined!", {
            value: this,
            stack: new Error().stack.split("\n").slice(0, 5) // top of stack only
        });
        return ""; // safe fallback
    }
    return originalToLowerCase.apply(this, args);
};

exports.createSquareOrder = functions.https.onRequest(async (req, res) => {
    // 🧭 Global state flags (function-wide, TDZ-safe)
    let validCorrection = false;
    const rawBody = req.rawBody?.toString();
    console.log("🟢 Raw Body received"); // lighter than full dump

    console.log("🗣️ Debug — user input snapshot:", {
        from_body_original_user_input: req.body?.original_user_input || null,
        from_body_user_intent: req.body?.user_intent || null,
        raw_keys: Object.keys(req.body || {})
    });

    // 🌎 Global tracking arrays for validation
    let globalInvalidItems = [];
    let globalInvalidModifiers = [];
    let globalValidItems = [];
    let globalValidModifiers = [];
    let clarification_needed_items = [];
    // 🧩 Safe early guard for modifier references
    let allModifierNames = [];

    // 🧱 Global retry_prompt placeholder to avoid TDZ issues
    let retry_prompt = "";

    try {
        global.parsedItemsOrdered = [];  // 🟢 Initialize snapshot holder

        // Parse JSON safely
        let body;
        try {
            body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
            console.log(`🧪 Parsed body with ${body?.items_ordered?.length || 0} items, client_id=${body?.client_id}`);
        } catch (err) {
            console.error("❌ Failed to parse incoming JSON:", err.message);
            return res.status(400).json({ success: false, message: "Invalid JSON format" });
        }

        // Guardrail for empty payload
        if (!body || Object.keys(body).length === 0) {
            console.warn("⚠️ Empty or invalid body received — likely a fallback webhook hit. Skipping.");
            return res.status(400).json({ success: false, message: "Empty or invalid request body" });
        }

        // ✅ Use parsed values
        const client_id = body.client_id || "default";
        const clientId = client_id; // 🔒 ensures consistent use throughout all nested async blocks

        // 🧩 Step 1 — Determine Square environment for this client
        const envCfg = await getClientEnvironment(clientId, admin);

        const baseUrl = envCfg.square_environment === "production"
            ? "https://connect.squareup.com"
            : "https://connect.squareupsandbox.com";

        const client_id_for_square = envCfg.square_environment === "production"
            ? functions.config().square.prod_client_id
            : functions.config().square.sandbox_client_id;

        const client_secret_for_square = envCfg.square_environment === "production"
            ? functions.config().square.prod_client_secret
            : functions.config().square.sandbox_client_secret;

        console.log(`🧩 [createSquareOrder] Square Env → ${envCfg.square_environment.toUpperCase()} | baseUrl=${baseUrl}`);

        const call_id = body.call_id || "unknown_call";
        let items_ordered = body.items_ordered || [];

        // 🔄 If items_ordered is missing but call_id exists, try Firestore fallback
        if ((!items_ordered || items_ordered.length === 0) && call_id) {
            console.warn("⚠️ items_ordered missing — trying Firestore fallback for call_id:", call_id);
            const orderRef = admin.firestore().collection("orders").doc(call_id);
            const orderSnap = await orderRef.get();

            if (orderSnap.exists) {
                const orderData = orderSnap.data();
                if (orderData?.items_ordered?.length) {
                    items_ordered = orderData.items_ordered;
                    console.log(`✅ Recovered ${items_ordered.length} items_ordered from Firestore`);
                    parsedItemsOrdered = items_ordered;
                } else {
                    console.error("❌ Firestore doc exists but items_ordered is empty or invalid");
                }
            } else {
                console.error("❌ No Firestore order found for call_id:", call_id);
            }
        }

        const user_intent = body.user_intent || null;
        const original_user_input = body.original_user_input || null;
        let spokenInput = safeLower(original_user_input || "", "createSquareOrder:original_user_input");

        let parsedItemsOrdered;

        if (body.correction_input && body.correction_input.trim() !== "") {
            console.log("✋ Correction input detected, skipping Square order.");
            return res.status(200).json({
                success: false,
                message: "Correction input received — order not sent to Square.",
                correction_mode: true,
            });
        }

        // 🔄 Helper: Apply fuzzy item aliases
        function applyAliasRewrite(items, aliasMap) {
            return items.map(item => {
                const rawName = safeLower(item.name, "applyAliasRewrite.itemName").trim();
                if (aliasMap[rawName]) {
                    const { target_item_name, target_variation_name } = aliasMap[rawName];
                    return {
                        ...item,
                        name: target_item_name,
                        size: target_variation_name || item.size
                    };
                }
                return item;
            });
        }

        const fuzzyItemAliases = await loadFuzzyItemAliases(client_id);

        if (!fuzzyItemAliases || Object.keys(fuzzyItemAliases).length === 0) {
            console.warn(`⚠️ No fuzzyItemAliases loaded for client ${client_id}`);
        } else {
            console.log("🧠 Loaded fuzzy item aliases (keys):", Object.keys(fuzzyItemAliases));
        }

        parsedItemsOrdered = Array.isArray(body.items_ordered) ? body.items_ordered : [];
        console.log("🟡 Initial parsedItemsOrdered from body:", JSON.stringify(parsedItemsOrdered));

        // 🛡️ Ensure modifiers is always an array
        parsedItemsOrdered = parsedItemsOrdered.map(item => ({
            ...item,
            modifiers: Array.isArray(item.modifiers) ? item.modifiers : []
        }));
        console.log("🟡 Normalized modifiers to arrays:", JSON.stringify(parsedItemsOrdered));

        // 🛡️ Global invariant: force all modifiers to safe arrays of strings
        parsedItemsOrdered = parsedItemsOrdered.map(item => ({
            ...item,
            modifiers: Array.isArray(item.modifiers)
                ? item.modifiers.filter(m => typeof m === "string" && m.trim().length > 0)
                : []
        }));
        console.log("🛡️ Enforced global modifiers invariant:", JSON.stringify(parsedItemsOrdered));

        // 🛡️ Normalize toolCall for Blend vs curl/manual requests
        const toolCall = body.toolCall || {};

        // 🧹 Clean up stray/misparsed modifiers before anything else
        parsedItemsOrdered = fixDetachedModifiers(
            parsedItemsOrdered,
            original_user_input || toolCall?.original_user_input || ""
        );

        // 🚫 Strip auto-attached modifiers before alias rewrite
        parsedItemsOrdered = parsedItemsOrdered.map(item => {
            if (!item.modifiers || !Array.isArray(item.modifiers)) return item;

            const lowerInput = (original_user_input && typeof original_user_input === "string")
                ? safeLower(original_user_input, "modifierCleanup.lowerInput")
                : "";

            const filtered = item.modifiers.filter(m => {
                if (!m || typeof m !== "string") return false;

                // ✅ Always keep if explicitly provided
                if (Array.isArray(item.modifiers) && item.modifiers.includes(m)) return true;

                // 🪶 Soft fuzzy check: keep if phrase overlap ≥0.7
                const modLower = safeLower(m, "modifierFilter");
                const idx = lowerInput.indexOf(modLower);
                if (idx !== -1) return true;

                // Partial token match fallback
                const tokens = modLower.split(/\s+/);
                const matchedTokens = tokens.filter(t => lowerInput.includes(t)).length;
                const ratio = matchedTokens / tokens.length;
                return ratio >= 0.7;
            });

            if (filtered.length !== item.modifiers.length) {
                console.log(
                    `🧹 Pre-normalize cleanup for "${item.name}" → kept: [${filtered.join(", ")}]`
                );
            }

            return { ...item, modifiers: filtered };
        });


        console.log("🧾 Final modifiers after invariant+cleanup:", JSON.stringify(parsedItemsOrdered.map(i => i.modifiers)));

        // 🧩 Alias pre-normalization for combined size+name variants
        parsedItemsOrdered = parsedItemsOrdered.map(item => {
            const combinedKey = safeLower(`${item.size || ""} ${item.name || ""}`.trim());
            if (fuzzyItemAliases && fuzzyItemAliases[combinedKey]) {
                const alias = fuzzyItemAliases[combinedKey];
                console.log(
                    `🎯 Alias rewrite triggered for "${combinedKey}" → target="${alias.target_item_name}" [variation=${alias.target_variation_name}]`
                );
                item.name = alias.target_item_name;
                item.size = alias.target_variation_name || item.size;
            }
            return item;
        });

        // 🔁 Apply alias rewrite
        parsedItemsOrdered = applyAliasRewrite(parsedItemsOrdered, fuzzyItemAliases || {});
        console.log(`🧠 After alias rewrite: ${parsedItemsOrdered.map(i => i.name).join(", ")}`);

        // 🧩 Embedded fuzzy matcher
        function fuzzyMatchItem(name, catalogItems) {
            const lowerName = safeLower(name, "fuzzyMatchItem.name").trim();
            const aliasEntry = fuzzyItemAliases[lowerName];
            let searchName = lowerName;

            if (aliasEntry?.target_item_name) {
                const itemPart = aliasEntry.target_item_name;
                const variationPart = aliasEntry.target_variation_name;
                searchName = variationPart ? `${variationPart} ${itemPart}` : itemPart;
                console.log(`🔁 Alias rewrite: "${name}" → "${searchName}"`);
            }

            const validCatalogItems = catalogItems
                .filter(item => item.name && item.name.trim() !== "")
                .map(item => ({ name: item.name, raw: item.raw || item }));

            console.log(`🔍 Attempting fuzzy match for: "${searchName}"`);
            const fuse = new Fuse(validCatalogItems, { keys: ["name"], threshold: 0.6 });
            const results = fuse.search(searchName);

            if (results.length > 0) {
                console.log(`✅ Fuzzy match found: "${results[0].item.name}"`);
                return {
                    name: results[0].item.name,
                    raw: results[0].item.raw,
                    score: results[0].score,
                    variationOverride: aliasEntry?.target_variation_name || null,
                };
            }

            // 🔄 Second pass — fuzzy match variation names if item-level match fails
            const variationNameMap = catalogItems.flatMap(item => {
                const itemName = safeLower(item.raw?.item_data?.name, "fuzzyMatchItem.itemName");
                const variations = item.raw?.item_data?.variations || [];
                return variations
                    .filter(v => v.item_variation_data?.name)
                    .map(v => {
                        const variationName = safeLower(v.item_variation_data?.name, "fuzzyMatchItem.variationName");
                        const fullName = `${variationName} ${itemName}`.trim();
                        return { variationId: v.id, name: fullName, itemId: v.item_variation_data.item_id };
                    });
            });

            const variationFuse = new Fuse(variationNameMap, {
                keys: ['name'],
                includeScore: true,
                threshold: 0.6
            });

            const variationResult = variationFuse.search(searchName)[0];
            if (variationResult) {
                console.log("🧠 Variation-level match found:", variationResult.item.name);
                const matchedVariation = variationResult.item;
                const parentItem = catalogItems.find(item => item.raw?.id === matchedVariation.itemId);
                if (parentItem) {
                    const allVariations = parentItem.raw?.item_data?.variations || [];
                    const matchedVariationFull = allVariations.find(v => v.id === matchedVariation.variationId);
                    const priceCents = matchedVariationFull?.item_variation_data?.price_money?.amount || null;
                    return {
                        name: parentItem.name,
                        raw: parentItem.raw,
                        score: variationResult.score,
                        variationId: matchedVariation.variationId,
                        variationName: matchedVariation.name,
                        price: priceCents
                    };
                }
            }

            console.warn(`⚠️ No fuzzy or variation match found for: "${name}"`);
            return null;
        }

        if (typeof parsedItemsOrdered === "string") {
            try {
                parsedItemsOrdered = JSON.parse(parsedItemsOrdered);
                console.log(`✅ Parsed stringified items_ordered, count=${parsedItemsOrdered.length}`);
            } catch (err) {
                console.error("❌ Invalid items_ordered JSON:", err.message);
                return res.status(400).json({ success: false, message: "Invalid items_ordered format" });
            }
        }

        console.log("🧩 Step 2 pre-map items:", JSON.stringify(parsedItemsOrdered));

        // 🛡️ Guardrail: Mark invalid items before normalization
        parsedItemsOrdered = parsedItemsOrdered.filter((item, idx) => {
            if (!item?.name || typeof item.name !== "string") {
                console.error(`🚨 Step 2: Invalid item.name at index ${idx}:`, JSON.stringify(item));
                globalInvalidItems.push(item);   // 📝 Track for Blend fallback routing
                return false;                    // 🚫 Remove from enrichment flow
            }
            return true;
        });

        // 🧩 Load catalog_debug_json for downstream compatibility
        const debugDocRef = db
            .collection("clients")
            .doc(clientId)
            .collection("catalog")
            .doc("catalog_debug_json");

        const debugSnap = await debugDocRef.get();
        const debugData = debugSnap.exists ? debugSnap.data() : {};

        // ✅ Use let so later logic can reuse or modify this variable safely
        let catalogObjects = debugData?.catalog_debug_json?.objects || [];

        console.log(`🧠 Loaded ${catalogObjects.length} catalog objects for downstream enrichment`);

        // 🧩 Load catalog_items for item-level enrichment
        const clientCatalogRef = db
            .collection("clients")
            .doc(clientId)
            .collection("catalog")
            .doc("catalog_items");

        const catalogSnap = await clientCatalogRef.get();

        if (!catalogSnap.exists) {
            console.warn(`⚠️ No catalog_items found for client ${clientId} — returning empty list`);
        }

        const catalogData = catalogSnap.data() || {};
        const catalogItems = Array.isArray(catalogData?.catalog_items)
            ? catalogData.catalog_items
            : [];

        console.log(`📦 Loaded catalog for client_id=${clientId}, items=${catalogItems.length}`);

        // ✅ Declare normalizedCatalogItems early so later steps can safely reference it
        const normalizedCatalogItems = catalogItems.map(item => ({
            name: safeLower(item.item_data?.name, "catalogNormalization") || "",
            id: item.id,
            raw: item,
        }));


        // 🧠 Build dynamic descriptor vocabulary from the loaded catalog
        const descriptorTerms = new Set();

        // From MODIFIER and MODIFIER_LIST options (covers “iced”, “hot”, “almond milk”, “double”, etc.)
        for (const obj of catalogObjects) {
            if (obj.type === "MODIFIER" && obj.modifier_data?.name) {
                descriptorTerms.add(obj.modifier_data.name.toLowerCase().trim());
            }
            if (obj.type === "MODIFIER_LIST") {
                for (const opt of obj.modifier_list_data?.modifiers || []) {
                    if (opt?.name) descriptorTerms.add(opt.name.toLowerCase().trim());
                }
            }
            if (obj.type === "ITEM_VARIATION" && obj.item_variation_data?.name) {
                descriptorTerms.add(obj.item_variation_data.name.toLowerCase().trim());
            }
        }

        console.log(`🧠 Built dynamic descriptor set (${descriptorTerms.size} terms)`);

        // 🧠 Step 1.3 — Load modifier names directly from catalog (Square MODIFIER + MODIFIER_LIST objects)
        let allKnownPrefixes = new Set();

        try {
            // 1️⃣ Collect direct MODIFIER names (like "Iced", "Hot", "Blended")
            const modifierObjects = catalogObjects.filter(obj => obj.type === "MODIFIER");
            for (const mod of modifierObjects) {
                const name = safeLower(mod?.modifier_data?.name || "").trim();
                if (name) allKnownPrefixes.add(name);
            }

            // 2️⃣ Collect nested MODIFIER_LIST modifier names (for completeness)
            const modifierLists = catalogObjects.filter(obj => obj.type === "MODIFIER_LIST");
            for (const list of modifierLists) {
                const mods = list.modifier_list_data?.modifiers || [];
                for (const m of mods) {
                    const mName = safeLower(m?.name || "").trim();
                    if (mName) allKnownPrefixes.add(mName);
                }
            }

            console.log(`🧠 Step 1.45 — Loaded ${allKnownPrefixes.size} modifier/variation prefixes from catalog data`);
        } catch (err) {
            console.error("⚠️ Step 1.45 failed to extract modifier prefixes from catalog:", err.message);
        }

        // 🧠 Step 1.4 — Smart token & compound name handler (catalog-validated)
        try {
            const rawInput = safeLower(original_user_input || "");

            // Build quick-access lookup sets from catalog data
            // 🧩 Define scoped catalog collections used below
            const allCatalogItems = normalizedCatalogItems || [];
            const allCatalogModifiers = Array.from(allKnownPrefixes); // from Step 1.45
            const allCatalogVariations = Array.isArray(catalogData?.catalog_variations)
                ? catalogData.catalog_variations
                : [];

            // Build quick-access lookup sets from catalog data
            const validItemNames = new Set(allCatalogItems.map(i => safeLower(i.name)));
            const validModifiers = new Set(allCatalogModifiers.map(m => safeLower(m)));
            const validVariations = new Set(allCatalogVariations.map(v => safeLower(v.name)));
            const validTokens = new Set([...validItemNames, ...validModifiers, ...validVariations]);

            const unrecognizedTokens = new Set();

            parsedItemsOrdered = parsedItemsOrdered.map(item => {
                if (!item?.name) return item;
                const nameTokens = safeLower(item.name).split(/\s+/).filter(Boolean);
                let updatedName = item.name;
                let updatedModifiers = new Set(item.modifiers?.map(m => safeLower(m)) || []);

                // --- 🧩 1. Split compound item names like "iced cappuccino"
                // 🧱 Guardrail: skip split if full item name or token-reversed name matches a catalog entry
                const fullLowerName = safeLower(item.name).trim();
                const reversedName = fullLowerName.split(" ").reverse().join(" ").trim();

                if ([...validItemNames].some(v => {
                    const val = safeLower(v).trim();
                    return val === fullLowerName || val === reversedName;
                })) {
                    console.log(`✅ [Step1.3 Guard] Catalog match (direct or reversed) for "${item.name}" — skipping split`);
                    return item;
                }

                if (nameTokens.length > 1) {
                    const [firstToken, ...restTokens] = nameTokens;
                    if (validModifiers.has(firstToken)) {
                        updatedName = restTokens.join(" ");
                        updatedModifiers.add(firstToken);
                        console.log(`🧊 Step1.3 split compound name "${item.name}" → "${updatedName}" + modifier "${firstToken}"`);
                    }
                }

                // --- 🧩 2. Scan entire user input for additional catalog-valid tokens near item name
                const tokens = rawInput.split(/\s+/);
                for (let i = 0; i < tokens.length; i++) {
                    const tok = tokens[i];
                    const nearby = rawInput.includes(`${tok} ${safeLower(updatedName)}`) || rawInput.includes(`${safeLower(updatedName)} ${tok}`);

                    if (nearby && validModifiers.has(tok) && !updatedModifiers.has(tok)) {
                        updatedModifiers.add(tok);
                        console.log(`🧩 Step1.3 attached nearby valid token "${tok}" → "${updatedName}"`);
                    } else if (nearby && !validTokens.has(tok)) {
                        unrecognizedTokens.add(tok);
                    }
                }

                return { ...item, name: updatedName.trim(), modifiers: [...updatedModifiers] };
            });

            if (unrecognizedTokens.size > 0) {
                console.log(`⚠️ Step1.3 unrecognized tokens (ignored, may trigger clarification later): [${[...unrecognizedTokens].join(", ")}]`);
            }
        } catch (err) {
            console.error("⚠️ Step1.3 smart token handler failed:", err);
        }

        // ===== Step 1.5 — Catalog-driven prefix extraction (uses Step 1.45 prefixes) =====
        try {
            if (allKnownPrefixes.size === 0) {
                console.warn("⚠️ No prefix candidates found in catalog — skipping prefix extraction.");
            } else {
                parsedItemsOrdered = parsedItemsOrdered.map(item => {
                    if (!item?.name) return item;

                    const nameLower = safeLower(item.name);
                    const tokens = nameLower.split(/\s+/).filter(Boolean);
                    if (tokens.length < 2) return item;

                    // Find if the first token matches a known modifier/variation
                    const firstToken = tokens[0];
                    const matchedModifier = Array.from(allKnownPrefixes).find(
                        m => safeLower(m.trim()) === firstToken.trim()
                    );

                    if (!matchedModifier) {
                        console.log(
                            `🧪 Prefix candidate miss → token="${firstToken}", sample candidates=[${Array.from(allKnownPrefixes).slice(0, 10).join(", ")}]`
                        );
                    }

                    if (matchedModifier) {
                        const newName = item.name.replace(
                            new RegExp(`^${matchedModifier}[\\s,\\-]*`, "i"),
                            ""
                        ).trim();

                        const updatedModifiers = [...new Set([...(item.modifiers || []), matchedModifier])];

                        console.log(
                            `✅ Prefix extraction: moved "${matchedModifier}" from name → modifiers for "${newName}"`
                        );

                        // 🧭 Diagnostic: trace which modifier_list_id this matched modifier belongs to
                        const catalogObjects = catalogData?.catalog_debug_json?.objects || [];
                        const sourceList = catalogObjects.find(obj =>
                            obj.type === "MODIFIER" &&
                            safeLower(obj?.modifier_data?.name || "") === safeLower(matchedModifier)
                        );
                        if (sourceList) {
                            console.log(`🧭 Modifier "${matchedModifier}" traced to list_id=${sourceList.modifier_data?.modifier_list_id || "unknown"}`);
                        }

                        return { ...item, name: newName, modifiers: updatedModifiers };
                    }
                    return item;
                });
            }
        } catch (err) {
            console.error("⚠️ Step 1.5 prefix extraction failed:", err.message);
        }

        // 🔧 Preprocess compound item names (e.g., "mocha double shot")
        for (let parsedItem of parsedItemsOrdered) {
            if (
                parsedItem.name &&
                typeof parsedItem.name === "string" &&
                safeLower(parsedItem.name, "compoundCheck").includes("double shot")
            ) {
                parsedItem.name = parsedItem.name.replace(/double shot/i, "").trim();
                if (!Array.isArray(parsedItem.modifiers)) parsedItem.modifiers = [];
                if (!parsedItem.modifiers.includes("double shot")) {
                    parsedItem.modifiers.push("double shot");
                }
                console.log(`🔧 Split compound → item="${parsedItem.name}", modifiers=${parsedItem.modifiers}`);
            } else {
                console.log(`🟡 Preprocess pass-through → item="${parsedItem.name}", modifiers=${JSON.stringify(parsedItem.modifiers)}`);
            }
        }

        // Step 1.6 — Restore last known modifiers for this call if missing
        if (call_id) {
            for (let item of parsedItemsOrdered) {
                const priorOrder = await admin.firestore().collection("orders").doc(call_id).get();
                if (priorOrder.exists && Array.isArray(priorOrder.data()?.items)) {
                    const previous = priorOrder.data().items.find(i => i.name === item.name);
                    if (previous?.modifiers?.length && (!item.modifiers || item.modifiers.length === 0)) {
                        item.modifiers = previous.modifiers;
                        console.log(`♻️ Restored modifiers from prior call state for "${item.name}" →`, item.modifiers);
                    }
                }
            }
        }

        // 🧩 Step 1.65 — Restore previous valid items for same call (state continuity)
        if (call_id) {
            try {
                const orderRef = admin.firestore().collection("orders").doc(call_id);
                const priorSnap = await orderRef.get();

                if (priorSnap.exists && Array.isArray(priorSnap.data()?.items_ordered)) {
                    const previousItems = priorSnap.data().items_ordered;
                    if (previousItems.length > 0) {
                        console.log(`♻️ [Step1.65] Found ${previousItems.length} previous valid items for call_id=${call_id}`);

                        // Helper to merge current + previous while preserving modifiers
                        const mergeItems = (prev, curr) => {
                            const merged = [...prev];
                            for (const cur of curr) {
                                const idx = merged.findIndex(p =>
                                    safeLower(p.name) === safeLower(cur.name)
                                );
                                if (idx >= 0) {
                                    const mergedMods = Array.from(new Set([
                                        ...(merged[idx].modifiers || []),
                                        ...(cur.modifiers || [])
                                    ]));
                                    merged[idx] = { ...merged[idx], ...cur, modifiers: mergedMods };
                                    console.log(`🔄 Merged existing item "${cur.name}" modifiers → ${mergedMods}`);
                                } else {
                                    merged.push(cur);
                                    console.log(`➕ Added new item "${cur.name}" to order`);
                                }
                            }
                            return merged;
                        };

                        // Perform merge
                        parsedItemsOrdered = mergeItems(previousItems, parsedItemsOrdered);
                        console.log("✅ [Step1.65] Merged previous and current items →", parsedItemsOrdered);
                    }
                } else {
                    console.log(`ℹ️ [Step1.65] No previous valid items found for call_id=${call_id}`);
                    // 🧩 Optional clarifier merge — blends single-word corrections like "iced"
                    try {
                        const clarifier = body.clarifier_modifier?.toLowerCase()?.trim();
                        if (clarifier && parsedItemsOrdered?.length > 0) {
                            console.log(`🧩 Clarifier detected: "${clarifier}" — merging into first item`);
                            const firstItem = parsedItemsOrdered[0];
                            firstItem.modifiers = firstItem.modifiers || [];
                            if (!firstItem.modifiers.includes(clarifier)) {
                                firstItem.modifiers.push(clarifier);
                                console.log(`✅ Clarifier merged → updated modifiers: ${JSON.stringify(firstItem.modifiers)}`);
                            }
                        }
                    } catch (err) {
                        console.error("⚠️ Clarifier merge skipped due to parsing error:", err.message);
                    }
                }
            } catch (mergeErr) {
                console.error("⚠️ [Step1.65] Error restoring prior valid items:", mergeErr.message);
            }
        }

        // Step 2: Normalize
        parsedItemsOrdered = parsedItemsOrdered.map((item, index) => {
            console.log(`🔍 Step 2 — Pre-normalize size for item[${index}]:`, item.size);

            const name = safeLower(item.name, "Step2:item.name").trim();
            const quantity = item.quantity || 1;
            const modifiers = Array.isArray(item.modifiers)
                ? item.modifiers
                : item.modifiers
                    ? [item.modifiers]
                    : [];
            const normalizedModifiers = modifiers.map((m, idx) => {
                if (typeof m === "string") return safeLower(m, `Step2:modifier[${idx}]`).trim();
                if (m && typeof m.name === "string") return safeLower(m.name, `Step2:modifierObjName[${idx}]`).trim();
                console.warn("⚠️ Step2: unexpected modifier type", m);
                return "";
            });
            const size = normalizeSize(item.size || "", item, descriptorTerms);

            // 🆕 Detect "no ___" style phrases for ingredient removals
            let customizations = [];
            if (original_user_input && typeof original_user_input === "string") {
                const lowerInput = safeLower(original_user_input, "Step2:customizationScan");
                const noMatch = lowerInput.match(/no\s+([a-zA-Z ]+)/g);
                if (noMatch) {
                    customizations = noMatch.map(phrase => {
                        const ing = phrase.replace(/^no\s+/, "").trim();
                        return ing ? `No ${ing}` : "";
                    }).filter(Boolean);
                    if (customizations.length > 0) {
                        console.log(`🆕 Detected removals for "${name}":`, customizations);
                    }
                }
            }

            console.log(`🧼 Parsed item ${index + 1}: ${quantity}x ${size} ${name} [Modifiers: ${normalizedModifiers.join(", ")}]`);
            // Separate exclusions from true modifiers
            const exclusions = normalizedModifiers.filter(m =>
                /^no\s+/.test(m) || /^without\s+/.test(m)
            );

            const trueModifiers = normalizedModifiers.filter(m =>
                !/^no\s+/.test(m) && !/^without\s+/.test(m)
            );

            console.log(`🪓 Step 2 exclusion split for "${name}" → mods=[${trueModifiers}], custom=[${exclusions}]`);

            return {
                name,
                size,
                quantity,
                modifiers: trueModifiers,
                customizations: exclusions
            };
        });

        // 🟢 Keep global snapshot in sync for debugging
        global.parsedItemsOrdered = parsedItemsOrdered;

        // 🛡️ Preserve incoming modifiers before any post-normalize filtering
        parsedItemsOrdered = parsedItemsOrdered.map(item => {
            if (Array.isArray(item.modifiers) && item.modifiers.length > 0) {
                item._preservedModifiers = [...item.modifiers];
                console.log(`🧩 Preserved raw incoming modifiers for "${item.name}":`, item._preservedModifiers);
            }
            return item;
        });

        // 🚫 Strip modifiers not explicitly spoken by the user (post-normalize)
        parsedItemsOrdered = parsedItemsOrdered.map(item => {
            if (!item.modifiers || !Array.isArray(item.modifiers)) return item;

            const lowerInput = (original_user_input && typeof original_user_input === "string")
                ? safeLower(original_user_input, "modifierFilter.lowerInput")
                : "";

            const filtered = item.modifiers.filter(m => {
                if (!m || typeof m !== "string") return false;   // 🛡️ Guard

                // ✅ Always keep if explicitly provided in the payload
                if (Array.isArray(item.modifiers) && item.modifiers.includes(m)) {
                    return true;
                }

                // 🛡️ Otherwise, only keep if spoken
                return lowerInput.includes(safeLower(m, "modifierFilter"));
            });

            if (filtered.length !== item.modifiers.length) {
                console.log(
                    `🧹 Post-normalize cleanup for "${item.name}" → kept: [${filtered.join(", ")}]`
                );
            }

            // 🧩 Restore preserved modifiers if all were stripped but we had incoming ones
            if (filtered.length === 0 && Array.isArray(item._preservedModifiers)) {
                console.log(`🔁 Restoring preserved modifiers for "${item.name}" →`, item._preservedModifiers);
                filtered.push(...item._preservedModifiers);
            }

            return { ...item, modifiers: filtered };
        });

        if (user_intent === "modify_item") {
            parsedItemsOrdered = parsedItemsOrdered.map(item => ({ ...item, size: null }));
            console.log("🧼 Cleared size on parsedItemsOrdered for modify_item intent.");
            console.log(`🧪 Step 2 — After normalization: ${parsedItemsOrdered.length} items`, parsedItemsOrdered[0]);
        }

        // ===== Step 2.1: Tokenization + Classification + Normalization =====
        console.log("🧠 Step 2 — Token-based parsing and normalization (universal)");

        // 🩹 Hotfix: ensure lowerInput is safely defined for implied-modifier logic
        const lowerInput = (spokenInput || req.body.rawInput || '').toLowerCase();

        for (let i = 0; i < parsedItemsOrdered.length; i++) {
            const item = parsedItemsOrdered[i];
            if (!item?.name) continue;

            const rawName = safeLower(item.name).trim();
            const tokens = rawName.split(/\s+/).filter(Boolean);
            const localLowerInput = safeLower(original_user_input || "");

            const quantity = item.quantity || 1;
            const modifiersIn = Array.isArray(item.modifiers)
                ? item.modifiers.map(m => safeLower(m).trim())
                : item.modifiers ? [safeLower(item.modifiers).trim()] : [];

            // --- 2.1 Collect reference data from catalog ---
            const variationNames = new Set();
            const modifierNames = new Set();

            if (Array.isArray(normalizedCatalogItems)) {
                for (const catItem of normalizedCatalogItems) {
                    const vars = catItem.item_data?.variations || [];
                    for (const v of vars) {
                        const vName = safeLower(v.item_variation_data?.name || "").trim();
                        if (vName) variationNames.add(vName);
                    }
                    const modLists = catItem.item_data?.modifier_list_info || [];
                    for (const list of modLists) {
                        const listDoc = await db
                            .collection("clients").doc(client_id)
                            .collection("modifiers").doc(list.modifier_list_id)
                            .get();
                        if (listDoc.exists && Array.isArray(listDoc.data()?.modifiers)) {
                            for (const m of listDoc.data().modifiers) {
                                const mName = safeLower(m.name || "").trim();
                                if (mName) modifierNames.add(mName);
                            }
                        }
                    }
                }
            }

            // --- 2.2 Classify tokens ---
            let baseTokens = [];
            let detectedSize = normalizeSize(item.size || "", item, descriptorTerms);
            let detectedMods = new Set(modifiersIn);
            let detectedCustom = [];

            for (let t of tokens) {
                const token = t.trim();
                if (!token) continue;

                if (variationNames.has(token)) {
                    detectedSize = token;
                    console.log(`🎯 Step2: token "${token}" classified as VARIATION`);
                    continue;
                }
                if (modifierNames.has(token)) {
                    detectedMods.add(token);
                    console.log(`🎯 Step2: token "${token}" classified as MODIFIER`);
                    continue;
                }
                if (/^no\s+/.test(token) || /^without\s+/.test(token)) {
                    detectedCustom.push(`No ${token.replace(/^(no|without)\s+/, "").trim()}`);
                    console.log(`🧩 Step2: token "${token}" classified as CUSTOMIZATION`);
                    continue;
                }
                baseTokens.push(token);
            }

            // --- 2.3 Fallback: if nothing recognized, assume last token is base name ---
            if (baseTokens.length === 0 && tokens.length > 0) baseTokens = tokens;

            const finalName = baseTokens.join(" ").trim();

            parsedItemsOrdered[i] = {
                name: finalName,
                size: detectedSize,
                quantity,
                modifiers: Array.from(detectedMods),
                customizations: [
                    ...new Set([
                        ...(item.customizations || []),
                        ...(detectedCustom || [])
                    ])
                ]
            };

            console.log(`🧾 Step2 result → ${quantity}x ${detectedSize || ""} ${finalName} [Mods: ${Array.from(detectedMods).join(", ")}]`);
        }

        // 🟢 Snapshot after tokenization
        global.parsedItemsOrdered = parsedItemsOrdered;

        // --- 2.4 Post-cleanup: safely retain meaningful modifiers ---
        parsedItemsOrdered = parsedItemsOrdered.map(item => {
            if (!Array.isArray(item.modifiers) || item.modifiers.length === 0) return item;

            // 🛡️ Preserve temperature-related modifiers before cleanup
            const hasTemperature = item.modifiers.some(m =>
                ["iced", "hot", "blended"].includes(safeLower(m))
            );
            if (hasTemperature) {
                console.log(`🧊 Preserving temperature modifier(s): ${JSON.stringify(item.modifiers)} for "${item.name}"`);
                item._preserveModifiers = [...item.modifiers]; // temporary backup
            }

            // 🧩 Safe filter: remove only obviously invalid or empty entries
            const keep = item.modifiers.filter(m =>
                typeof m === "string" && m.trim().length >= 2
            );

            if (keep.length !== item.modifiers.length) {
                console.log(`🧹 Step2 cleanup refined for "${item.name}" → kept: [${keep.join(", ")}]`);
            }

            let cleaned = { ...item, modifiers: keep };

            // 🧩 Restore preserved temperature modifiers after cleanup
            if (item._preserveModifiers) {
                cleaned.modifiers = [...new Set([...cleaned.modifiers, ...item._preserveModifiers])];
                delete cleaned._preserveModifiers;
                console.log(`🔁 Restored preserved modifiers for "${item.name}": ${JSON.stringify(cleaned.modifiers)}`);
            }

            // ✅ Guard: if cleanup left us empty, revert to original modifiers
            if (cleaned.modifiers.length === 0 && Array.isArray(item.modifiers) && item.modifiers.length > 0) {
                console.warn(`⚠️ No modifiers survived cleanup for "${item.name}", restoring originals.`);
                cleaned.modifiers = item.modifiers;
            }

            return cleaned;
        });

        // --- 2.5 Modify intent guard ---
        if (user_intent === "modify_item") {
            parsedItemsOrdered = parsedItemsOrdered.map(item => ({ ...item, size: null }));
            console.log("🧼 Cleared size on parsedItemsOrdered for modify_item intent.");
        }

        // --- 2.6 Bundled-item splitter (with quantity-preservation fix) ---
        parsedItemsOrdered = parsedItemsOrdered.flatMap(item => {
            // 🩹 Guard — identical multi-order (same modifiers for all) → keep quantity
            if (item.quantity > 1 && Array.isArray(item.modifiers) && item.modifiers.length > 0) {
                const uniqueMods = [...new Set(item.modifiers.map(m => safeLower(m.trim())))];
                if (uniqueMods.length === item.modifiers.length) {
                    console.log(`🩹 Quantity preserved for identical multi-order "${item.name}" (qty=${item.quantity})`);
                    return [item]; // don't split, keep quantity = 2
                }
            }

            // 🧩 Otherwise, run the original exclusive-list splitter
            if (item.quantity > 1 && Array.isArray(item.modifiers) && item.modifiers.length > 1) {
                console.log(`🔀 Splitting bundled item "${item.name}" qty=${item.quantity} mods=${item.modifiers.join(", ")}`);
                const listInfo = item.allowed_modifier_lists_info || [];
                const exclusiveGroups = listInfo.filter(l => l.max_selected_modifiers === 1);
                const grouped = {};
                for (let mod of item.modifiers) {
                    const list = listInfo.find(l => l.options?.includes(mod));
                    const key = list ? list.id : "other";
                    if (!grouped[key]) grouped[key] = [];
                    grouped[key].push(mod);
                }
                let splitItems = [{ ...item, quantity: 1, modifiers: [...item.modifiers] }];
                for (const [listId, mods] of Object.entries(grouped)) {
                    const isExclusive = exclusiveGroups.some(g => g.id === listId);
                    if (isExclusive && mods.length > 1) {
                        splitItems = mods.map(m => ({
                            ...item,
                            quantity: 1,
                            modifiers: [
                                m,
                                ...Object.entries(grouped)
                                    .filter(([k]) => k !== listId)
                                    .flatMap(([, arr]) => arr)
                            ]
                        }));
                    }
                }
                console.log("🧾 Step2.6 post-split:", splitItems);
                return splitItems;
            }

            return item;
        });

        console.log("✅ Step 2 complete — parsedItemsOrdered:", parsedItemsOrdered);

        // 🧱 TEMP FIX — Disable item condensing (keeps hot/iced variants separate)
        parsedItemsOrdered = parsedItemsOrdered.map(i => ({ ...i })); // no merge
        console.log("🧱 Condensing disabled for regression: identical items will not merge");

        // 🧹 Step 2.7 — Remove orphaned non-catalog items (portable version)
        if (Array.isArray(parsedItemsOrdered) && Array.isArray(normalizedCatalogItems)) {
            const validCatalogNames = new Set(
                normalizedCatalogItems.map(i => safeLower(i.name, "catalogItem"))
            );

            parsedItemsOrdered = parsedItemsOrdered.filter(item => {
                const itemName = safeLower(item.name || "", "parsedItem");
                const isKnownItem = validCatalogNames.has(itemName);

                // Flag as orphaned only if not in catalog and name is short/simple (likely a modifier)
                const wordCount = itemName.split(" ").length;
                const isOrphaned = !isKnownItem && wordCount <= 3 && !allModifierNames?.includes(itemName);

                if (isOrphaned) {
                    console.warn(`🧹 Removing orphaned non-catalog item "${item.name}" — likely detached modifier or flavor.`);
                }
                return !isOrphaned;
            });
        }

        // 🪄 Step 2.9 — Merge any extracted descriptors (like "iced", "double", "blended") into modifiers
        parsedItemsOrdered = parsedItemsOrdered.map(item => {
            if (item.detectedDescriptors?.length) {
                item.modifiers = Array.isArray(item.modifiers) ? item.modifiers : [];
                for (const desc of item.detectedDescriptors) {
                    const descNorm = desc.toLowerCase().trim();
                    if (!item.modifiers.some(m => m.toLowerCase().trim() === descNorm)) {
                        item.modifiers.push(descNorm);
                        console.log(`🪄 Merged extracted descriptor "${desc}" into modifiers for "${item.name}"`);
                    }
                }
            }
            return item;
        });

        // 🧩 Step 3.05 — Merge Guard: Preserve previously valid modifiers across clarifications
        if (Array.isArray(parsedItemsOrdered)) {
            parsedItemsOrdered = parsedItemsOrdered.map(item => {
                if (Array.isArray(item.prev_valid_modifiers) && item.prev_valid_modifiers.length > 0) {
                    const merged = new Set([
                        ...item.prev_valid_modifiers.map(m => safeLower(m)),
                        ...(item.modifiers || []).map(m => safeLower(m))
                    ]);
                    item.modifiers = Array.from(merged);
                    console.log(`🔄 Merge guard applied for "${item.name}" → ${item.modifiers}`);
                }
                return item;
            });
        }

        // 🧩 Step 3.06 — Temperature keyword failsafe (temporary guardrail)
        if (original_user_input && typeof original_user_input === "string") {
            const lowerInput = original_user_input.toLowerCase();

            for (const item of parsedItemsOrdered) {
                if (!item.modifiers || !Array.isArray(item.modifiers)) item.modifiers = [];

                // Only attach if clearly mentioned in the utterance and not already attached
                if (lowerInput.includes("hot") && !item.modifiers.includes("hot")) {
                    item.modifiers.push("hot");
                    console.log(`🔥 Auto-attached "hot" modifier for "${item.name}" from user input`);
                }

                if (lowerInput.includes("iced") && !item.modifiers.includes("iced")) {
                    item.modifiers.push("iced");
                    console.log(`🧊 Auto-attached "iced" modifier for "${item.name}" from user input`);
                }

                if (lowerInput.includes("blended") && !item.modifiers.includes("blended")) {
                    item.modifiers.push("blended");
                    console.log(`🥤 Auto-attached "blended" modifier for "${item.name}" from user input`);
                }
            }
        }

        // ===== Step 3.1: Auto-Attach Implied Modifiers & Variations (Universal) =====
        console.log("🧠 Step 3.1 — Auto-attaching implied modifiers and variations (failsafe version)");

        const userInput = safeLower(original_user_input || "").trim();

        for (const item of parsedItemsOrdered) {
            if (!item.name) continue;
            const itemNameLower = safeLower(item.name);
            item.modifiers = Array.isArray(item.modifiers) ? item.modifiers : [];
            const existingMods = new Set(item.modifiers.map(m => safeLower(m.trim())));

            // 🧩 1. Handle implied VARIATIONS (e.g., half, full, 12oz, large)
            if (Array.isArray(item.item_data_variations) && item.item_data_variations.length > 0) {
                for (const variation of item.item_data_variations) {
                    const variationName = safeLower(variation.item_variation_data?.name || "");
                    if (!variationName) continue;

                    if (itemNameLower.includes(variationName)) {
                        if (item.size && safeLower(item.size) === variationName) {
                            console.log(`⚖️ Variation "${variationName}" already set for "${item.name}" — skipping duplicate.`);
                        } else {
                            item.size = variationName;
                            item.catalog_variation_id = variation.id;
                            console.log(`✅ Auto-attached variation "${variationName}" for "${item.name}"`);
                        }
                        break;
                    }
                }
            }

            // 🧩 2. Handle implied REQUIRED MODIFIERS (e.g., iced, hot, blended)
            if (Array.isArray(item.allowed_modifier_lists) && item.allowed_modifier_lists.length > 0) {
                for (const listId of item.allowed_modifier_lists) {
                    try {
                        const listDoc = await db
                            .collection("clients")
                            .doc(client_id)
                            .collection("modifiers")
                            .doc(listId)
                            .get();

                        if (!listDoc.exists || !Array.isArray(listDoc.data()?.modifiers)) continue;

                        for (const mod of listDoc.data().modifiers) {
                            const modName = safeLower(mod.name || "").trim();
                            if (!modName) continue;
                            const normalizedModName = modName.replace(/\s+/g, " ").trim(); // removes trailing/extra spaces
                            const alreadyHas = existingMods.has(normalizedModName);
                            if (!modName) continue;  // 🧩 Skip empty or malformed
                            const spoken = itemNameLower.includes(normalizedModName) || userInput.includes(normalizedModName);

                            if (spoken && !alreadyHas) {
                                item.modifiers.push(normalizedModName);
                                existingMods.add(normalizedModName);
                                console.log(`✅ Auto-attached required modifier "${normalizedModName}" for "${item.name}"`);
                            }
                        }
                    } catch (err) {
                        console.error(`⚠️ Modifier list lookup failed for ${listId}:`, err.message);
                    }
                }
            }
        }

        // 🟢 Log snapshot after temperature extraction
        console.log("🧾 Step 3.x post-temp extraction:", parsedItemsOrdered);

        // 🧩 Guard: ensure allModifierNames is defined (from Step 1.45)
        allModifierNames =
            Array.isArray(normalizedCatalogItems)
                ? normalizedCatalogItems.flatMap(i =>
                    (i.modifier_list_info || []).flatMap(info =>
                        (info.modifiers || []).map(m => safeLower(m.name || ""))
                    )
                )
                : [];

        // 🧩 Step 3.15 — Simple merge for detached valid modifiers (e.g., "flavor shot")
        if (Array.isArray(parsedItemsOrdered) && parsedItemsOrdered.length > 1) {
            const last = parsedItemsOrdered[parsedItemsOrdered.length - 1];
            const prev = parsedItemsOrdered[parsedItemsOrdered.length - 2];

            const detachedName = safeLower(last.name || "");
            if (allModifierNames?.includes(detachedName)) {
                console.log(`🔗 Merging detached modifier "${detachedName}" into previous item "${prev.name}"`);
                prev.modifiers = Array.isArray(prev.modifiers) ? prev.modifiers : [];
                if (!prev.modifiers.includes(detachedName)) prev.modifiers.push(detachedName);
                parsedItemsOrdered.pop(); // remove standalone "flavor shot"
            }
        }


        // 🧩 Step 3.2 — Universal Prefix Normalizer (catalog-driven, plug-and-play)
        parsedItemsOrdered = await Promise.all(parsedItemsOrdered.map(async item => {
            const tokens = item.name.split(" ");
            if (tokens.length <= 1) return item;

            const prefix = safeLower(tokens[0]);
            const baseName = tokens.slice(1).join(" ");
            const catalogMatch = normalizedCatalogItems.find(c => safeLower(c.name).includes(baseName));
            if (!catalogMatch) return item;

            // Collect variations from catalog
            const variationNames = (catalogMatch.item_data?.variations || [])
                .map(v => safeLower(v.item_variation_data?.name || ""));

            // Collect modifiers from Firestore
            const modifierListIds = (catalogMatch.item_data?.modifier_list_info || [])
                .map(l => l.modifier_list_id);
            let modifierNames = [];
            for (const listId of modifierListIds) {
                const listDoc = await db
                    .collection("clients").doc(client_id)
                    .collection("modifiers").doc(listId)
                    .get();
                if (listDoc.exists) {
                    const data = listDoc.data();
                    if (Array.isArray(data.modifiers)) {
                        modifierNames.push(...data.modifiers.map(m => safeLower(m.name).trim()));
                    }
                }
            }

            // 🧩 Optional fuzzy fallback for prefix (handles typos like "pln" → "plain", "ice" → "iced")
            const allKnownPrefixes = new Set([
                ...variationNames,
                ...modifierNames,
                ...Object.keys(fuzzyItemAliases).map(k => safeLower(k.split(" ")[0]))
            ]);

            if (!allKnownPrefixes.has(prefix)) {
                const fuse = new Fuse(Array.from(allKnownPrefixes), {
                    includeScore: true,
                    threshold: 0.7
                });
                const fuzzyMatch = fuse.search(prefix)[0];
                if (fuzzyMatch && fuzzyMatch.score <= 0.7) {
                    const confidence = (1 - fuzzyMatch.score).toFixed(2);
                    console.log(`🪶 Fuzzy prefix match: "${prefix}" → "${fuzzyMatch.item}" (confidence=${confidence})`);
                    prefix = fuzzyMatch.item;
                } else {
                    console.log(`🪶 No reliable fuzzy prefix match for "${prefix}"`);
                }
            } else {
                console.log(`✅ Exact prefix match found: "${prefix}"`);
            }

            // 🧠 Decision logic
            if (variationNames.includes(prefix)) {
                console.log(`🎯 Prefix "${prefix}" matched variation for ${baseName}`);
                item.size = prefix;
                item.name = baseName;
            } else if (modifierNames.includes(prefix)) {
                console.log(`🎯 Prefix "${prefix}" matched modifier for ${baseName}`);
                item.modifiers = Array.from(new Set([...item.modifiers, prefix]));
                item.name = baseName;
            } else if (fuzzyItemAliases[`${prefix} ${baseName}`]) {
                const alias = fuzzyItemAliases[`${prefix} ${baseName}`];
                console.log(`🎯 Prefix "${prefix}" matched alias for ${baseName} → ${alias.target_item_name}`);
                item.name = alias.target_item_name;
                if (alias.target_variation_name) item.size = alias.target_variation_name;
            } else {
                console.log(`🟤 Prefix "${prefix}" unrecognized for ${baseName}`);
            }

            return item;
        }));

        // 🧠 Step 3.3 — Auto-attach required modifier if prefix word matches a required option
        for (const item of parsedItemsOrdered) {
            if (!item.name) continue;

            const prefix = safeLower(item.name.split(" ")[0]);
            const base = item.name.split(" ").slice(1).join(" ");
            if (!base) continue;

            const allowedLists = item.allowed_modifier_lists || [];
            let matchedPrefix = false;

            for (const listId of allowedLists) {
                const listDoc = await db
                    .collection("clients")
                    .doc(client_id)
                    .collection("modifiers")
                    .doc(listId)
                    .get();
                if (!listDoc.exists) continue;

                const modList = listDoc.data()?.modifiers || [];
                for (const mod of modList) {
                    const modName = safeLower(mod.name || "").trim();
                    if (!modName) continue;
                    const normalizedModName = modName.replace(/\s+/g, " ").trim();

                    if (prefix === normalizedModName && !item.modifiers.includes(normalizedModName)) {
                        item.modifiers.push(normalizedModName);
                        item.name = base;
                        matchedPrefix = true;
                        console.log(`✅ Auto-attached prefix modifier "${normalizedModName}" for "${base}" (from list ${listId})`);
                        break; // stop scanning this list
                    }
                }

                if (matchedPrefix) break; // ✅ stop scanning other lists if already found
            }

            if (!matchedPrefix) {
                console.log(`🟤 Prefix "${prefix}" unrecognized for ${base} — scanned all lists`);
            }
        }

        // 🧩 Step 3.9 — Auto-fill missing sizes from user clarification (catalog-driven)
        if (original_user_input && typeof original_user_input === "string") {
            const lowerInput = safeLower(original_user_input, "clarificationScan");

            // 🔍 Build dynamic size vocabulary from catalog variations
            const allCatalogSizes = new Set();
            for (const obj of catalogObjects || []) {
                if (obj.type === "ITEM_VARIATION" && obj.item_variation_data?.name) {
                    const name = safeLower(obj.item_variation_data.name.trim());
                    if (name) allCatalogSizes.add(name);
                }
            }

            console.log(`🧠 Dynamic size vocabulary built (${allCatalogSizes.size} terms)`);

            for (const item of parsedItemsOrdered) {
                if (!item.size || item.size.trim() === "") {
                    const found = Array.from(allCatalogSizes).find(s => lowerInput.includes(s));
                    if (found) {
                        item.size = found;
                        console.log(`✅ Auto-filled size "${found}" for "${item.name}" from clarification input (catalog-driven).`);
                    }
                }
            }
        }

        // Step 4: Catalog matching with alias rewrite
        const parsedItemsWithCatalogMatch = [];

        for (const item of parsedItemsOrdered) {
            const rewrittenItem = applyAliasRewrite([item], fuzzyItemAliases)[0] || item;
            const match = fuzzyMatchItem(rewrittenItem.name || "", normalizedCatalogItems);

            if (!match) {
                console.warn("❌ No match found for:", rewrittenItem.name);
                globalInvalidItems.push(item);
                continue;
            }

            const matchedCatalogItem = match.raw;
            const itemWithMatch = {
                ...rewrittenItem,
                catalog_item_id: matchedCatalogItem.id,
                catalog_item_name: matchedCatalogItem.name,
                item_data_variations: matchedCatalogItem.item_data_variations || [],
                allowed_modifier_lists: matchedCatalogItem.item_data?.modifier_list_info?.map(
                    info => info.modifier_list_id
                ) || [],
            };

            parsedItemsWithCatalogMatch.push(itemWithMatch);
            console.log(`✅ Catalog match: "${rewrittenItem.name}" → ${matchedCatalogItem.id}`);
        }

        parsedItemsOrdered = parsedItemsWithCatalogMatch;
        console.log(`📦 Step 4 complete — matched ${parsedItemsOrdered.length} items`);

        // ♻️ Step 4.9 — Dynamically restore required modifiers from previous valid order context
        try {
            if (req.body.call_id && req.body.client_id) {
                const callId = req.body.call_id;
                const clientId = req.body.client_id;

                // 🔍 Load previous order context
                const prevOrderRef = admin.firestore().collection("orders").doc(callId);
                const prevSnap = await prevOrderRef.get();
                const prevItems = prevSnap.exists && Array.isArray(prevSnap.data()?.items_ordered)
                    ? prevSnap.data().items_ordered
                    : [];

                // 🔍 Load this client’s modifier metadata
                const modSnap = await admin.firestore()
                    .collection("clients")
                    .doc(clientId)
                    .collection("modifiers")
                    .get();

                const clientModifiers = modSnap.docs.map(d => d.data());

                // Build a map of modifierListId → options
                const modifierLookup = {};
                for (const mod of clientModifiers) {
                    modifierLookup[mod.modifier_list_id] = {
                        options: (mod.options || []).map(o => o.name.toLowerCase().trim()),
                        min: mod.min_selected_modifiers ?? 0
                    };
                }

                parsedItemsOrdered = parsedItemsOrdered.map((item, idx) => {
                    const prev = prevItems[idx];
                    if (!prev) return item;

                    const prevMods = Array.isArray(prev.modifiers) ? prev.modifiers : [];
                    const currMods = Array.isArray(item.modifiers) ? item.modifiers : [];

                    // Collect all required modifier options for this item dynamically
                    const requiredOptions = (item.allowed_modifier_lists || [])
                        .flatMap(listId =>
                            modifierLookup[listId]?.min > 0
                                ? modifierLookup[listId].options
                                : []
                        );

                    const normalizedCurr = currMods.map(m => m.toLowerCase().trim());
                    const missingRequired = requiredOptions.some(reqOpt =>
                        !normalizedCurr.includes(reqOpt)
                    );

                    if (missingRequired) {
                        const merged = Array.from(
                            new Set([...prevMods.map(m => m.toLowerCase().trim()), ...normalizedCurr])
                        );
                        item.modifiers = merged;
                        console.log(
                            `♻️ Re-applied missing required modifiers for "${item.name}" → ${merged.join(", ")}`
                        );
                    }

                    return item;
                });
            }
        } catch (err) {
            console.error("⚠️ Step 4.9 dynamic restore error:", err);
        }

        // 🧩 Step 4.95 — carry-forward valid modifiers (final TDZ-proof + merge-ready)
        try {
            (() => {
                // ✅ check via globalThis, never binds to local TDZ variable
                const safeValid =
                    typeof globalThis.validItems !== "undefined"
                        ? globalThis.validItems
                        : undefined;

                if (!Array.isArray(parsedItemsOrdered) || !Array.isArray(safeValid) || !safeValid.length) {
                    console.log("🪄 Step 4.95 skipped — validItems unavailable or empty.");
                    return;
                }

                parsedItemsOrdered = parsedItemsOrdered.map(item => {
                    const lastValid = safeValid.find(v => safeLower(v.name) === safeLower(item.name));
                    if (lastValid?.enrichedModifiers?.length) {
                        const carried = lastValid.enrichedModifiers.map(m => m.name);
                        item.prev_valid_modifiers = carried;
                        // 🧬 merge guard — add them back if missing
                        const currentMods = new Set(item.modifiers || []);
                        carried.forEach(m => currentMods.add(m));
                        item.modifiers = Array.from(currentMods);
                        console.log(`🪄 Carried & merged valid modifiers for "${item.name}" →`, item.modifiers);
                    }
                    return item;
                });
            })();
        } catch (err) {
            console.error("⚠️ Step 4.95 carry-forward error:", err.message);
        }

        // 🧩 Step 4.96 — Soft Validation Guard (filters obvious non-menu items safely)
        try {
            const junkWords = [
                // Conversational fillers
                "uh", "um", "yeah", "sure", "okay", "ok", "alright", "cool", "please", "thanks", "hi", "hello", "hey",
                // Ordering verbs / intents
                "order", "pickup", "pick up", "takeout", "take out", "carryout", "carry out",
                "delivery", "to go", "for here", "get", "grab", "place", "put in",
                // Misheard junk
                "picture", "photo", "pitcher", "record", "call", "menu", "number", "receipt"
            ];

            parsedItemsOrdered = parsedItemsOrdered.filter(item => {
                const name = (item.name || "").toLowerCase();

                // Allow through if it matches any known catalog item
                const isCatalogMatch = normalizedCatalogItems.some(cat =>
                    cat.name.toLowerCase() === name
                );

                const isJunk = junkWords.some(w => name.includes(w));

                if (isJunk && !isCatalogMatch) {
                    console.log(`🧱 Ignored probable non-menu item: "${name}"`);
                    return false; // safely skip
                }

                return true;
            });
        } catch (err) {
            console.error("⚠️ Step 4.96 soft validation skipped:", err);
        }

        // 🧩 Step 4.97 — Preparation / Note Classification (Non-breaking Add-on)
        try {
            const noteTriggers = [
                "make it", "no ", "without", "light", "less", "more", "extra", "not too",
                "cut", "half", "to go", "well done", "crispy", "soft", "add napkins"
            ];

            // Build a quick catalog-name index for comparison
            const catalogNames = normalizedCatalogItems.map(i => i.name.toLowerCase());
            const detectedNotes = [];

            parsedItemsOrdered = parsedItemsOrdered.filter(item => {
                const name = (item.name || "").toLowerCase();
                const isCatalogItem = catalogNames.some(n => name.includes(n));
                const isNoteLike = noteTriggers.some(trigger => name.includes(trigger));
                if (!isCatalogItem && isNoteLike) {
                    detectedNotes.push(item.name);
                    return false;
                }
                return true;
            });

            if (detectedNotes.length > 0) {
                orderData.note = [
                    orderData?.note || "",
                    detectedNotes.join(", ")
                ].filter(Boolean).join(" | ");
                console.log(`📝 Detected kitchen notes: ${detectedNotes.join(", ")}`);
            }
        } catch (noteErr) {
            console.error("⚠️ Step 4.97 note classification skipped due to error:", noteErr);
        }

        // 🧊 Step 4.98 — Kitchen-Note Modifier Filter (complements Step 4.97)
        try {
            const kitchenNotePatterns = [
                /\blight\b/i, /\blight\s+ice\b/i, /\blight\s+sugar\b/i,
                /\bextra\b/i, /\bextra\s+hot\b/i, /\bextra\s+sweet\b/i,
                /\bno\b/i, /\bwithout\b/i, /\bless\b/i, /\bmore\b/i,
                /easy on/i, /add /i, /well done/i, /crispy/i, /soft/i, /to go/i
            ];
            const detectedModifierNotes = [];

            parsedItemsOrdered.forEach(item => {
                if (!item.modifiers) return;
                const kept = [];
                item.modifiers.forEach(mod => {
                    if (kitchenNotePatterns.some(p => p.test(mod))) {
                        detectedModifierNotes.push(`${item.name}: ${mod}`);
                    } else kept.push(mod);
                });
                item.modifiers = kept;
            });

            if (detectedModifierNotes.length > 0) {
                const notes = detectedModifierNotes.join(" | ");
                // ✅ Append to body (not orderData)
                body.customer_note = [body.customer_note || "", notes].filter(Boolean).join(" | ");
                console.log(`🧊 Detected kitchen-note modifiers: ${notes}`);
            }
        } catch (err) {
            console.error("⚠️ Step 4.98 kitchen-note filter skipped:", err);
        }

        // Step 5: Enrich Items
        // Capture what the user actually said to avoid auto-attaching modifiers
        // (spokenInput already defined above)
        let enrichedItems = await Promise.all(
            parsedItemsOrdered.map(async (item) => {
                const resolved = fuzzyMatchItem(item.name, normalizedCatalogItems, fuzzyItemAliases);

                if (!resolved || !resolved.name) {
                    console.warn(`⚠️ No fuzzy match found for "${item.name}" — skipping.`);
                    globalInvalidItems.push(item);
                    return null;
                }

                console.log(`✅ Fuzzy match found: "${resolved.name}" for requested "${item.name}"`);
                let matchingItem = resolved.raw;

                // 🆕 Check for missing size when multiple variations exist
                if (
                    matchingItem?.item_data?.variations &&
                    matchingItem.item_data.variations.length > 1 &&
                    (!item.size || item.size.trim() === "")
                ) {
                    console.warn(`⚠️ Item "${item.name}" has multiple sizes but none specified.`);
                    const incompleteItem = {
                        ...item,
                        name: resolved.name,
                        valid: false,
                        reason: "size_required",
                        options: matchingItem.item_data.variations.map(v => v.item_variation_data?.name),
                        needs_clarification: true,
                        retry_source: "step5",
                        catalogMatch: matchingItem
                    };
                    globalInvalidItems.push(incompleteItem);
                    return incompleteItem;
                }

                // 🆕 General check for missing required choice (temperature, size, bread type, etc.)
                const variationOptions = (matchingItem?.item_data?.variations || [])
                    .map(v => v?.item_variation_data?.name?.trim())
                    .filter(Boolean);

                // Normalize provided input (what the user actually said)
                const spokenInput = [item.size, ...(item.modifiers || []), item.name]
                    .join(" ")
                    .toLowerCase();

                // Find if any variation option is already covered in spoken input
                let matchedOption = variationOptions.find(opt =>
                    spokenInput.includes(opt.toLowerCase())
                );

                // 🧩 Auto-select variation when size matches variation name
                if (variationOptions.length > 1 && item.size && !matchedOption) {
                    const matchedVar = (matchingItem.item_data.variations || []).find(v => {
                        const varName = safeLower(v.item_variation_data?.name || "");
                        return varName.includes(safeLower(item.size));
                    });

                    if (matchedVar) {
                        item.variation_id = matchedVar.id;
                        item.base_price_money = matchedVar.item_variation_data?.price_money || item.base_price_money;
                        console.log(`✅ Auto-selected variation "${matchedVar.item_variation_data?.name}" for "${item.name}" (${item.size})`);

                        matchedOption = matchedVar.item_variation_data?.name.toLowerCase();
                    }
                }

                if (variationOptions.length > 1 && !matchedOption) {
                    console.warn(`⚠️ Item "${item.name}" requires a choice (options: ${variationOptions.join(", ")})`);

                    const incompleteItem = {
                        ...item,
                        name: resolved.name,
                        valid: false,
                        reason: "size_required",   // 🧩 restore semantic reason for size variation guardrail
                        options: variationOptions,
                        needs_clarification: true,
                        retry_source: "step5",
                        catalogMatch: matchingItem
                    };

                    globalInvalidItems.push(incompleteItem);
                    return incompleteItem;
                }

                // 🆕 Check for missing required modifiers
                const requiredModifierLists = (matchingItem?.item_data?.modifier_list_info || [])
                    .filter(m => m.enabled && m.min_selected_modifiers > 0);
                for (const list of requiredModifierLists) {
                    console.log("🧪 Debug [required] modifiers for", item.name, "list", list.modifier_list_id, "modifiers=", JSON.stringify(item.modifiers));

                    const userHasSelection = (item.modifiers || []).some(mod =>
                        (typeof mod === "string" && typeof list.modifier_list_id === "string" &&
                            mod.toLowerCase() === list.modifier_list_id.toLowerCase()) ||
                        (typeof mod?.name === "string" && typeof list.modifier_list_id === "string" &&
                            mod.name.toLowerCase() === list.modifier_list_id.toLowerCase()) ||
                        (typeof mod?.list_id === "string" && typeof list.modifier_list_id === "string" &&
                            mod.list_id === list.modifier_list_id)
                    );

                    if (!userHasSelection) {
                        const modifierSnap = await admin.firestore()
                            .collection("clients")
                            .doc(client_id)
                            .collection("modifiers")
                            .where("modifier_list_id", "==", list.modifier_list_id)
                            .get();

                        const modifierOptions = modifierSnap.docs.map(d => d.data().name);

                        const normalizedUserMods = (item.modifiers || []).map(m =>
                            typeof m === "string" ? m.toLowerCase().trim()
                                : typeof m?.name === "string" ? m.name.toLowerCase().trim()
                                    : ""
                        );

                        const normalizedOptions = modifierOptions.map(o =>
                            typeof o === "string" ? o.toLowerCase().trim() : ""
                        );

                        const hasValidModifier = normalizedUserMods.some(u =>
                            normalizedOptions.includes(u)
                        );

                        if (hasValidModifier) {
                            console.log(`✅ User provided valid required modifier "${item.modifiers}" for list ${list.modifier_list_id}`);
                            item.validatedModifiers = true; // 🧩 mark this item so Step 6.4 skips it later
                            continue;
                        }

                        console.warn(`⚠️ Item "${item.name}" missing required choice from modifier list ${list.modifier_list_id}`);
                        const incompleteItem = {
                            ...item,
                            name: resolved.name,
                            valid: false,
                            reason: "modifier_required",
                            options: modifierOptions,
                            needs_clarification: true,
                            retry_source: "step5",
                            catalogMatch: matchingItem
                        };
                        globalInvalidItems.push(incompleteItem);
                        return incompleteItem;
                    }
                }

                // 🆕 Plug-and-play overrides for "must-ask" modifier lists
                let overrideDoc = await admin.firestore()
                    .collection("clients")
                    .doc(client_id)
                    .collection("config")
                    .doc("mustAskModifiers")
                    .get();

                if (overrideDoc.exists) {
                    const mustAskMap = overrideDoc.data();
                    for (const list of matchingItem?.item_data?.modifier_list_info || []) {
                        if (mustAskMap[list.modifier_list_id]) {
                            console.log("🧪 Debug [override] modifiers for", item.name, "list", list.modifier_list_id, "modifiers=", JSON.stringify(item.modifiers));

                            const userHasSelection = (item.modifiers || []).some(mod =>
                                (typeof mod === "string" && typeof list.modifier_list_id === "string" &&
                                    mod.toLowerCase() === list.modifier_list_id.toLowerCase()) ||
                                (typeof mod?.name === "string" && typeof list.modifier_list_id === "string" &&
                                    mod.name.toLowerCase() === list.modifier_list_id.toLowerCase()) ||
                                (typeof mod?.list_id === "string" && typeof list.modifier_list_id === "string" &&
                                    mod.list_id === list.modifier_list_id)
                            );

                            if (!userHasSelection) {
                                const modifierSnap = await admin.firestore()
                                    .collection("clients")
                                    .doc(client_id)
                                    .collection("modifiers")
                                    .where("modifier_list_id", "==", list.modifier_list_id)
                                    .get();

                                const modifierOptions = modifierSnap.docs.map(d => d.data().name);

                                const normalizedUserMods = (item.modifiers || []).map(m =>
                                    typeof m === "string" ? m.toLowerCase().trim()
                                        : typeof m?.name === "string" ? m.name.toLowerCase().trim()
                                            : ""
                                );

                                const normalizedOptions = modifierOptions.map(o =>
                                    typeof o === "string" ? o.toLowerCase().trim() : ""
                                );

                                const hasValidModifier = normalizedUserMods.some(u =>
                                    normalizedOptions.includes(u)
                                );

                                if (hasValidModifier) {
                                    console.log(`✅ User provided valid required modifier "${item.modifiers}" for list ${list.modifier_list_id}`);
                                    continue;
                                }

                                console.warn(`⚠️ Item "${item.name}" missing *override-required* modifier from list "${list.modifier_list_id}"`);
                                const incompleteItem = {
                                    ...item,
                                    name: resolved.name,
                                    valid: false,
                                    reason: "modifier_required",
                                    options: modifierOptions,
                                    needs_clarification: true,
                                    retry_source: "step5",
                                    catalogMatch: matchingItem
                                };
                                globalInvalidItems.push(incompleteItem);
                                return incompleteItem;
                            }
                        }
                    }
                }

                // ✅ Variation-level override
                if (resolved.variationId) {
                    console.log(`🎯 Using variation override for "${item.name}" → "${resolved.variationName}"`);
                    return {
                        ...item,
                        name: resolved.name,
                        variation_id: resolved.variationId,
                        catalog_item_id: resolved.variationId,
                        base_price_money: resolved.base_price_money,
                        modifiers: item.modifiers,
                        quantity: item.quantity || 1,
                        catalogMatch: matchingItem,
                        valid: true
                    };
                }

                // 🔍 Variation matching
                let matchingVariation = matchingItem.item_data.variations.find(v =>
                (typeof v?.item_variation_data?.name === "string" &&
                    v.item_variation_data.name.toLowerCase().trim() === item.size)
                );

                if (!matchingVariation && item.size) {
                    matchingVariation = matchingItem.item_data.variations.find(v =>
                    (typeof v?.item_variation_data?.name === "string" &&
                        v.item_variation_data.name.toLowerCase().trim().includes(item.size))
                    );
                }

                // 🛡️ Single unnamed variation fallback
                if (!matchingVariation && matchingItem.item_data.variations.length === 1) {
                    const soleVariation = matchingItem.item_data.variations[0];
                    const variationName = (typeof soleVariation?.item_variation_data?.name === "string"
                        ? soleVariation.item_variation_data.name.toLowerCase().trim()
                        : "");
                    if (!variationName) {
                        console.warn(`⚠️ Using sole unnamed variation for "${resolved.name}"`);
                        matchingVariation = soleVariation;
                    }
                }

                // 🆕 Step 5 synthetic variation fallback
                if ((!matchingItem.item_data.variations || matchingItem.item_data.variations.length === 0)
                    && !matchingVariation) {
                    console.log(`✅ Step 5 synthetic fallback — "${item.name}" has no variations, injecting default variation.`);

                    const fallbackPrice =
                        matchingItem.item_data.price_money || // try top-level price
                        (matchingItem.item_data.variations?.[0]?.item_variation_data?.price_money) || // backup safety
                        { amount: 0, currency: "USD" }; // last resort

                    matchingVariation = {
                        id: `${matchingItem.id}_default`,   // synthetic variation_id
                        item_variation_data: {
                            name: "default",
                            price_money: fallbackPrice
                        }
                    };
                }

                // 🆕 override — items with no variations (chips, avocado toast, etc.)
                if ((!item.catalogMatch?.item_data?.variations || item.catalogMatch.item_data.variations.length === 0)
                    && item.size === "") {
                    console.log(`✅ Step 5 override — "${resolved.name}" has no variations, using real item as variation.`);

                    const safeMatch = item.catalogMatch || matchingItem;
                    const soleVariation = safeMatch?.item_data?.variations?.[0] || null;

                    if (!soleVariation) {
                        console.error(`🚨 Item "${resolved.name}" has no valid variation in Square catalog.`);
                        globalInvalidItems.push({
                            ...item,
                            name: resolved.name,
                            valid: false,
                            reason: "no_variation",
                            needs_clarification: true
                        });
                        return null;
                    }

                    // 🧹 Handle modifiers: separate invalid vs negative → customizations
                    const validModifiers = [];
                    const customizationNotes = [...(item.customizations || [])];

                    for (let mod of (item.modifiers || [])) {
                        const modLower = (typeof mod === "string" ? mod.toLowerCase().trim() : "").trim();
                        if (!modLower) continue;

                        // 🧩 Negative prefix → customization note
                        if (
                            modLower.startsWith("no ") ||
                            modLower.startsWith("without") ||
                            modLower.startsWith("remove") ||
                            modLower.startsWith("hold ")
                        ) {
                            customizationNotes.push(mod);
                            continue;
                        }

                        // 🧠 Step 5 defer — don’t reject modifiers here; Step 6 will validate via Firestore
                        console.log(`🕓 Step 5 defer — "${mod}" for "${resolved.name}" pending Step 6 validation`);
                        validModifiers.push(modLower);
                    }

                    // keep any notes/mods for Step 6 enrichment
                    item.modifiers = validModifiers;
                    item.customizations = customizationNotes;

                    const priceMoney =
                        soleVariation.item_variation_data?.price_money ||
                        safeMatch?.item_data?.price_money ||
                        { amount: 0, currency: "USD" };

                    const enriched = {
                        ...item,
                        name: resolved.name,
                        variation_id: soleVariation.id,              // ✅ always real Square variation ID
                        catalog_item_id: safeMatch?.id || null,
                        base_price_money: priceMoney,
                        allowed_modifier_lists: (safeMatch?.item_data?.modifier_list_info || []).map(i => i.modifier_list_id),
                        modifiers: validModifiers,
                        customizations: customizationNotes,
                        quantity: item.quantity || 1,
                        valid: true
                    };

                    // 🩹 Preserve any Step 2-detected customizations (e.g., "no tomatoes") if still present
                    if (item.customizations && Array.isArray(item.customizations) && item.customizations.length > 0) {
                        enriched.customizations = [
                            ...new Set([...(enriched.customizations || []), ...item.customizations])
                        ];
                        console.log(`🩹 Preserved customizations for "${item.name}":`, enriched.customizations);
                    }

                    return enriched;
                }

                if (!matchingVariation) {
                    console.warn(`⚠️ Size mismatch for ${item.name} with size ${item.size}`);
                    globalInvalidItems.push(item);
                    return null;
                }

                const priceMoney = matchingVariation.item_variation_data?.price_money;
                if (!priceMoney || typeof priceMoney.amount !== "number") {
                    console.error(`🚨 Missing price_money for "${resolved.name}"`);
                    globalInvalidItems.push(item);
                    throw new Error(`Missing price for "${resolved.name}"`);
                }

                console.log("🧮 Step 5 sanity — enriched item:", {
                    name: resolved.name,
                    variation_id: matchingVariation.id,
                    catalog_item_id: matchingItem?.id,
                    base_price_money: priceMoney,
                    allowed_modifier_lists: (matchingItem?.item_data?.modifier_list_info || []).map(i => i.modifier_list_id)
                });

                return {
                    ...item,
                    name: resolved.name,
                    variation_id: matchingVariation.id,
                    catalog_item_id: matchingItem?.id,
                    base_price_money: priceMoney,
                    modifiers: item.modifiers,
                    quantity: item.quantity || 1,
                    catalogMatch: matchingItem,
                    allowed_modifier_lists: (matchingItem?.item_data?.modifier_list_info || []).map(i => i.modifier_list_id) || [],
                    valid: true
                };
            })
        );

        console.log("🛑 Debug guard — enrichedItems, validItems, invalidItemsEarly ready");
        console.log("🛑 typeof clarification_needed_items at this point:", typeof clarification_needed_items);

        // Use enrichment output as the source of truth
        enrichedItems = (enrichedItems || []).filter(Boolean);
        let validItems = (enrichedItems || []).filter(item => item?.valid === true);
        const invalidItemsEarly = enrichedItems.filter(item => !item || item.valid !== true);

        console.log(
            "🔬 Step 5→6 handoff — enriched=%s valid=%s invalidEarly=%s",
            (typeof enrichedItems !== "undefined" && enrichedItems ? enrichedItems.length : "N/A"),
            (typeof validItems !== "undefined" && validItems ? validItems.length : "N/A"),
            (typeof invalidItemsEarly !== "undefined" && invalidItemsEarly ? invalidItemsEarly.length : "N/A")
        );

        // 🧾 Debug: list invalid items with reasons/options
        if (globalInvalidItems.length > 0) {
            console.log("🧾 Step 5 invalid items detail:", globalInvalidItems);
        }

        // 🛑 Early exit if no valid items but clarification is possible
        if (validItems.length === 0 && clarification_needed_items.length > 0) {
            console.log("🛑 Early exit — clarification required before building Square order");

            // Prefer structured clarification_needed_items
            retry_prompt = clarification_needed_items
                .map(ci => {
                    const opts = ci.options || [];
                    if (opts.length > 0) {
                        return `For your ${ci.name}, would you like ${opts.join(" or ")}?`;
                    }
                    const missing = ci.missing?.[0];
                    const listName = missing?.modifier_list_name || "this option";
                    return `For your ${ci.name}, which ${listName} would you like?`;
                })
                .join(" ");

            console.log("🗣️ Early-exit retry_prompt being sent (Step 5):", retry_prompt);
            console.log("🧾 Step 5 clarification_needed_items:", clarification_needed_items);

            return res.status(200).json({
                success: false,
                message: "Clarification required",
                retry_prompt,
                clarification_needed_items,

                // 🆕 consistency fields
                validation_passed: false,
                needs_clarification: true,
                valid_items_count: 0,
                invalid_items_count: globalInvalidItems.length || 0,
                invalid_modifiers_count: globalInvalidModifiers.length || 0,
                escalate_to_human: false   // keep consistent with Step 9 contract
            });
        }

        console.log("🟢 TDZ guard — clarification_needed_items exists?", typeof clarification_needed_items);

        // 🆕 Step 5.5: Detect missing required modifiers
        for (let [index, item] of parsedItemsOrdered.entries()) {
            try {
                if (!item.matchingItem || !item.matchingItem.item_data) continue;

                const modifierListInfo = item.matchingItem.item_data.modifier_list_info || [];
                for (let list of modifierListInfo) {
                    if (list.min_selected_modifiers && list.min_selected_modifiers > 0) {
                        // Load this modifier list’s options from Firestore-scoped cache
                        const modifierListId = list.modifier_list_id;
                        const modifierList = modifierOptions[modifierListId];
                        const options = (modifierList?.options || []).map(opt =>
                            safeLower(opt.name, "requiredModifier.option")
                        );

                        // Check if user supplied a modifier from this list
                        const userMods = (item.enrichedModifiers || []).map(m => safeLower(m.name, "user.enrichedModifier"));
                        const hasRequired = userMods.some(u => options.includes(u));

                        // 🧩 Guard: prevent invalid modifiers (like "pineapple syrup") from being re-treated as standalone items
                        if (globalInvalidItems?.length > 0) {
                            const invalidModNames = globalInvalidItems
                                .flatMap(it => it.invalid_modifiers || [])
                                .map(m => m.toLowerCase().trim());
                            if (invalidModNames.includes(item.name.toLowerCase().trim())) {
                                console.log(`🚫 Skipping detached invalid modifier "${item.name}" from being re-treated as an item`);
                                continue; // Skip this item entirely
                            }
                        }

                        if (!hasRequired) {
                            console.warn(`⚠️ Missing required modifier for "${item.name}" → list ${modifierListId}`);

                            // Push into clarification array (drives retry prompts)
                            clarification_needed_items.push({
                                index,
                                name: item.name,
                                missing: [{
                                    modifier_list_id: modifierListId,
                                    modifier_list_name: modifierList?.name || "Required Option",
                                    options
                                }]
                            });

                            // 🆕 Also mirror into globalInvalidItems (for Step 9 + counts)
                            globalInvalidItems.push({
                                name: item.name || "unknown item",
                                reason: "modifier_required",
                                options,
                                needs_clarification: true
                            });
                        }
                    }
                }
            } catch (err) {
                console.error("🚨 Error in required modifier check:", err);
            }
        }

        // 🆕 Ensure Step 5 invalid items flow into Step 5.5 clarification
        if (globalInvalidItems.length > 0) {
            clarification_needed_items = [
                ...(clarification_needed_items || []),
                ...globalInvalidItems.map(i => ({
                    name: i.name || "unknown item",
                    reason: i.reason || "modifier_required",
                    options: i.options || [],
                    needs_clarification: true
                }))
            ];
            console.log("🟢 Step 5.5 fix — clarification_needed_items populated:", clarification_needed_items);
        }

        // 🧹 Cosmetic: deduplicate identical clarification prompts
        if (clarification_needed_items.length > 1) {
            const seen = new Set();
            clarification_needed_items = clarification_needed_items.filter(ci => {
                const key = `${ci.name}-${ci.reason}-${(ci.options || []).join(",")}`;
                if (seen.has(key)) return false;
                seen.add(key);
                return true;
            });
            console.log("✨ Deduplicated clarification_needed_items:", clarification_needed_items);
        }

        // 🆕 Merge invalid modifiers into clarification_needed_items
        for (const item of parsedItemsOrdered) {
            if (item.invalidModifiers && item.invalidModifiers.length > 0) {
                console.log(`⚠️ Step 5.45 detected invalid modifiers for "${item.name}":`, item.invalidModifiers);
                clarification_needed_items.push({
                    name: item.name,
                    reason: "invalid_modifier",
                    invalid_modifiers: item.invalidModifiers,
                    needs_clarification: true
                });
            }
        }

        // 🛑 If clarification is needed, short-circuit and return 200
        if (clarification_needed_items.length > 0) {
            console.log("🔎 Missing required modifiers detected:", JSON.stringify(clarification_needed_items, null, 2));
            return res.status(200).json({
                success: false,
                message: "Missing required modifiers",
                clarification_needed_items,
                validation_passed: false,                // 🆕 explicit
                needs_clarification: true,               // 🆕 consistent flag
                invalid_items_count: globalInvalidItems.length || 0,   // 🆕 counts for Blend
                invalid_modifiers_count: globalInvalidModifiers.length || 0,
                valid_items_count: validItems?.length || 0,
                retry_prompt: clarification_needed_items
                    .map(ci => {
                        const opts = ci.options || [];
                        if (opts.length > 0) {
                            return `For your ${ci.name}, would you like ${opts.join(" or ")}?`;
                        }
                        const missing = ci.missing?.[0];
                        const listName = missing?.modifier_list_name || "this option";
                        return `For your ${ci.name}, which ${listName} would you like?`;
                    })
                    .join(" ")
            });
        }

        console.log("🟢 TDZ guard (end of 5.5) — clarification_needed_items length:", clarification_needed_items.length);

        // ── Step 6: Enrich Modifiers ───────────────────────────────────────────────

        // ===== Ensure modifier alias maps are safe inside Step 6 =====
        const safeModifierAliasMap = (typeof modifierAliasMap !== "undefined" && modifierAliasMap) ? modifierAliasMap : {};
        const safeNormalizedModifierAliasMap = (typeof normalizedModifierAliasMap !== "undefined" && normalizedModifierAliasMap) ? normalizedModifierAliasMap : {};

        // Load modifier data once per client
        const modifierDataSnapshot = await db
            .collection("clients").doc(client_id).collection("modifiers").get();
        const modifierData = modifierDataSnapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
        const allModifierLists = Object.fromEntries(modifierData.map(m => [m.id, m]));

        const allModifiers = modifierData;

        let invalidModifiers = [];

        try {
            for (let item of validItems) {
                item.enrichedModifiers = Array.isArray(item.enrichedModifiers) ? item.enrichedModifiers : [];

                // 🧩 Guard with Firestore fallback for missing catalogMatch
                if (!item.catalogMatch || !item.catalogMatch.item_data) {
                    console.warn(`⚠️ "${item.name}" missing catalogMatch.item_data — performing Firestore modifier fallback.`);

                    try {
                        // 🧩 Load all modifier lists for this client
                        const modifierDocs = await db
                            .collection("clients")
                            .doc(client_id)
                            .collection("modifiers")
                            .get();

                        // 🔧 Correct Firestore modifier flattening (single-doc-per-modifier structure)
                        const allModifiers = modifierDocs.docs.map(doc => {
                            const data = doc.data();
                            return {
                                name: safeLower((data.name || "").trim()),
                                id: doc.id,
                                price:
                                    data.price ||
                                    data.price_money?.amount ||
                                    data.modifier_data?.price_money?.amount ||
                                    0,
                                list_id:
                                    data.modifier_data?.modifier_list_id ||
                                    data.modifier_list_id ||
                                    null,
                            };
                        });

                        const normalizedMods = (item.modifiers || []).map(m => safeLower((m || "").trim()));
                        const matchedMods = allModifiers.filter(m => normalizedMods.includes(m.name));

                        // 🧩 Guard: drop modifiers not in the item’s allowed lists (plug-and-play)
                        const allowedLists = (item.catalogMatch?.item_data?.modifier_list_info || []).map(l => l.modifier_list_id);

                        // 🧹 Clean lingering invalid modifiers before revalidation
                        if (Array.isArray(item.modifiers) && item.modifiers.length > 0 && invalidModifiers.length > 0) {
                            const before = [...item.modifiers];
                            item.modifiers = item.modifiers.filter(m => !invalidModifiers.includes(m));
                            if (before.length !== item.modifiers.length) {
                                console.log(`🧹 Removed lingering invalid modifiers for "${item.name}" → before=${before} after=${item.modifiers}`);
                            }
                        }

                        if (Array.isArray(allowedLists) && allowedLists.length > 0) {
                            const preFiltered = matchedMods.filter(m => allowedLists.includes(m.list_id || m.modifier_list_id));
                            if (preFiltered.length !== matchedMods.length) {
                                console.log(`🚫 Dropped ${matchedMods.length - preFiltered.length} modifiers not in allowed lists for "${item.name}"`);
                            }
                            matchedMods.length = 0;
                            matchedMods.push(...preFiltered);
                        }

                        // (If the item had no catalogMatch, fall back to any listIds stored on it)
                        const itemAllowedLists = Array.isArray(allowedLists) && allowedLists.length > 0
                            ? allowedLists
                            : (item.allowed_modifier_lists || []);

                        const filteredMods = [];

                        for (const m of matchedMods) {
                            const modListId = m.list_id || m.modifier_list_id || null;

                            if (itemAllowedLists.length > 0 && !itemAllowedLists.includes(modListId)) {
                                console.log(
                                    `🚫 Modifier "${m.name}" not allowed for "${item.name}" — list ${modListId} not in itemAllowedLists=${itemAllowedLists}`
                                );
                                invalidModifiers.push(m.name);
                                continue;
                            }

                            console.log(
                                `📦 Fallback found valid "${m.name}" → id=${m.id}, list=${modListId || "none"}, price=${m.price}`
                            );
                            filteredMods.push(m);
                        }

                        if (matchedMods.length > 0) {
                            const filteredMods = [];

                            for (const m of matchedMods) {
                                // 🚫 Skip modifiers already marked invalid in earlier validation
                                if (invalidModifiers.includes(m.name)) {
                                    console.log(`⏭️ Skipping "${m.name}" — previously marked invalid for "${item.name}"`);
                                    continue;
                                }

                                try {
                                    // 🧠 Fetch modifier metadata from Firestore
                                    const modDoc = await db
                                        .collection("clients")
                                        .doc(client_id)
                                        .collection("modifiers")
                                        .doc(m.id)
                                        .get();

                                    const modData = modDoc.exists ? modDoc.data() : null;
                                    const itemCategory = safeLower(item.catalogMatch?.category_name || "");
                                    const allowedParents = (modData?.allowed_parent_types || []).map(safeLower);

                                    const isCompatible =
                                        allowedParents.length === 0 || // unrestricted modifier
                                        allowedParents.includes(itemCategory);

                                    if (!isCompatible) {
                                        console.log(
                                            `🚫 Modifier "${m.name}" not compatible with "${item.name}" (item category=${itemCategory}, allowed=${allowedParents})`
                                        );
                                        invalidModifiers.push(m.name);
                                        continue;
                                    }

                                    console.log(
                                        `📦 Fallback found valid "${m.name}" → id=${m.id}, list=${m.list_id || "none"}, price=${m.price}`
                                    );
                                    filteredMods.push(m);
                                } catch (innerErr) {
                                    console.warn(`⚠️ Error validating modifier "${m.name}" compatibility:`, innerErr.message);
                                    // Graceful fallback: include it to avoid data loss if metadata missing
                                    filteredMods.push(m);
                                }
                            }

                            if (filteredMods.length > 0) {
                                item.enrichedModifiers = filteredMods.map(m => ({
                                    catalog_object_id: m.id,
                                    name: m.name,
                                    base_price_money: { amount: m.price, currency: "USD" },
                                }));
                                console.log(
                                    `✅ Fallback-enriched modifiers for "${item.name}":`,
                                    filteredMods.map(m => m.name)
                                );
                            } else {
                                console.warn(
                                    `⚠️ All fallback modifiers filtered out for "${item.name}" (likely invalid for this category).`
                                );
                                // 🧠 Early clarification — all modifiers invalid in fallback
                                if (item.modifiers?.length && (!filteredMods || filteredMods.length === 0)) {
                                    console.log(`🧠 Early exit — all modifiers invalid for "${item.name}" in fallback`);
                                    return res.status(200).json({
                                        success: false,
                                        validation_passed: false,
                                        invalid_modifiers: item.modifiers.map(m => ({ item_name: item.name, attempted_modifier: m })),
                                        needs_clarification: true,
                                        route: "clarify_modifier",
                                        retry_prompt: `Sorry, ${item.modifiers.join(", ")} isn’t available for ${item.name}. Would you like to pick another option instead?`
                                    });
                                }
                            }
                        } else {
                            console.warn(`⚠️ Fallback found no matching docs for "${item.name}" →`, normalizedMods);
                        }
                    } catch (err) {
                        console.error(`🔥 Firestore fallback enrichment failed for "${item.name}":`, err.message);
                    }

                    continue; // skip the catalogMatch-based logic below
                }

                // Fetch modifier lists from Firestore if present
                if (item.catalogMatch?.item_data?.modifier_list_info?.length) {
                    for (const listInfo of item.catalogMatch.item_data.modifier_list_info) {
                        const listId = listInfo.modifier_list_id;
                        const listSnap = await db
                            .collection("clients").doc(client_id)
                            .collection("modifiers").doc(listId)
                            .get();

                        if (listSnap.exists) {
                            const modifierList = listSnap.data();
                            modifierData.push(...(modifierList.modifiers || []).map(m => ({
                                ...m,
                                modifier_list_id: listId
                            })));
                        }
                    }
                }

                // 🆕 Validate required modifier lists (handle both missing & invalid options)
                let missingRequiredModifiers = [];

                // 🧩 collect invalids across all lists for this item
                let invalidThisItem = new Set();

                for (const listInfo of item.catalogMatch.item_data.modifier_list_info) {
                    const listId = listInfo.modifier_list_id;
                    const scopedModifiers = modifierData.filter(m => m.modifier_list_id === listId);
                    const modifierOptions = scopedModifiers.map(m =>
                        safeLower((m.name || "").trim())
                    );
                    console.log(`🧪 [Debug] listId=${listId} modifierOptions=`, modifierOptions);
                    const normalizedUserMods = (item.modifiers || []).map(m =>
                        safeLower((m || "").trim())
                    );

                    // Separate user modifiers into valid vs invalid
                    const validUserMods = normalizedUserMods.filter(u => modifierOptions.includes(u));
                    const invalidUserMods = normalizedUserMods.filter(u => !modifierOptions.includes(u));

                    // ✅ Case 1: All provided modifiers are valid
                    if (validUserMods.length > 0 && invalidUserMods.length === 0) {
                        console.log(`✅ All user-provided modifiers valid for "${item.name}" list ${listId}:`, validUserMods);
                        item.valid = true;
                        continue;
                    }

                    // 🧠 Instead of pushing now, collect candidates to review after all lists
                    invalidUserMods.forEach(mod => invalidThisItem.add(mod));

                    continue; // Skip further modifier handling for this item
                }

                // 🧩 Post-loop validation — keep only modifiers not valid in *any* list
                if (invalidThisItem.size > 0) {
                    const allAllowed = new Set(
                        Object.values(allModifierLists)
                            .filter(m =>
                                (item.catalogMatch?.item_data?.modifier_list_info || [])
                                    .some(l => l.modifier_list_id === m.modifier_list_id)
                            )
                            .map(m => safeLower(m.name.trim()))
                    );

                    // 🧪 Debug log to confirm valid modifiers recognized
                    console.log(`🧪 [Post-loop] allAllowed for "${item.name}":`, Array.from(allAllowed));

                    const trulyInvalid = [...invalidThisItem].filter(m =>
                        !allAllowed.has(m.trim().toLowerCase()) &&
                        !(item.enrichedModifiers || []).some(em => safeLower(em.name) === safeLower(m))
                    );

                    if (trulyInvalid.length > 0) {
                        // ✅ Prevent marking as invalid if any of the "invalid" names were actually enriched as valid
                        const stillInvalid = trulyInvalid.filter(mod =>
                            !(item.enrichedModifiers || []).some(em => safeLower(em.name) === safeLower(mod))
                        );

                        if (stillInvalid.length > 0) {
                            console.warn(`⚠️ Truly invalid modifiers for "${item.name}":`, stillInvalid);
                            item.invalidModifiers = stillInvalid;
                            item.reason = "invalid_modifier";
                            item.needs_clarification = true;

                            // 🧩 Only mark invalid and push if none were later enriched
                            if (stillInvalid.length > 0) {
                                item.valid = false;
                                if (!globalInvalidItems.some(i => i.name === item.name)) {
                                    globalInvalidItems.push(item);
                                }
                            }

                            globalInvalidModifiers.push(...stillInvalid.map(t => ({ name: t, reason: "not_in_any_list" })));
                            console.log(`📦 Scoped push → "${item.name}" with invalidModifiers=${stillInvalid.join(", ")}`);
                        } else {
                            console.log(`✅ Skipped false invalids for "${item.name}" — all enriched modifiers verified valid.`);
                        }
                    } else {
                        console.log(`✅ All modifiers for "${item.name}" validated within allowed lists`);
                    }
                }

                // 🧩 Preserve currently valid modifiers before clarification rebuild
                if (item.enrichedModifiers?.length && !item._preservedMods) {
                    item._preservedMods = [...item.enrichedModifiers];
                }

                // 🧠 After scanning all lists, handle collective return if any required modifiers missing
                if (missingRequiredModifiers.length > 0) {
                    const retryPrompt = missingRequiredModifiers
                        .map(it => {
                            const opts = (it.options || [])
                                .map(o => o.trim())
                                .join(", ")
                                .replace(/,\s*([^,]*)$/, ", or $1");
                            return `For your ${it.name}, would you like it ${opts}?`;
                        })
                        .join(" ");

                    console.log("🛑 Early return for missing required modifiers (multi-item case)");
                    return res.status(200).json({
                        success: false,
                        message: "Missing required modifiers",
                        clarification_needed_items: missingRequiredModifiers,
                        validation_passed: false,
                        needs_clarification: true,
                        retry_prompt: retryPrompt
                    });
                }

                // 🔎 Validate each user-provided modifier against allowed list
                for (const userMod of item.modifiers || []) {
                    let match;
                    try {
                        match = modifierData.find(m =>
                            typeof m?.name === "string" && typeof userMod === "string" &&
                            m.name.toLowerCase().trim() === userMod.toLowerCase().trim()
                        );
                    } catch (err) {
                        console.error("🚨 Crash in Step 6 userMod match", { userMod, error: err.message });
                        throw err;
                    }

                    if (match) {
                        console.log(`✅ User provided valid modifier "${userMod}" → list_id=${match?.modifier_list_id || "unknown"}`);
                        item.enrichedModifiers.push({
                            catalog_object_id: match.id,
                            name: match.name,
                            base_price_money: match?.price_money || match?.modifier_data?.price_money,
                            modifier_list_id: match.modifier_list_id
                        });

                        // 🩹 Fix: once a modifier is matched, stop checking other lists
                        break;
                    } else {
                        // ❌ Invalid → track globally, but do not attach
                        globalInvalidModifiers.push({
                            item: item.name,
                            attempted_modifier: userMod
                        });
                        console.log(`⚠️ Invalid modifier ignored: "${userMod}" for ${item.name}`);
                    }

                    // 🩹 Prevent duplicate pushes for the same invalid item
                    if (!item.invalidModifiers?.includes(userMod)) {
                        item.invalidModifiers = item.invalidModifiers || [];
                        item.invalidModifiers.push(userMod);
                    }
                    item.valid = false;
                    item.reason = "invalid_modifier";
                    item.needs_clarification = true;

                    // 🆕 Scoped-safe global push (ensure item is defined here)
                    if (item && !globalInvalidItems.find(i => i.name === item.name)) {
                        globalInvalidItems.push({
                            name: item.name,
                            invalid_modifiers: item.invalidModifiers || [],
                            allowed_modifier_lists: item.allowed_modifier_lists || item.allowedModifierLists || [],
                            reason: "invalid_modifier"
                        });
                        console.log("🆕 Pushed invalid_modifier into globalInvalidItems:", JSON.stringify(globalInvalidItems, null, 2));
                    }

                    break; // 🧠 stop duplicate clarification pushes for same item
                }

                // Resolve allowed modifier lists
                const allowedModifierLists = item.allowed_modifier_lists && item.allowed_modifier_lists.length > 0
                    ? item.allowed_modifier_lists
                    : (
                        item.catalogMatch?.itemData?.modifierListInfo ||
                        item.catalogMatch?.itemData?.modifier_list_info ||
                        []
                    ).map(info => info.modifierListId || info.modifier_list_id);

                const modifierOptions = modifierData.filter(mod =>
                    allowedModifierLists.includes(
                        mod?.modifier_data?.modifier_list_id || mod?.modifier_list_id
                    )
                );

                // Per-item state
                item.enrichedModifiers = [];
                item.invalidModifiers = [];
                let hadInvalidModifier = false;

                // 🛡️ Sanitize modifiers to guarantee safe iteration
                item.modifiers = Array.isArray(item.modifiers)
                    ? item.modifiers.filter(m => typeof m === "string" && m.trim().length > 0).map(m => m.trim())
                    : [];

                for (const spokenModifier of item.modifiers) {
                    // At this point, spokenModifier is guaranteed a non-empty string.
                    let raw = "";
                    try {
                        raw = safeLower(spokenModifier, "spokenModifier").replace(/[^a-z0-9]/g, "");
                    } catch (err) {
                        console.error("🚨 Crash in Step 6 raw normalization", { spokenModifier, error: err.message });
                        globalInvalidModifiers.push({ name: spokenModifier, reason: "normalization_crash" });
                        item.invalidModifiers.push(spokenModifier);
                        hadInvalidModifier = true;
                        continue;
                    }

                    let alias = safeNormalizedModifierAliasMap[raw] || null;
                    const query = alias || spokenModifier;

                    // Skip duplicates (variation vs modifier)
                    if (
                        typeof query === "string" &&
                        item.variation
                    ) {
                        if (safeLower(query, "modifier_query") === safeLower(item.variation, "variation")) {
                            console.log(`⚠️ Skipping duplicate — query "${query}" matches variation "${item.variation}"`);
                            continue;
                        }
                    }

                    if (!query || typeof query !== "string") {
                        globalInvalidModifiers.push({ name: spokenModifier, reason: "invalid_query" });
                        item.invalidModifiers.push(spokenModifier);
                        hadInvalidModifier = true;
                        continue;
                    }

                    const normalizedQuery = (query || "").toLowerCase().replace(/[^a-z0-9]/g, "");
                    alias = normalizedModifierAliasMap[normalizedQuery] || query;

                    // 🆕 Detect negative customizations before fuzzy matching
                    const lowerMod = spokenModifier.toLowerCase().trim();
                    if (
                        lowerMod.startsWith("no") ||
                        lowerMod.startsWith("without") ||
                        lowerMod.startsWith("remove")
                    ) {
                        console.log(`✏️ Treating "${spokenModifier}" as customization for "${item.name}"`);
                        item.customizations = item.customizations || [];
                        if (!item.customizations.includes(spokenModifier)) {
                            item.customizations.push(spokenModifier);
                        }
                        continue; // Skip normal modifier validation
                    }

                    // 🩹 Guard against items with no catalogMatch (e.g., direct variation overrides)
                    const scopedLists = item.catalogMatch?.item_data?.modifier_list_info
                        ? item.catalogMatch.item_data.modifier_list_info.map(l => l.modifier_list_id)
                        : Array.isArray(item.allowed_modifier_lists)
                            ? item.allowed_modifier_lists
                            : [];

                    // 🆕 Filter scoped modifiers from modifierData by allowed lists
                    const scopedData = modifierData.filter(m =>
                        scopedLists.includes(m.modifier_list_id || m.modifier_data?.modifier_list_id)
                    );

                    // 🆕 Flatten into a single array (handles both nested and flat data)
                    const scopedModifiersFlat = Array.isArray(scopedData)
                        ? scopedData.flatMap(list =>
                            list?.options?.length
                                ? list.options.map(opt => ({
                                    ...opt,
                                    modifier_list_id: list.modifier_list_id
                                }))
                                : [list]
                        )
                        : [];

                    // Use this flattened array for fuzzy matching
                    const matched = fuzzyMatchModifier(alias, scopedModifiersFlat);

                    if (matched) {
                        console.log(`✅ User provided valid modifier "${alias}" → list_id=${matched?.modifier_list_id || "unknown"}`);
                        item.valid = true; // 🧠 re-flip to valid after successful revalidation

                        // 🧩 Enrich valid modifier immediately
                        const modifierPrice =
                            matched?.modifier_data?.price_money ??
                            matched?.price_money ??
                            (typeof matched?.price === "number"
                                ? { amount: matched.price, currency: "USD" }
                                : { amount: 0, currency: "USD" });

                        item.enrichedModifiers = item.enrichedModifiers || [];
                        item.enrichedModifiers.push({
                            catalog_object_id: matched.id,
                            name: matched.name,
                            base_price_money: modifierPrice,
                            modifier_list_id: matched.modifier_list_id || matched.modifier_data?.modifier_list_id || "unknown",
                        });

                        continue;
                    } else {
                        console.warn(`⚠️ Modifier "${alias}" not found within allowed lists:`, scopedLists);
                        invalidModifiers.push(alias);

                        // 🧠 Move your invalid handler *inside* this else block
                        item.valid = false;
                        item.reason = "invalid_modifier";
                        item.invalidModifiers = item.invalidModifiers || [];
                        item.invalidModifiers.push(alias);
                        item.needs_clarification = true;
                        globalInvalidItems.push(item);

                        // 🆕 Early clarification return for invalid modifier (safe and scoped)
                        if (Array.isArray(validItems) && validItems.length > 0) {
                            console.log(`🧠 Early exit — invalid modifier "${alias}" for "${item.name}", triggering clarification`);

                            // Record globally for downstream consistency (Step 9 still sees it if needed)
                            globalInvalidModifiers.push({ item_name: item.name, attempted_modifier: alias });
                            globalInvalidItems.push({
                                name: item.name,
                                reason: "invalid_modifier",
                                invalid_modifiers: [alias],
                                needs_clarification: true
                            });

                            // ✅ Return structured clarification response
                            return res.status(200).json({
                                success: false,
                                validation_passed: false,
                                invalid_modifiers: globalInvalidModifiers,
                                needs_clarification: true,
                                route: "clarify_modifier",
                                retry_prompt: `Sorry, ${alias} isn’t available for ${item.name}. Would you like something else instead?`
                            });
                        }
                    }

                    if (matched && typeof matched === "object") {
                        let modifierPrice =
                            matched?.modifier_data?.price_money ??
                            matched?.price_money ??
                            (typeof matched?.price === "number"
                                ? { amount: matched.price, currency: "USD" }
                                : undefined);

                        if (!modifierPrice || typeof modifierPrice.amount !== "number") {
                            invalidModifiers.push({ name: spokenModifier });
                            item.invalidModifiers.push(spokenModifier);
                            hadInvalidModifier = true;
                            globalInvalidModifiers.push({ name: spokenModifier, reason: "missing_price" });
                            continue;
                        }

                        item.enrichedModifiers.push({
                            catalog_object_id: matched.id,
                            name: matched.name,
                            base_price_money: modifierPrice,
                            modifier_list_id: matched.modifier_list_id  // 🆕 attach listId
                        });

                        item.valid = true;
                    } else {
                        invalidModifiers.push({ name: spokenModifier });
                        item.invalidModifiers.push(spokenModifier);
                        hadInvalidModifier = true;
                        globalInvalidModifiers.push({ name: spokenModifier, reason: "no_match" });
                    }
                } // end for(spokenModifier)

                // ✅ Safe validity guard — only flip to true if no invalid modifiers in this pass
                if (!hadInvalidModifier && Array.isArray(item.modifiers) && item.modifiers.length > 0) {
                    item.valid = true;
                    console.log(`✅ Safe guard → marked "${item.name}" valid (no invalid modifiers detected in current pass).`);
                }

                // 🧾 Debug — show final customizations for this item
                if (item.customizations && item.customizations.length > 0) {
                    console.log(`📝 Customizations for "${item.name}":`, item.customizations);
                }

                // 🆕 Refined invalid handling
                if (hadInvalidModifier) {
                    item.valid = false;

                    // If we captured explicit invalid modifiers, prefer that reason
                    if (item.invalidModifiers && item.invalidModifiers.length > 0) {
                        item.drop_reason = "invalid_modifier";
                        globalInvalidItems.push(item);
                    }
                    // Otherwise, fall back to required modifier guard (handled later in Step 6.5)
                }

            } // end for(item)

        } catch (error) {
            console.error(`🔥 Error while enriching modifiers:`, error?.stack || error?.message || error);
            return res.status(500).json({
                success: false,
                message: "Unexpected error while enriching modifiers",
            });
        }

        // Keep only valid items
        validItems = validItems.filter(i => i?.valid === true);
        console.log(`🧹 Step 6 — post-modifier filter: kept=${validItems.length}`);

        // 🧠 Step 6.3 — Check for missing required modifiers (e.g., temperature)
        for (const ci of enrichedItems) {
            const modifierData = allModifiers || []; // 🔧 ensures availability for Firestore fallback
            if (!ci.allowed_modifier_lists || !Array.isArray(ci.allowed_modifier_lists)) continue;

            const requiredLists = ci.allowed_modifier_lists.filter(id => {
                const listDoc = allModifierLists?.[id];
                return listDoc && listDoc.min_selected_modifiers > 0; // Only required ones
            });

            for (const listId of requiredLists) {
                const userHasSelected = (ci.enrichedModifiers || []).some(m => m.modifier_list_id === listId);
                if (!userHasSelected) {
                    console.warn(`⚠️ Missing required modifier for "${ci.name}" → list_id=${listId}`);
                    invalidModifiers.push(`missing required modifier: ${listId}`);
                    const listDoc = allModifierLists?.[listId];
                    const modifierOptions = (() => {
                        if (!listDoc) return [];

                        // ✅ handle array shapes first
                        if (Array.isArray(listDoc.modifier_data)) return listDoc.modifier_data.map(m => m.name);
                        if (Array.isArray(listDoc.modifier_list_data?.modifier_data))
                            return listDoc.modifier_list_data.modifier_data.map(m => m.name);
                        if (Array.isArray(listDoc.modifiers)) return listDoc.modifiers.map(m => m.name);
                        if (Array.isArray(listDoc.options)) return listDoc.options.map(o => o.name);

                        // 🆕 handle Firestore "one doc per modifier" pattern
                        const flatFromCollection = modifierData
                            .filter(m => m.modifier_list_id === listId)
                            .map(m => m.name);

                        if (flatFromCollection.length > 0) {
                            console.log(`🧪 [Debug] Fetched ${flatFromCollection.length} modifiers for list ${listId}:`, flatFromCollection);
                            return flatFromCollection;
                        }

                        return [];
                    })();

                    clarification_needed_items.push({
                        name: ci.name,
                        reason: "missing_required_modifier",
                        options: modifierOptions && modifierOptions.length > 0
                            ? modifierOptions.filter(Boolean)
                            : (listDoc?.modifier_data || listDoc?.modifiers || []).map(m => m.name),
                        needs_clarification: true,
                        // 🆕 Provides context for Step 6.5 prompt ("which temperature would you like?")
                        missing: [{ modifier_list_name: listDoc?.name || listId || "option" }]
                    });
                }
            }
        }

        // 🧽 Deduplicate invalid items before clarification
        if (globalInvalidItems?.length > 0) {
            const seen = new Set();
            globalInvalidItems = globalInvalidItems.filter(it => {
                // create a unique key combining item name + invalid modifiers
                const mods = Array.from(new Set(it.invalidModifiers || [])).join(",");
                const key = `${(it.name || "").toLowerCase()}|${mods}`;
                if (seen.has(key)) return false;
                seen.add(key);
                // also deduplicate inside invalidModifiers arrays
                if (it.invalidModifiers?.length > 1) {
                    it.invalidModifiers = Array.from(new Set(it.invalidModifiers));
                }
                return true;
            });
            console.log(`🧽 Deduplicated globalInvalidItems → now ${globalInvalidItems.length}`);
        }

        // 🩹 Failsafe: if validCorrection=true but validItems somehow filtered out, restore from enrichedItems
        if (validCorrection === true && (!validItems || validItems.length === 0) && Array.isArray(enrichedItems) && enrichedItems.length > 0) {
            console.warn("🩹 Restoring validItems from enrichedItems after valid correction flow.");
            validItems = enrichedItems;
        }

        // 🚨 Guard: no valid items remaining, abort gracefully
        if (!validItems || validItems.length === 0) {
            console.error("🚨 No valid line items to send to Square (post-modifier filter).");

            // 🔐 Reuse global clientId defined at top of function
            if (!clientId || clientId === "unknown") {
                console.error("⚠️ Missing or unknown clientId in modifier validation block.");
                return res.status(500).json({
                    success: false,
                    message: "Client ID missing during invalid item clarification.",
                });
            }

            // 🧠 Build a consistent retry prompt for invalid modifiers
            if (!retry_prompt || retry_prompt.trim() === "") {
                retry_prompt = "Sorry, we don’t have that option. Would you like something else for that?";
            }

            if (globalInvalidItems?.length > 0) {
                const sentences = [];

                for (const it of globalInvalidItems) {
                    const invalidMods = Array.from(new Set(it.invalidModifiers || []));
                    if (invalidMods.length === 0) continue;

                    const itemName = it.name || "your item";

                    // 🧩 Handle single vs multiple modifiers gracefully
                    let modPhrase = "";
                    if (invalidMods.length === 1) {
                        modPhrase = invalidMods[0];
                    } else if (invalidMods.length === 2) {
                        modPhrase = `${invalidMods[0]} or ${invalidMods[1]}`;
                    } else {
                        modPhrase = `${invalidMods.slice(0, -1).join(", ")}, or ${invalidMods.slice(-1)}`;
                    }

                    // 💬 Deterministic, clear phrasing
                    sentences.push(`We don’t have ${modPhrase} for ${itemName}. Would you like something else for that?`);
                }

                if (sentences.length > 0) {
                    retry_prompt = sentences.join(" ");
                }
            }

            // 🪵 Log invalid items and final retry prompt (for debugging)
            console.log("🔍 Invalid items summary:", JSON.stringify(globalInvalidItems, null, 2));
            console.log(`🔁 Final retry_prompt being returned: "${retry_prompt}"`);

            // 🧾 Final structured response for Blend
            const invalid_items_count = (globalInvalidItems || []).length;
            const invalid_modifiers_count = (invalidModifiers || []).length;

            console.log(`🔁 Final retry_prompt being returned: "${retry_prompt}"`);

            return res.status(200).json({
                success: false,
                validation_passed: false,
                invalid_items: globalInvalidItems || [],
                invalid_modifiers: invalidModifiers || [],
                invalid_items_count,
                invalid_modifiers_count,
                needs_clarification: true,
                retry_prompt,
                message: "No valid line items after modifier validation."
            });
        }

        // ===== Step 6.4: Invalid Modifier Pre-Check =====
        for (const item of validItems) {
            // 🧩 Skip if this item already validated its modifiers in Step 6.3
            if (item.validatedModifiers === true) {
                console.log(`✅ "${item.name}" already validated modifiers earlier — skipping invalid check.`);
                continue;
            }

            if (!item.catalogMatch || !item.modifiers || item.modifiers.length === 0) continue;

            const allowedLists = item.catalogMatch.item_data?.modifier_list_info || [];
            const allAllowedModifiers = new Set();

            // ✅ Collect all valid modifier names (fully normalized)
            for (const list of allowedLists) {
                const listDoc = await db
                    .collection("clients")
                    .doc(client_id)
                    .collection("modifiers")
                    .doc(list.modifier_list_id)
                    .get();

                if (listDoc.exists && listDoc.data()?.modifiers) {
                    for (const mod of listDoc.data().modifiers) {
                        if (mod?.name) allAllowedModifiers.add(safeLower(mod.name));
                    }
                }
            }

            // 🧼 Force normalization for safe comparison
            const normalizedAllowed = new Set([...allAllowedModifiers].map(m => safeLower(m.trim())));
            const normalizedUserMods = item.modifiers.map(m => safeLower(m.trim()));

            // 🩹 Skip Step 6.4 re-validation for items that already passed earlier checks
            if (item.valid === true) {
                console.log(`✅ "${item.name}" already validated modifiers — skipping Step 6.4 recheck.`);
                continue;
            }

            // 🧩 Detect truly invalid modifiers after uniform normalization
            const invalidMods = normalizedUserMods.filter(m => !normalizedAllowed.has(m));

            if (invalidMods.length > 0) {
                console.warn(`❌ Invalid modifier(s) detected for "${item.name}": ${invalidMods.join(", ")}`);
                item.valid = false;
                item.drop_reason = "invalid_modifier";
                item.reason = "invalid_modifier";
                item.invalid_modifiers = invalidMods;
                item.needs_clarification = true;

                clarification_needed_items.push({
                    name: item.name,
                    reason: "invalid_modifier",
                    invalid_modifiers: invalidMods,
                    needs_clarification: true
                });

                // 🆕 Mirror invalid modifier info into globalInvalidItems for retry prompt generation
                // 🧩 Identify the specific instance that truly contained these invalid modifiers
                const itemIndex = parsedItemsOrdered.findIndex(i => {
                    if (i.name?.toLowerCase() !== item.name?.toLowerCase()) return false;
                    if (!Array.isArray(i.modifiers)) return false;

                    // check for any overlap between the failing modifiers and this item's modifiers
                    const overlap = (invalidMods || []).some(mod =>
                        i.modifiers.some(m => m.toLowerCase().includes(mod.toLowerCase()))
                    );
                    console.log(
                        `🧠 Overlap debug → item="${item.name}", invalidMods=${item.invalidModifiers || invalidMods}, itemMods=${i.modifiers}`
                    );

                    return overlap;
                });

                // 🛡️ Fallback if no overlap match found
                const finalIndex = itemIndex !== -1 ? itemIndex : parsedItemsOrdered.indexOf(item);

                // 🧩 Final guard — skip if item already validated elsewhere
                const alreadyValid = validItems.some(v =>
                    v.name?.toLowerCase() === item.name?.toLowerCase() &&
                    (v.valid === true || (Array.isArray(v.enrichedModifiers) && v.enrichedModifiers.length > 0))
                );

                if (alreadyValid) {
                    console.log(`🛑 Skipping invalid push — "${item.name}" already valid in another instance.`);
                } else if (item.valid === true || (Array.isArray(item.enrichedModifiers) && item.enrichedModifiers.length > 0)) {
                    console.log(`🛑 Skipping invalid push — "${item.name}" already validated or enriched.`);
                } else {
                    // 🧩 Re-check validity now that validItems is populated
                    const isValidNow = validItems.some(v =>
                        v.name?.toLowerCase() === item.name?.toLowerCase() &&
                        (v.valid === true || (Array.isArray(v.enrichedModifiers) && v.enrichedModifiers.length > 0))
                    );

                    if (isValidNow) {
                        console.log(`🛑 Late-stage skip — "${item.name}" now recognized as valid, skipping invalid push.`);
                        continue;
                    }

                    // 🕐 Defer push to next event tick to allow validItems update to complete
                    setTimeout(() => {
                        globalInvalidItems.push({
                            ...item,
                            index: itemIndex,
                            reason: "invalid_modifier",
                            invalid_modifiers: invalidMods || [],
                            needs_clarification: true
                        });
                        console.log(`📦 [Deferred] Pushed invalid item → ${item.name} [index=${itemIndex}] with invalid_modifiers:`, invalidMods);
                    }, 0);
                }
            }
        } // <-- this closes the for-loop cleanly

        // 🧩 Step 6.5 — build clarification prompts for all flagged invalid items + required modifiers
        if (clarification_needed_items.length > 0 || globalInvalidItems.length > 0) {
            // Merge any invalid-modifier items into the clarification list
            for (const badItem of globalInvalidItems) {
                if (
                    badItem.reason === "invalid_modifier" &&
                    Array.isArray(badItem.invalidModifiers) &&
                    badItem.invalidModifiers.length > 0
                ) {
                    clarification_needed_items.push({
                        name: badItem.name,
                        reason: "invalid_modifier",
                        invalid_modifiers: badItem.invalidModifiers,
                        needs_clarification: true
                    });

                    console.log(
                        `🧠 Clarification built → item="${badItem.name}" invalid_modifiers=${badItem.invalidModifiers.join(", ")}`
                    );
                }
            }

            console.log("🟢 Step 6.5 clarifications (merged):", clarification_needed_items);

            // 🧠 Build one unified retry prompt — item/modifier pairs only, no positional assumptions
            retry_prompt = clarification_needed_items
                .map(ci => {
                    const opts = ci.options || [];
                    const invalidMods = ci.invalid_modifiers || ci.attempted_modifiers || [];

                    // 🆕 Safe guard for any undefined variables (covers required-modifier + fallback cases)
                    const badMods =
                        invalidMods.length > 0
                            ? invalidMods.join(", ")
                            : "that option";

                    const index = ci.index !== undefined ? ` [#${ci.index}]` : "";
                    if (opts.length > 0) {
                        return `For your ${ci.name}${index}, would you like ${opts.join(" or ")}?`;
                    }
                    if (invalidMods.length > 0) {
                        return `For your ${ci.name}${index}, we don't have ${invalidMods.join(", ")}. Which option would you like instead?`;
                    }

                    if (ci.reason === "missing_required_modifier" && opts.length > 0) {
                        return `For your ${ci.name}${index}, would you like it ${opts.join(" or ")}?`;
                    }

                    // 🆕 Unified fallback — handles missing required modifiers cleanly with list context
                    const missing = ci.missing?.[0];
                    const listName = missing?.modifier_list_name || "this option";
                    return `For your ${ci.name}${index}, which ${listName} would you like?`;
                })
                .join(" ");

            console.log(`🧠 Step 6.5 built retry_prompt: "${retry_prompt}"`);

            // 🧩 Restore preserved valid modifiers after clarification rebuild
            for (const item of validItems) {
                if (item._preservedMods?.length) {
                    console.log(`♻️ Restoring preserved modifiers for "${item.name}" →`, item._preservedMods.map(m => m.name || m));
                    item.enrichedModifiers = [
                        ...new Set([...(item.enrichedModifiers || []), ...item._preservedMods])
                    ];
                }
            }
        }
        // ===== End of Step 6.5 =====

        // 🧱 Ensure retry_prompt is safely initialized (reuse existing variable)
        retry_prompt = retry_prompt || "";

        invalidModifiers = globalInvalidModifiers || [];
        const droppedItems = Array.isArray(enrichedItems)
            ? enrichedItems.filter(i => i?.drop_reason)
            : [];

        if (droppedItems.length) {
            console.log(`🪓 Dropped items: ${droppedItems.map(d => d.name).join(", ")}`);
        }

        // 🧽 Step 6.8 — Deduplicate invalid items before clarification fallback
        if (globalInvalidItems?.length > 0) {
            const seenNames = new Set();
            globalInvalidItems = globalInvalidItems.filter(it => {
                const key = it?.name?.toLowerCase();
                if (!key || seenNames.has(key)) return false;
                seenNames.add(key);
                return true;
            });
            console.log(`🧽 Deduplicated globalInvalidItems pre-fallback → now ${globalInvalidItems.length}`);
        }

        // 🛡️ Force global retry_prompt preservation before Step 7 (improved context)
        if (clarification_needed_items.length > 0 && retry_prompt.trim() === "") {
            retry_prompt = clarification_needed_items
                .map(ci => {
                    const missing = ci.missing?.[0];
                    const listName = missing?.modifier_list_name || "this option";
                    return `For your ${ci.name}, which ${listName} would you like?`;
                })
                .join(" ");
            console.log("🛡️ Forced preservation — populated retry_prompt before Step 7:", retry_prompt);
        }

        // 🧠 Handle items flagged as invalid_modifier before final drop
        const clarificationFallback = globalInvalidItems.filter(i => i.reason === "invalid_modifier");

        if (clarificationFallback.length > 0 && retry_prompt.trim() === "") {
            console.log("🟡 Detected invalid modifiers needing clarification:", clarificationFallback.map(i => i.name));

            // ✅ Guard — dynamically rebuild allowed modifier names from Firestore instead of modifierOptions
            let allAllowedMods = [];

            for (const it of clarificationFallback) {
                if (Array.isArray(it.allowed_modifier_lists)) {
                    for (const listId of it.allowed_modifier_lists) {
                        const modDoc = await admin.firestore()
                            .collection("clients")
                            .doc(req.body.client_id)
                            .collection("modifiers")
                            .doc(listId)
                            .get();

                        const modData = modDoc.exists ? modDoc.data() : null;
                        if (modData?.options) {
                            allAllowedMods.push(...modData.options.map(o => o.name.toLowerCase().trim()));
                        }
                    }
                }
            }

            // Deduplicate allowed modifier names
            allAllowedMods = [...new Set(allAllowedMods)];

            validCorrection = clarificationFallback.every(it =>
                !it.invalid_modifiers ||
                it.invalid_modifiers.every(mod => allAllowedMods.includes(mod.toLowerCase().trim()))
            );

            if (validCorrection) {
                console.log("✅ User provided valid correction — skipping Step 6.9 fallback");

                // 🧹 Clear stale invalid items once valid correction detected
                if (Array.isArray(globalInvalidItems) && globalInvalidItems.length > 0) {
                    console.log("🧹 Clearing globalInvalidItems after valid correction");
                    globalInvalidItems = [];
                }

                // 🧹 Also clear stale invalidModifiers for clean Step 7 pass
                if (Array.isArray(invalidModifiers) && invalidModifiers.length > 0) {
                    console.log("🧹 Clearing invalidModifiers after valid correction");
                    invalidModifiers = [];
                }

                // 🩹 Instead of returning early, set a flag
                validCorrection = true;

                // 🧭 Guard — if user correction is valid, skip retry prompt entirely
                console.log("🧭 Skipping Step 6.8 retry prompt — proceeding to Step 7+");
                retry_prompt = "";

                // ⚠️ Do NOT return here — allow flow to continue to Step 7+
            } else {
                // 🧩 Unified and simplified retry prompt
                const retrySentences = await Promise.all(
                    clarificationFallback.map(async it => {
                        const itemName = it.name || "your item";
                        const badMods = Array.isArray(it.invalid_modifiers) ? it.invalid_modifiers.join(", ") : null;
                        let sentence;

                        // 🧠 Case 1: Invalid modifier
                        if (it.reason === "invalid_modifier" && badMods) {
                            sentence = `For your ${itemName}, we don't have ${badMods}. Would you like to pick a different option instead?`;
                        }
                        // 🧠 Case 2: Missing required modifier(s)
                        else if (it.reason === "missing_required_modifier" && Array.isArray(it.allowed_modifier_lists)) {
                            const missingLists = [];

                            for (const listId of it.allowed_modifier_lists) {
                                const modDoc = await admin.firestore()
                                    .collection("clients")
                                    .doc(req.body.client_id)
                                    .collection("modifiers")
                                    .doc(listId)
                                    .get();

                                const modData = modDoc.exists ? modDoc.data() : null;
                                if (modData && (modData.min_selected_modifiers ?? 0) > 0) {
                                    const optionNames = (modData.options || []).map(o => o.name.toLowerCase().trim());
                                    const hasAny = Array.isArray(it.modifiers) && it.modifiers.some(m => optionNames.includes(m.toLowerCase().trim()));
                                    if (!hasAny) missingLists.push(modData.name || listId);
                                }
                            }

                            if (missingLists.length > 0) {
                                sentence = `Looks like your ${itemName} is missing a required option — ${missingLists.join(", ")}. Which would you like to add?`;
                            } else {
                                sentence = `Looks like your ${itemName} is missing a required option. Which would you like to add?`;
                            }
                        }
                        // 🧠 Case 3: Invalid item entirely
                        else if (it.reason === "invalid_item") {
                            sentence = `I'm not seeing ${itemName} on the menu. Would you like to choose something else instead?`;
                        }
                        // 🧠 Case 4: Generic / uncertain → graceful human fallback
                        else {
                            sentence = `I'm having a little trouble with your ${itemName}. Would you like me to transfer you to a team member to finish up?`;
                        }

                        return sentence;
                    })
                );

                const retryPrompt = retrySentences.join(" ");
                console.log(`🔁 Final retry_prompt being returned: "${retryPrompt}"`);

                return res.status(200).json({
                    success: false,
                    message: "Invalid modifiers detected — clarification needed",
                    clarification_needed_items: clarificationFallback,
                    validation_passed: false,
                    needs_clarification: true,
                    retry_prompt: retryPrompt
                });
            }
        }

        // ===== Step 6.9 → Pre-Step-7 Sanity =====
        console.log("🔎 Pre-Step-7 sanity:", {
            enrichedCount: Array.isArray(enrichedItems) ? enrichedItems.length : "not array",
            validCount: Array.isArray(validItems) ? validItems.length : "not array",
            firstValidItem: validItems?.[0]
                ? {
                    name: validItems[0].name,
                    variation_id: validItems[0].variation_id,
                    catalog_item_id: validItems[0].catalog_item_id,
                    base_price_money: validItems[0].base_price_money,
                    enrichedModifiers: validItems[0].enrichedModifiers,
                    customizations: validItems[0].customizations,   // 🆕 added
                }
                : null,
        });

        // 🧭 Forwarding valid correction flag through normal flow for pricing + Square POST
        if (typeof validCorrection !== "undefined" && validCorrection === true) {
            console.log("🧭 Forwarding valid correction through normal flow for pricing and Square POST");
            // Ensure retry_prompt is empty to avoid triggering Step 7 fallback
            retry_prompt = "";
        }

        // 🛡️ Guard — preserve Step 6.5 retry prompt from being overwritten later
        if (retry_prompt && retry_prompt.trim() !== "") {
            console.log("🛡️ Guard — preserving Step 6.5 retry_prompt:", retry_prompt);
        }


        // ===== Step 7: Final guard validation =====

        // 🧹 Post-Step 6 cleanup — drop invalid modifiers from raw item.modifiers
        if (Array.isArray(enrichedItems) && enrichedItems.length > 0 && Array.isArray(invalidModifiers) && invalidModifiers.length > 0) {
            for (const item of enrichedItems) {
                if (!Array.isArray(item.modifiers)) continue;
                const before = [...item.modifiers];
                item.modifiers = item.modifiers.filter(m => !invalidModifiers.includes(safeLower(m)));

                if (before.length !== item.modifiers.length) {
                    console.log(
                        `🧽 Removed invalid modifiers from "${item.name}" → before=${before}, after=${item.modifiers}`
                    );
                }
            }
        }

        // 🛡️ Skip Step 7 fallback if Step 6.5 already set a retry prompt
        if (retry_prompt && retry_prompt.trim() !== "") {
            console.log("🛡️ Skipping Step 7 fallback — retry_prompt already set:", retry_prompt);
            return res.status(200).json({
                success: false,
                validation_passed: false,
                needs_clarification: true,
                retry_prompt
            });
        }

        // ✅ Sanity guards before using validItems / enrichedItems
        if (!Array.isArray(validItems)) {
            throw new Error(`🚨 Step 7: validItems is not an array (type=${typeof validItems})`);
        }
        if (!Array.isArray(enrichedItems)) {
            throw new Error(`🚨 Step 7: enrichedItems is not an array (type=${typeof enrichedItems})`);
        }

        console.log(`✅ Step 7: validItems=${validItems.length}, enrichedItems=${enrichedItems.length}`);

        // 🟢 Sync snapshot after Step 7 enrichment
        global.parsedItemsOrdered = parsedItemsOrdered;

        // 🚦 Final guard validation loop
        for (const item of validItems) {
            if (!item) continue;

            if (!item?.base_price_money || typeof item.base_price_money.amount !== "number") {
                console.error(`🚨 Invalid price_money for "${item?.name}"`);
                return res.status(500).json({
                    success: false,
                    message: `Final validation failed for price of item: ${item?.name}`,
                });
            }

            if (Array.isArray(item.enrichedModifiers)) {
                for (const mod of item.enrichedModifiers) {
                    if (!mod?.base_price_money || typeof mod.base_price_money.amount !== "number") {
                        console.error(`🚨 Invalid modifier price for "${mod?.name}" on "${item?.name}"`);
                        return res.status(500).json({
                            success: false,
                            message: `Final validation failed for modifier "${mod?.name}" on item "${item?.name}"`,
                        });
                    }
                }
            }
        }

        // 🚨 If nothing valid remains, return gracefully instead of 500
        if ((globalInvalidItems && globalInvalidItems.length > 0) || (invalidModifiers && invalidModifiers.length > 0)) {
            console.error("🚨 No valid line items to send to Square");

            // 🧠 If all dropped items failed due to invalid modifiers → dynamic retry prompt
            if (globalInvalidItems.some(i => i.reason === "invalid_modifier")) {
                console.log("🟠 Redirecting to dynamic invalid-modifier retry fallback...");
                const clarificationFallback = globalInvalidItems.filter(i => i.reason === "invalid_modifier");
                let retrySentences = [];

                for (const it of clarificationFallback) {
                    const itemName = it.name || "item";
                    const badMods = (it.invalid_modifiers || []).join(", ");
                    const allowedLists = it.allowed_modifier_lists || [];

                    // 🧾 Collect a few example alternatives from catalog
                    let suggestions = new Set();
                    for (const listId of allowedLists) {
                        const list = (catalogData?.catalog_debug_json?.objects || []).find(
                            obj => obj.type === "MODIFIER_LIST" && obj.id === listId
                        );
                        if (list?.modifier_list_data?.modifiers) {
                            list.modifier_list_data.modifiers.forEach(m => {
                                const mName = safeLower(m?.name || "").trim();
                                if (mName) suggestions.add(mName);
                            });
                        }
                    }

                    // ✂️ Limit to three examples for brevity
                    const exampleMods = Array.from(suggestions).slice(0, 3);
                    let optionsText = "";
                    if (exampleMods.length === 1) optionsText = ` but we do have ${exampleMods[0]}.`;
                    else if (exampleMods.length === 2) optionsText = ` but we do have ${exampleMods[0]} and ${exampleMods[1]}.`;
                    else if (exampleMods.length >= 3)
                        optionsText = ` but we do have ${exampleMods.slice(0, -1).join(", ")} and ${exampleMods.slice(-1)}.`;

                    retrySentences.push(`We don’t have ${badMods} for ${itemName}${optionsText}`);
                }

                retry_prompt = retrySentences.join(" ");
                console.log("🗣️ retryPrompt (dynamic fallback):", retry_prompt);

                return res.status(200).json({
                    success: false,
                    message: "Invalid modifiers detected — clarification needed",
                    validation_passed: false,
                    needs_clarification: true,
                    retry_prompt
                });
            }

            // 🪓 Default fallback for true invalid items or missing modifiers
            console.log("🟣 Using default clarification fallback (no valid items remain).");

            // ✅ Only set fallback if no retry_prompt already exists
            if (!retry_prompt || retry_prompt.trim() === "") {
                retry_prompt = "Sorry, I can’t add that option. Could you repeat or clarify?";
            }

            if (clarification_needed_items?.length > 0 && (!retry_prompt || retry_prompt.trim() === "")) {
                retry_prompt = clarification_needed_items
                    .map(ci => {
                        const opts = ci.options || [];
                        if (opts.length > 0) {
                            return `For your ${ci.name}, would you like ${opts.join(" or ")}?`;
                        }
                        const missing = ci.missing?.[0];
                        const listName = missing?.modifier_list_name || "this option";
                        return `For your ${ci.name}, which ${listName} would you like?`;
                    })
                    .join(" ");
            }

            return res.status(200).json({
                success: false,
                message: "Invalid or unsupported items/modifiers detected",
                invalid_items_count: globalInvalidItems.length || 0,
                invalid_modifiers_count: globalInvalidModifiers.length || 0,
                valid_items_count: 0,
                validation_passed: false,
                needs_clarification: true,
                retry_prompt,
                missing_required_modifiers: validItems?.flatMap(i => i.missing_required_modifiers || []) || []
            });
        }

        // 🩹 Guard — prevent false “no valid items” drop
        if ((!validItems || validItems.length === 0) && Array.isArray(enrichedItems) && enrichedItems.length > 0) {
            console.warn("🩹 Restoring validItems from enrichedItems (prevent false empty filter).");
            validItems = enrichedItems.filter(i => i && i.name);
        }

        // 🧮 Restore correct quantities if items were split earlier
        if (Array.isArray(enrichedItems) && enrichedItems.length > 0) {
            enrichedItems.forEach(ei => {
                const match = parsedItemsOrdered.find(pi =>
                    safeLower(pi.name) === safeLower(ei.name) &&
                    (pi.size ? safeLower(pi.size) === safeLower(ei.size) : true)
                );
                if (match && typeof match.quantity === "number" && match.quantity > 1) {
                    ei.quantity = match.quantity;
                }
            });
        }

        // ===== Step 7.5: Build validLineItems =====
        let validLineItems = (validItems || [])
            .filter(v => v && v.variation_id && v.base_price_money?.amount)
            .map(v => ({
                quantity: String(v.quantity ?? 1),
                catalog_object_id: v.variation_id,   // ✅ Square variation ID
                base_price_money: v.base_price_money, // ✅ Variation price
                modifiers: Array.isArray(v.enrichedModifiers)
                    ? v.enrichedModifiers
                        .filter(m => m && m.catalog_object_id) // 🟢 keep even if $0
                        .map(m => ({
                            catalog_object_id: m.catalog_object_id,
                            base_price_money: m.base_price_money
                        }))
                    : [],
                name: v.catalog_item_name || v.name
            }));

        if (!validLineItems.length) {
            throw new Error("🚨 No valid line items to send to Square");
        }

        console.log(`✅ Step 7.5: Built ${validLineItems.length} validLineItems`);

        // 🧹 Remove raw modifiers that weren’t enriched (prevents “oat milk” leakage in summary)
        for (const item of validItems) {
            if (Array.isArray(item.modifiers) && item.modifiers.length > 0) {
                const validNames = (item.enrichedModifiers || []).map(em => safeLower(em.name));
                const before = item.modifiers.length;
                item.modifiers = item.modifiers.filter(m => validNames.includes(safeLower(m)));
                const after = item.modifiers.length;
                if (after < before) {
                    console.log(`🧹 Dropped ${before - after} invalid raw modifiers for "${item.name}"`);
                }
            }
        }

        validItems.forEach((item, idx) => {
            console.log(`🧾 ValidItem[${idx}] → ${item.quantity}x ${item.name} (${item.size || "default"})`);
            if (item.enrichedModifiers && item.enrichedModifiers.length > 0) {
                console.log("   ↳ Enriched Modifiers:", item.enrichedModifiers.map(m => m.name).join(", "));
            } else if (item.modifiers && item.modifiers.length > 0) {
                console.log("   ↳ Raw Modifiers:", item.modifiers.join(", "));
            } else {
                console.log("   ↳ No modifiers");
            }

            if (item.customizations && item.customizations.length > 0) {
                console.log("   ↳ Customizations:", item.customizations.join(", "));
            }
        });

        // ✅ Calculate total price (items + modifiers)
        const totalPriceCents = validItems.reduce((sum, item) => {
            const itemPrice = item?.base_price_money?.amount ?? 0;
            const modifiersTotal = (item?.enrichedModifiers || []).reduce(
                (modSum, mod) => modSum + (mod?.base_price_money?.amount ?? 0),
                0
            );
            return sum + (itemPrice + modifiersTotal) * (item.quantity ?? 1);
        }, 0);

        // Diagnostics for Step 8+
        console.log("🧾 OrderSummary", {
            items: validItems.map(i => ({
                name: i.name,
                size: i.size,
                qty: i.quantity,
                mods: i.modifiers?.map(m => m.name) || []
            })),
            lineItemsCount: validLineItems.length,
            totalCents: totalPriceCents
        });
        // ===== End of Step 7.5 =====

        // ===== Fetch client location_id from Firestore =====
        const clientDoc = await admin.firestore()
            .collection("clients")
            .doc(client_id)
            .get();

        const clientLocationId = clientDoc.exists ? clientDoc.data().location_id : null;

        if (!clientLocationId) {
            throw new Error(`Missing location_id for client ${client_id}`);
        }

        // ===== End of Step 7 =====

        // ===== Step 8: Build Square order payload =====
        // 🧾 Step 8 pre-metadata: ensure customer fields exist
        const customer_name = body.customer_name || body.customerName || "";
        const customer_phone = body.customer_phone || body.customerPhone || "";
        // 🗒️ Safely resolve optional customer note for order metadata
        const customerNote = body.customer_note || body.customerNote || "";
        let squareOrder = {
            idempotency_key: call_id,   // ✅ ensures duplicate calls don’t double-create
            order: {
                location_id: clientLocationId,
                line_items: validLineItems
                    .map((li, idx) => {
                        if (!li) {
                            console.error("🚨 Null/undefined li at index:", idx, "validLineItems:", validLineItems);
                            return null; // drop instead of crashing
                        }
                        return {
                            quantity: li.quantity || "1",
                            catalog_object_id: li.catalog_object_id || "MISSING",
                            modifiers: Array.isArray(li.modifiers) ? li.modifiers : []
                        };
                    })
                    .filter(li => li && li.catalog_object_id && li.catalog_object_id !== "MISSING"),
                customer_note: customerNote,
                metadata: {
                    customer_name: customer_name || "N/A",
                    customer_phone: customer_phone || "N/A",
                },
            }
        };

        // 🧾 Debug check to confirm name & phone presence
        console.log("📞 Step 8: Customer Info →", { customer_name, customer_phone });

        // 🪪 Log the idempotency key for traceability
        console.log(`🪪 Step 8: Using idempotency_key=${call_id}`);

        if (!squareOrder.order.line_items.length) {
            throw new Error("No valid line items to send to Square");
        }

        console.log(`✅ Step 8: Built Square order with ${squareOrder.order.line_items.length} line_items`);
        console.log(`🧾 Total price: $${(totalPriceCents / 100).toFixed(2)}`);

        // 🧠 Step 8.1 — Merge late-detected notes or customizations (scope-safe)
        try {
            const noteCandidate =
                body.customer_note ||
                body.customerNote ||
                (typeof orderData !== "undefined" && orderData.note
                    ? orderData.note
                    : null);

            if (noteCandidate) {
                const detectedNotes = noteCandidate
                    .split(" | ")
                    .map(n => n.trim())
                    .filter(Boolean);

                // 🧹 Step 8.1a — Deduplicate kitchen notes before merging (case-insensitive)
                if (detectedNotes.length > 0) {
                    const normalized = detectedNotes.map(n => n.toLowerCase());
                    const uniqueSet = new Set(normalized);
                    if (uniqueSet.size !== detectedNotes.length) {
                        console.log(`🧹 Deduped kitchen notes →`, [...uniqueSet]);
                    }

                    // Preserve original casing of first occurrence
                    const dedupedNotes = detectedNotes.filter(
                        (note, idx) => normalized.indexOf(note.toLowerCase()) === idx
                    );

                    console.log("🪶 Merging detected notes into Square order:", dedupedNotes);

                    const existingNote = squareOrder.order.customer_note || "";
                    const mergedNote = existingNote
                        ? `${existingNote} | ${dedupedNotes.join(" | ")}`
                        : dedupedNotes.join(" | ");
                    squareOrder.order.customer_note = mergedNote;

                    // 🧼 Step 8.1b — Final cleanup for customer_note formatting
                    if (squareOrder.order.customer_note) {
                        let cleanedNote = squareOrder.order.customer_note
                            .replace(/\s*\|\s*$/, "")        // remove trailing "|"
                            .replace(/\s{2,}/g, " ")         // collapse multiple spaces
                            .replace(/\s*\|\s*/g, " | ");    // normalize pipe spacing

                        if (cleanedNote !== squareOrder.order.customer_note) {
                            console.log(`🧼 Cleaned customer_note → "${cleanedNote}"`);
                            squareOrder.order.customer_note = cleanedNote.trim();
                        }
                    }
                }
            }
        } catch (err) {
            console.error("⚠️ Step 8.1 note merge error:", err.message);
        }
        // ===== End of Step 8 =====


        // ===== Step 9: Finalize response =====

        // Items that failed for reasons other than being intentionally dropped
        const invalidItems = (enrichedItems || []).filter(i => i && i.valid !== true && !i.drop_reason);

        // ✅ Use global invalid lists for final counts and arrays
        invalidModifiers = globalInvalidModifiers || invalidModifiers;

        // 🧹 Final safeguard — clear any leftover invalid arrays if valid items exist
        if (validItems && validItems.length > 0) {
            console.log("🧹 Final cleanup — validItems exist, clearing invalid arrays");
            globalInvalidItems = [];
            globalInvalidModifiers = [];
            invalidModifiers = [];
        }

        // Count values for Blend
        const invalid_items_count = globalInvalidItems.length;
        const invalid_modifiers_count = globalInvalidModifiers.length;

        // Final flags/counts for Blend
        const validation_passed = (validItems.length > 0) && (invalid_modifiers_count === 0);
        const valid_items_count = validItems.length;

        // 🧠 New edge-case: handle invalid modifiers when item is still valid
        if (validItems.length > 0 && globalInvalidModifiers.length > 0) {
            console.log("🧠 Edge case: valid item(s) but invalid modifier(s) detected, building clarification prompt");

            const badMods = globalInvalidModifiers.map(m =>
                m.attempted_modifier || m.name || m
            ).join(", ");

            const badItems = validItems.map(i => i.name).join(", ");

            retry_prompt = `Sorry, ${badMods} isn’t available for ${badItems}. Would you like something else instead?`;

            // Set flags so Blend routes correctly
            validation_passed = false;
            needs_clarification = true;

            console.log("🗣️ Generated invalid modifier clarification:", retry_prompt);
        }

        // Decide next action for Blend
        let route_hint = "FIX_INVALIDS"; // default
        if (validation_passed) {
            route_hint = "CONFIRM";
        } else if (validItems.length === 0 && (droppedItems || []).length > 0) {
            route_hint = "ASK_REPLACEMENT";
        } else if (validItems.length > 0 && invalidModifiers.length === 0) {
            route_hint = "CONFIRM";
        }

        // 🆕 Track invalid attempts in Firestore
        let invalid_attempts_count = 0;
        try {
            if (!validation_passed) {
                const orderRef = admin.firestore().collection("orders").doc(call_id);
                await admin.firestore().runTransaction(async (t) => {
                    const docSnap = await t.get(orderRef);
                    const currentCount = docSnap.exists && docSnap.data().invalid_attempts_count
                        ? docSnap.data().invalid_attempts_count
                        : 0;
                    invalid_attempts_count = currentCount + 1;
                    t.set(orderRef, { invalid_attempts_count }, { merge: true });
                });
            } else {
                await admin.firestore().collection("orders").doc(call_id)
                    .set({ invalid_attempts_count: 0 }, { merge: true });
            }
        } catch (err) {
            console.error("⚠️ Failed to update invalid_attempts_count:", err.message);
        }

        // 🧹 Final safeguard — clear any leftover invalid arrays if valid items exist
        if (validItems && validItems.length > 0) {
            console.log("🧹 Final cleanup — validItems exist, preserving modifier invalids for clarification");
            globalInvalidItems = [];
            // Keep globalInvalidModifiers intact for Step 9 clarification
        }

        // 📊 Compact outcome logs
        console.log(`📊 Step 9 outcome — valid=${valid_items_count}, invalidItems=${invalid_items_count}, invalidModifiers=${invalid_modifiers_count}, validation_passed=${validation_passed}, attempts=${invalid_attempts_count}`);

        // Retry prompt logic
        if (!retry_prompt || retry_prompt.trim() === "") {
            retry_prompt = "Great, logging that in…";   // default when validation passes
        }

        if (!validation_passed) {
            if (invalid_attempts_count >= 3 && (!retry_prompt || retry_prompt.trim() === "")) {
                retry_prompt = "I’m still having trouble understanding. Let me transfer you to a representative.";
            }
            else if (clarification_needed_items.length > 0 && (!retry_prompt || retry_prompt.trim() === "")) {
                retry_prompt = clarification_needed_items
                    .map(ci => {
                        const opts = ci.options || [];
                        if (opts.length > 0) {
                            return `Sorry, we don’t have ${badMods} for ${itemName}. Would you like something else for that?`;
                        }
                        const missing = ci.missing?.[0];
                        const listName = missing?.modifier_list_name || "this option";
                        return `For your ${ci.name}, which ${listName} would you like?`;
                    })
                    .join(" ");
            }
            else if (invalid_modifiers_count > 0 && (!retry_prompt || retry_prompt.trim() === "")) {
                const badMods = globalInvalidModifiers.map(m => `"${m.attempted_modifier}"`).join(", ");
                retry_prompt = `Sorry, I didn’t quite get that — ${badMods} isn’t available for this item. Could you pick another option?`;
            }
            else if (globalInvalidItems.length > 0 && (!retry_prompt || retry_prompt.trim() === "")) {
                const clarificationItems = globalInvalidItems.filter(i => i.needs_clarification);
                const itemPrompts = [];

                clarificationItems.forEach(invalid => {
                    const opts = invalid.options || [];
                    if (opts.length > 0) {
                        itemPrompts.push(`For your ${invalid.name}, would you like ${opts.join(" or ")}?`);
                    } else {
                        itemPrompts.push(`For your ${invalid.name}, could you clarify the option?`);
                    }
                });

                console.log("🧾 Step 9 clarification prompts built:", itemPrompts);

                if (itemPrompts.length > 0) {
                    retry_prompt = itemPrompts.join(" ");
                } else {
                    retry_prompt = "Sorry, I didn’t quite get that. Could you repeat the item or option?";
                }
            }
        }

        // 📝 Step 9 clarification snapshot (reuse Step 5.5 array)
        if (clarification_needed_items.length > 0) {
            console.log("📝 Step 9 clarification_needed_items:", clarification_needed_items);
        }

        // 🆕 Unified flag for Blend routing
        // True if there are any invalid items OR invalid modifiers OR explicit clarifications
        const needs_clarification =
            (globalInvalidItems.length > 0) ||
            (globalInvalidModifiers.length > 0) ||
            (clarification_needed_items.length > 0);

        // 🛡️ Prevent stale retry prompts when validation actually passed
        if (validation_passed) {
            retry_prompt = null; // suppress duplicate clarification
        }

        // 🧾 Build customer-facing order summary for logging + response
        const line_items_display = (validItems || []).map(item => {
            const mods = item.enrichedModifiers?.map(m => m.name).join(", ") || "";
            const cust = item.customizations?.join(", ") || "";
            const sizeLabel =
                item.size && item.size.trim() && item.size.toLowerCase() !== "default"
                    ? item.size.trim()
                    : "";
            let desc = `${sizeLabel ? sizeLabel + " " : ""}${item.name}`;
            if (mods) desc += ` with ${mods}`;
            if (cust) desc += ` (${cust})`;   // shows removals as parentheses
            return desc;
        });

        console.log("🧾 Line Items Display (customer-facing):", line_items_display);

        // Clarification prompt trigger for invalid modifiers
        if (globalInvalidModifiers.length > 0) {
            console.log(`🧠 Step 9 clarification — Detected invalid modifiers:`, globalInvalidModifiers);

            // Build a user-friendly summary for the voice agent
            const clarificationPrompts = globalInvalidModifiers.map(entry =>
                `${entry.attempted_modifier} isn’t available for ${entry.item_name}.`
            );
            const clarification_message = clarificationPrompts.join(" ");

            // Return clarification route instead of default fallback
            return res.status(200).json({
                validation_passed: false,
                invalid_modifiers: globalInvalidModifiers,
                clarification_message,
                retry_prompt: `${clarification_message} Would you like to choose something else or continue with your current order?`,
                route: "clarify_modifier"
            });
        }

        // 🗣️ Build canonical spoken summary string for Blend to read aloud
        let line_items_text = (validItems || []).map(item => {
            const qtyText = item.quantity > 1 ? `${item.quantity}x ` : "";
            const sizeLabel =
                item.size && item.size.trim() && item.size.toLowerCase() !== "default"
                    ? `${item.size.trim()} `
                    : "";
            const mods = item.enrichedModifiers?.length
                ? ` with ${item.enrichedModifiers.map(m => m.name).join(", ")}`
                : "";
            const cust = item.customizations?.length
                ? ` (${item.customizations.join(", ")})`
                : "";
            return `${qtyText}${sizeLabel}${item.name}${mods}${cust}`;
        }).join(", ") || "no valid items";

        // 🪶 Optional: include kitchen note summary for voice confirmation
        let kitchen_notes_summary = null;
        if (body.customer_note) {
            kitchen_notes_summary = body.customer_note
                .replace(/\s*\|\s*/g, ', ')
                .replace(/:\s*/g, ' — ');
            console.log("🗣️ Appending kitchen note to spoken summary:", kitchen_notes_summary);

            // 🔗 Merge note directly into spoken line_items_text
            line_items_text = `${line_items_text} — ${kitchen_notes_summary}`;
        }

        // Canonical spoken confirmation for valid orders
        let confirmation_prompt;

        if (validation_passed) {
            if (kitchen_notes_summary) {
                confirmation_prompt = `Got it — ${kitchen_notes_summary}. Alright, here’s what I’ve got: ${line_items_text}. Does everything look good?`;
            } else {
                confirmation_prompt = `Alright, here’s what I’ve got: ${line_items_text}. Does everything look good?`;
            }
        } else {
            confirmation_prompt = retry_prompt;
        }

        // 🧩 Step 9.9 — Persist validated order state for continuity (non-breaking add-on)
        try {
            if (validation_passed && call_id && Array.isArray(validItems) && validItems.length > 0) {
                const orderRef = admin.firestore().collection("orders").doc(call_id);

                const orderPayload = {
                    items_ordered: validItems.map(i => ({
                        name: i.name,
                        size: i.size,
                        quantity: i.quantity,
                        modifiers: i.modifiers || i.enrichedModifiers?.map(m => m.name) || [],
                        customizations: i.customizations || [],
                        base_price_money: i.base_price_money || null,
                        variation_id: i.variation_id || null,
                        catalog_item_id: i.catalog_item_id || null
                    })),
                    customer_note: body.customer_note || null,
                    updated_at: new Date().toISOString()
                };

                await orderRef.set(orderPayload, { merge: true });
                console.log(`💾 [Step9.9] Persisted ${orderPayload.items_ordered.length} item(s) for call_id=${call_id}`);
            } else {
                console.log("ℹ️ [Step9.9] Skipped save — validation not passed or no valid items.");
            }
        } catch (persistErr) {
            console.error("⚠️ [Step9.9] Failed to persist order continuity:", persistErr.message);
        }

        // 🚀 Final response
        return res.status(200).json({
            success: valid_items_count > 0,
            message: valid_items_count > 0
                ? "Order payload built"
                : "Invalid or unsupported items/modifiers detected",

            square_order: squareOrder,
            total_price: (totalPriceCents / 100).toFixed(2),

            // Counts for Blend
            invalid_items_count: globalInvalidItems.length || 0,
            invalid_modifiers_count: globalInvalidModifiers.length || 0,
            valid_items_count,
            invalid_attempts_count,

            // Routing flags
            validation_passed,
            needs_clarification,
            escalate_to_human: invalid_attempts_count >= 3,

            // Retry prompt for Blend to speak
            retry_prompt,

            // 🆕 Extra structured detail
            clarification_needed_items,

            // 🆕 Missing required modifiers
            missing_required_modifiers: validItems?.flatMap(i => i.missing_required_modifiers || []) || [],

            // 🆕 Customer-facing order summary
            line_items_display,

            // 🆕 Kitchen note summary for voice confirmation
            kitchen_notes_summary,

            // 🗣️ Canonical spoken version for Blend voice confirmation
            line_items_text,
            confirmation_prompt,
        });


    } catch (error) {
        console.error("🔥 createSquareOrder Error:", error.message);
        return res.status(500).json({ success: false, message: error.message });
    }
});

const getAccessTokenForClient = async (client_id) => {
    // 🧠 Environment-aware access token retriever using getClientEnvironment()
    const now = Date.now();

    // 1️⃣ Load environment for this client
    const { square_environment } = await getClientEnvironment(client_id);
    const environment = square_environment || "sandbox";
    console.log(`🌎 [getAccessTokenForClient] Environment for ${client_id}: ${environment}`);

    const isValid = (data) => {
        if (!data?.access_token || !data?.expires_at) return false;
        const exp = new Date(data.expires_at).getTime();
        if (isNaN(exp)) return false;
        const hoursLeft = (exp - now) / (1000 * 60 * 60);
        return hoursLeft > 24;
    };

    // ✅ Pull correct token doc based on detected environment
    const tokenDocId = environment === "production" ? client_id : `${client_id}_sandbox`;
    console.log(`🔍 [getAccessTokenForClient] Fetching token from: tokens/${tokenDocId}`);

    try {
        let doc = await admin.firestore().collection("tokens").doc(tokenDocId).get();
        if (doc.exists) {
            const data = doc.data();
            if (isValid(data)) {
                console.log(`🔑 Using valid ${environment} access_token for client_id: ${client_id}`);
                return data.access_token;
            } else if (data.refresh_token) {
                console.warn(`⚠️ ${environment} token expiring soon for ${client_id}, refreshing…`);
                return await refreshSquareToken(client_id, data.refresh_token);
            } else {
                console.warn(`⚠️ ${environment} token doc missing refresh_token for ${client_id}`);
            }
        }

        console.error(`❌ [getAccessTokenForClient] No valid token found for ${client_id} (${environment})`);
        return null;
    } catch (err) {
        console.error(`🚨 [getAccessTokenForClient] Error retrieving token for ${client_id}:`, err.message);
        return null;
    }
};

exports.storeOrUpdateOrderItems = functions.https.onRequest(async (req, res) => {
    const { call_id, client_id, items_ordered } = req.body;

    if (!call_id || !client_id || !Array.isArray(items_ordered)) {
        return res.status(400).json({ success: false, message: 'Missing required fields' });
    }

    try {
        await admin.firestore()
            .collection("orders")
            .doc(call_id)
            .set({ client_id, items_ordered }, { merge: true });

        console.log(`✅ Stored items_ordered for call_id: ${call_id}`, items_ordered);
        return res.status(200).json({ success: true });
    } catch (error) {
        console.error(`❌ Failed to store order for call_id: ${call_id}`, error);
        return res.status(500).json({ success: false });
    }
});

// --- clearItemsOrdered (optimized for Blend AI + call_id memory) ---
exports.clearItemsOrdered = functions.https.onRequest(async (req, res) => {
    const clientId = req.body.client_id;
    const callId = req.body.call_id;

    if (!clientId || !callId) {
        console.error("❌ Missing client_id or call_id");
        return res.status(400).json({
            success: false,
            message: "Missing client_id or call_id",
            overwrite_variables: {
                items_ordered: [],
                line_items_display: '',
                total_price: '$0.00'
            }
        });
    }

    try {
        const db = admin.firestore();
        await db.collection("orders").doc(callId).delete();
        console.log(`🧹 Cleared order memory for call_id: ${callId}`);

        // 🧩 Added for Blend routing visibility
        console.log("✅ clearItemsOrdered response payload:", {
            success: true,
            message: "Order cleared successfully",
            overwrite_variables: {
                items_ordered: [],
                line_items_display: '',
                total_price: '$0.00'
            }
        });

        return res.status(200).json({
            success: true,
            message: "Order cleared successfully",
            overwrite_variables: {
                items_ordered: [],
                line_items_display: '',
                total_price: '$0.00'
            }
        });
    } catch (err) {
        console.error("❌ Failed to clear order:", err);
        return res.status(500).json({
            success: false,
            message: "Failed to clear order",
            overwrite_variables: {
                items_ordered: [],
                line_items_display: '',
                total_price: '$0.00'
            }
        });
    }
});

exports.ingestCatalog = functions.https.onRequest(async (req, res) => {
    try {
        const client_id = req.body.client_id;
        if (!client_id) {
            throw new Error("Missing client_id in request body");
        }

        // 🧩 Step 0 — Retrieve latest access token directly from /tokens
        let access_token = null;
        try {
            const tokenDoc = await admin.firestore().collection("tokens").doc(client_id).get();
            if (tokenDoc.exists) {
                access_token = tokenDoc.data().access_token;
                console.log(`🔑 [ingestCatalog] Using access_token from /tokens for client_id: ${client_id}`);
            } else {
                console.warn(`⚠️ [ingestCatalog] No token found under /tokens for ${client_id}, checking legacy /square_tokens...`);
                const legacyDoc = await admin.firestore().collection("square_tokens").doc(client_id).get();
                if (legacyDoc.exists) {
                    access_token = legacyDoc.data().access_token;
                    console.log(`🟡 [ingestCatalog] Using fallback token from /square_tokens for client_id: ${client_id}`);
                }
            }
        } catch (tokenErr) {
            console.error("🚨 [ingestCatalog] Failed to read token:", tokenErr.message);
        }

        if (!access_token) {
            throw new Error(`Missing access_token for client_id: ${client_id}`);
        }

        // 🧩 Step 0.5 — Ensure merchant → client mapping exists
        try {
            // 🧠 Retrieve merchant_id tied to this client
            const tokensSnap = await admin.firestore().collection("tokens").get();
            let merchantId = null;
            tokensSnap.forEach(doc => {
                const data = doc.data();
                if (data.merchant_id === client_id || doc.id === client_id) {
                    merchantId = data.merchant_id || doc.id;
                }
            });

            // ✅ If found, create or update mapping doc
            if (merchantId) {
                await admin.firestore().collection("mappings").doc(merchantId).set({
                    clientId: client_id
                });
                console.log(`✅ [ingestCatalog] Mapping ensured for merchant_id="${merchantId}" → client_id="${client_id}"`);
            } else {
                console.warn(`⚠️ [ingestCatalog] No merchant_id found for client_id="${client_id}" — skipping mapping creation`);
            }
        } catch (mapErr) {
            console.error("🚨 [ingestCatalog] Error creating mapping:", mapErr.message);
        }


        // 🧩 Determine Square environment for this client
        const envCfg = await getClientEnvironment(client_id, admin);

        // 🧩 Always override envCfg.square_environment if Firestore specifies one
        const clientDoc = await admin.firestore().collection("clients").doc(client_id).get();
        if (clientDoc.exists) {
            const data = clientDoc.data();
            if (data.square_environment && data.square_environment !== envCfg.square_environment) {
                console.log(`🛠️ [ingestCatalog] Overriding envCfg.square_environment → ${data.square_environment} (from Firestore)`);
                envCfg.square_environment = data.square_environment;
            } else {
                console.log(`ℹ️ [ingestCatalog] Using existing envCfg.square_environment → ${envCfg.square_environment}`);
            }
        }

        const baseUrl = envCfg.square_environment === "production"
            ? "https://connect.squareup.com"
            : "https://connect.squareupsandbox.com";

        console.log(`🧩 [ingestCatalog] Square Env → ${envCfg.square_environment.toUpperCase()} | baseUrl=${baseUrl}`);

        // 🧩 Optional: derive client credentials (for clarity/logging consistency)
        const client_id_for_square = envCfg.square_environment === "production"
            ? functions.config().square.prod_client_id
            : functions.config().square.sandbox_client_id;

        const client_secret_for_square = envCfg.square_environment === "production"
            ? functions.config().square.prod_client_secret
            : functions.config().square.sandbox_client_secret;

        console.log(`🔑 Using ${envCfg.square_environment} creds → ${client_id_for_square}`);

        if (!access_token) {
            throw new Error(`Access token not found for client_id: ${client_id}`);
        }

        // 🔁 Load all modifiers from Firestore
        const modifiersSnapshot = await admin
            .firestore()
            .collection("clients")
            .doc(client_id)
            .collection("modifiers")
            .get();

        const allModifiers = {};
        modifiersSnapshot.forEach(doc => {
            const data = doc.data();
            const nameKey = data.name.toLowerCase().trim();
            allModifiers[nameKey] = {
                catalog_object_id: data.id,
                name: data.name,
                base_price_money: data.price_money
            };
        });
        console.log(`📦 Loaded ${Object.keys(allModifiers).length} modifiers for client ${client_id}`);

        const catalogRes = await axios.post(
            `${baseUrl}/v2/catalog/search`,
            {
                object_types: ["ITEM", "ITEM_VARIATION", "MODIFIER", "MODIFIER_LIST", "CATEGORY"]
            },
            {
                headers: {
                    Authorization: `Bearer ${access_token}`,
                    "Square-Version": "2023-12-13",
                    "Content-Type": "application/json"
                }
            }
        );

        const catalogData = catalogRes.data;

        // 🔁 Step 1: Split out ITEMs and VARIATIONs
        const allObjects = catalogData.objects || [];
        const itemObjects = allObjects.filter(obj => obj.type === "ITEM");
        const variationObjects = allObjects.filter(obj => obj.type === "ITEM_VARIATION");

        // 🧪 Step 2: Build variation lookup by item_id
        const variationsByItemId = {};
        variationObjects.forEach(variation => {
            const itemId = variation.item_variation_data?.item_id;
            if (!itemId) return;
            if (!variationsByItemId[itemId]) {
                variationsByItemId[itemId] = [];
            }
            variationsByItemId[itemId].push(variation);
        });

        // 🧩 Step 3: Attach full variation objects to their parent ITEMs
        let enrichedItems = itemObjects.map(item => {
            const itemId = item.id;
            const variations = variationsByItemId[itemId] || [];
            return {
                ...item,
                item_data: {
                    ...item.item_data,
                    variations: variations // ✅ inject full variation objects
                }
            };
        });

        // 🧩 Step 4 — Save catalog under per-client path
        const clientCatalogRef = admin.firestore()
            .collection("clients")
            .doc(client_id)
            .collection("catalog");

        await clientCatalogRef
            .doc("catalog_debug_json")
            .set({ catalog_debug_json: catalogData }, { merge: true });

        await clientCatalogRef
            .doc("catalog_items")
            .set({ catalog_items: enrichedItems }, { merge: true });


        console.log(`📦 Stored ${enrichedItems.length} catalog_items for client_id: ${client_id}`);

        // 🧠 Extract and store modifiers in /clients/{client_id}/modifiers/{modifier_id}
        const modifiers = catalogData.objects?.filter(obj => obj.type === "MODIFIER") || [];

        const batch = admin.firestore().batch();
        const modifiersRef = admin.firestore().collection("clients").doc(client_id).collection("modifiers");

        modifiers.forEach(mod => {
            const modId = mod.id;
            const data = {
                name: mod?.modifier_data?.name || "unknown",
                price: mod?.modifier_data?.price_money?.amount || 0,
                modifier_list_id: mod?.modifier_data?.modifier_list_id || null
            };
            batch.set(modifiersRef.doc(modId), data);
        });

        await batch.commit();

        // 🆕 Step 4: Store MODIFIER_LIST objects with their child modifiers
        const modifierLists = catalogData.objects?.filter(obj => obj.type === "MODIFIER_LIST") || [];

        const listBatch = admin.firestore().batch();
        const listRef = admin.firestore().collection("clients").doc(client_id).collection("modifiers");

        modifierLists.forEach(list => {
            const listId = list.id;
            const listName = list.modifier_list_data?.name || "Unnamed List";
            // ✅ Filter out undefined modifier names before writing to Firestore
            const listModifiers = (list.modifier_list_data?.modifiers || [])
                .filter(m => m?.name)
                .map(m => ({
                    id: m.id,
                    name: m.name.trim()
                }));

            const payload = {
                name: listName,
                modifiers: listModifiers,
                min_selected_modifiers: list.modifier_list_data?.min_selected_modifiers ?? 0,
                max_selected_modifiers: list.modifier_list_data?.max_selected_modifiers ?? 0,
                enabled: list.modifier_list_data?.enabled ?? true
            };

            listBatch.set(listRef.doc(listId), payload, { merge: true });
            console.log(`📘 Stored modifier list "${listName}" with ${listModifiers.length} choices`);
        });

        await listBatch.commit();
        console.log(`✅ Stored ${modifierLists.length} modifier lists for client ${client_id}`);

        const itemCount = (catalogData.objects || []).filter(obj => obj.type === "ITEM").length;

        console.log(`✅ Found ${itemCount} ITEMs in catalog`);

        res.status(200).json({
            success: true,
            item_count: itemCount,
            modifier_count: modifiers.length
        });

    } catch (err) {
        console.error("❌ Error ingesting catalog:", err.response?.data || err.message);
        res.status(500).json({
            success: false,
            error: err.response?.data || err.message
        });
    }
});

exports.checkClientConfig = functions.https.onRequest(async (req, res) => {
    try {
        const client_id = req.body?.client_id || req.query?.client_id;
        if (!client_id) {
            return res.status(400).json({ success: false, message: "Missing client_id" });
        }

        console.log(`🧩 [checkClientConfig] Checking configuration for client ${client_id}`);

        // 1️⃣  Load environment doc
        const envRef = admin.firestore()
            .collection("clients")
            .doc(client_id)
            .collection("config")
            .doc("env");
        const envSnap = await envRef.get();
        const envData = envSnap.exists ? envSnap.data() : null;

        // 2️⃣  Load catalog docs
        const itemsRef = admin.firestore()
            .collection("clients")
            .doc(client_id)
            .collection("catalog")
            .doc("catalog_items");
        const itemsSnap = await itemsRef.get();
        const items = itemsSnap.exists ? itemsSnap.data()?.catalog_items || [] : [];

        const debugRef = admin.firestore()
            .collection("clients")
            .doc(client_id)
            .collection("catalog")
            .doc("catalog_debug_json");
        const debugSnap = await debugRef.get();
        const debugObjects = debugSnap.exists
            ? debugSnap.data()?.catalog_debug_json?.objects || []
            : [];

        const itemCount = items.length;
        const debugCount = debugObjects.length;

        const envStatus = envData
            ? `✅ ${envData.square_environment.toUpperCase()}`
            : "⚠️ MISSING";

        const health =
            itemCount > 0 && debugCount > 0 && envData
                ? "✅ HEALTHY"
                : "⚠️ INCOMPLETE";

        console.log(
            `📊 Client ${client_id} — Env: ${envStatus}, Items: ${itemCount}, Objects: ${debugCount}, Health: ${health}`
        );

        return res.status(200).json({
            success: true,
            client_id,
            env: envData || null,
            item_count: itemCount,
            debug_object_count: debugCount,
            health,
        });
    } catch (err) {
        console.error("❌ Error checking client config:", err);
        return res.status(500).json({ success: false, error: err.message });
    }
});


// --- createSquareOrderDebug ---
exports.createSquareOrderDebug = functions.https.onRequest(async (req, res) => {
    console.log("🟡 [DEBUG] Received raw order payload from Blend:");
    console.log(JSON.stringify(req.body, null, 2));

    const raw_items_ordered = req.body?.items_ordered;
    let catalog = [];
    const clientId = req.body?.client_id || "unknown";
    try {
        const docRef = await admin.firestore()
            .collection("catalogs")
            .doc(clientId)
            .get();

        const data = docRef.data();

        if (data && data.catalog_debug_json && Array.isArray(data.catalog_debug_json.objects)) {
            catalog = data.catalog_debug_json.objects;
            console.log(`📦 Loaded ${catalog.length} catalog items for client ${clientId}`);
        } else {
            console.warn(`⚠️ No catalog objects found for client ${clientId}`);
        }
    } catch (err) {
        console.error("❌ Failed to load catalog from Firestore:", err.message);
    }

    let parsedItemsOrdered;

    try {
        parsedItemsOrdered = typeof raw_items_ordered === 'string'
            ? JSON.parse(raw_items_ordered)
            : raw_items_ordered;

        console.log("✅ [DEBUG] Parsed parsedItemsOrdered:", JSON.stringify(parsedItemsOrdered, null, 2));
    } catch (e) {
        console.error("❌ Failed to parse parsedItemsOrdered:", e.message);
        return res.status(400).json({
            success: false,
            message: "Invalid items_ordered format"
        });
    }

    // 📦 Parse items_ordered
    parsedItemsOrdered = Array.isArray(rawBody.items_ordered) ? rawBody.items_ordered : [];

    // 🔁 Apply alias rewrites after initial parsing
    parsedItemsOrdered = applyAliasRewrite(parsedItemsOrdered, fuzzyItemAliases || {});
    console.log("🧠 After alias rewrite:", parsedItemsOrdered);

    res.status(200).json({
        success: false,
        message: "🟡 Debug webhook hit. No order was sent to Square.",
        debug_order_body: {
            items: (parsedItemsOrdered || []).map(i => ({
                name: i.name,
                size: i.size,
                quantity: i.quantity,
                modifiers: i.modifiers
            }))
        },
        catalog_summary: Array.isArray(catalog)
            ? `📦 Catalog contains ${catalog.length} items`
            : "⚠️ Catalog not loaded"
    });
}); // ✅ Close CORS wrapper

// --- detectUserIntent (MUST be outside of any other function) ---
exports.detectUserIntent = functions.https.onRequest(async (req, res) => {
    const user_input = req.body?.user_input?.toLowerCase();

    if (!user_input) {
        return res.status(400).json({ success: false, message: "Missing user_input" });
    }

    let user_intent = "unknown";

    // 🔍 Language Detection → Spanish → Transfer to Human
    const spanishSignals = [
        "hola", "quiero", "por favor", "gracias", "buenas",
        "ordenar", "pedido", "agregar", "tengo", "deseo", "me puedes", "buenos", "buenos dias", "si"
    ];

    function isLikelySpanish(text) {
        if (!text) return false;
        const lower = text.toLowerCase();
        return spanishSignals.some(sig => lower.includes(sig));
    }

    if (isLikelySpanish(user_input)) {
        console.log("🌐 Spanish detected → transfer_to_human");
        return res.status(200).json({
            success: true,
            user_intent: "transfer_to_human",
            original_user_input: user_input,
            reason: "spanish_detected"
        });
    }

    // --- 🥡 Safety override: to-go, takeout, or carryout phrasing always means start_order ---
    if (/\b(to[-\s]?go order|take\s?out|carry\s?out|carryout|pickup order|order for pickup)\b/i.test(user_input)) {
        return res.status(200).json({
            success: true,
            user_intent: "start_order_inquiry",
            original_user_input: user_input
        });
    }

    // --- Triggers (normalized, expanded, non-overlapping) ---
    const confirmTriggers = [
        "yes", "yeah", "yep", "yup", "sure", "sounds good",
        "correct", "that's right", "ok", "okay", "alright", "right",
        "that works", "that’s fine", "you got it", "go ahead", "absolutely",
        "perfect", "done", "fine by me", "can I order"
    ];

    const restartOrderTriggers = [
        // existing restart phrases
        "change my order", "start over", "clear my order",
        "actually", "never mind", "scratch that", "let me start again",
        "forget it", "redo", "restart", "start fresh", "do over",

        // negative responses → restart flow
        "no", "nope", "nah", "not really", "wrong", "that's wrong",
        "incorrect", "not quite", "not right", "doesn't look right",
        "not good", "not correct", "bad"
    ];

    const cancelOrderTriggers = [
        "cancel", "cancel my order", "never mind the order", "forget my order",
        "i dont want it", "i changed my mind", "too expensive",
        "no thanks", "no thank you", "not interested anymore",
        "stop the order", "dont place the order", "forget about it"
    ];

    const modifyItemTriggers = [
        "change the", "replace the", "switch the", "change just the", "replace just the",
        "take off", "remove the", "add instead", "swap out", "switch out",
        "without the", "with no", "substitute"
    ];

    const cateringTriggers = [
        "catering", "big order", "feeds", "party", "platter", "large group",
        "office order", "bulk order", "family size", "group order", "lots of people",
        "team order"
    ];

    // --- Normalizer (applies to both triggers + user input) ---
    function normalizeText(text) {
        return text
            .toLowerCase()
            .replace(/[^\w\s]/g, "") // remove punctuation
            .trim();
    }

    const matchIntent = (triggers) => triggers.some(trigger => user_input.includes(trigger));

    const matchedConfirm = matchIntent(confirmTriggers);
    const matchedRestart = matchIntent(restartOrderTriggers);

    // 📝 Conflict log: both confirm & restart triggers found
    if (matchedConfirm && matchedRestart) {
        console.warn(`⚠️ Conflict: input "${user_input}" matched both confirm & restart triggers. Defaulting to restart.`);
    }

    // 🔑 Prioritize restart > cancel > confirm
    if (matchIntent(restartOrderTriggers)) {
        user_intent = "restart_order";
    } else if (matchIntent(cancelOrderTriggers)) {
        user_intent = "cancel_order";
    } else if (matchIntent(confirmTriggers)) {
        user_intent = "confirm_order";
    } else if (matchIntent(modifyItemTriggers)) {
        user_intent = "modify_item";
    } else if (matchIntent(cateringTriggers)) {
        user_intent = "catering_order";
    }
    // 🥡 --- Detect start-order or open-hours phrasing ---
    else if (/\b(pick\s?up|to\s?go|place an order|order for pickup|carry ?out|for here|are you open|you guys open|still open|open right now)\b/i.test(user_input)) {
        user_intent = "start_order";
        console.log(`✅ [detectUserIntent] Detected start-order or open-hours phrase → ${user_intent}`);
    }

    // ✅ --- Additional start-order detectors for natural phrasing ---
    if (!["start_order", "cancel_order", "restart_order", "modify_item"].includes(user_intent)) {
        const startOrderPatterns = [
            /\b(can i get|i'll take|i would like|give me|i want|let me get|order me)\b/i
        ];

        if (startOrderPatterns.some(p => p.test(user_input))) {
            user_intent = "start_order";
            console.log(`✅ [detectUserIntent] Classified as start_order (opening phrase match)`);
        }
    }


    // --- 🧠 Tier-based FAQ and transfer detection ---
    try {
        const clientId = req.body?.client_id;
        if (clientId) {
            const clientDoc = await db.collection("clients").doc(clientId).get();
            const config = clientDoc.data()?.intents_config;

            if (config) {
                const { ai_faqs, mixed_keywords, transfer_keywords } = config;

                // --- Tier 3: Human handoff triggers ---
                const transferHit = transfer_keywords?.some(keyword =>
                    user_input.includes(keyword.toLowerCase())
                );
                if (transferHit) {
                    user_intent = "transfer_to_human";
                    console.log(`🤝 [detectUserIntent] Transfer trigger detected: "${user_input}"`);
                }

                // --- Tier 2: Mixed (AI + clarification) triggers ---
                else if (mixed_keywords?.some(keyword =>
                    user_input.includes(keyword.toLowerCase())
                )) {
                    user_intent = "mixed_intent";
                    console.log(`🟡 [detectUserIntent] Mixed trigger detected: "${user_input}"`);
                }

                // --- Tier 1: Direct FAQ matches (AI can answer immediately) ---
                else if (ai_faqs) {
                    // 🔤 Load universal or client-specific synonym map
                    const synonymMap = await getSynonymMap(clientId);

                    // Check for direct key match or any synonym hit
                    const matchedFaqKey = Object.keys(ai_faqs).find(key => {
                        const synonyms = synonymMap[key] || [];
                        return [key.toLowerCase(), ...synonyms.map(s => s.toLowerCase())]
                            .some(term => user_input.includes(term));
                    });

                    if (matchedFaqKey) {
                        user_intent = "ai_faq";
                        console.log(`💬 [detectUserIntent] AI FAQ detected via synonym: "${matchedFaqKey}"`);
                    }
                }
            } else {
                console.warn(`⚠️ [detectUserIntent] No intents_config found for ${clientId}`);
            }
        } else {
            console.warn("⚠️ [detectUserIntent] Missing client_id in request body");
        }
    } catch (err) {
        console.error("❌ [detectUserIntent] Error loading intents_config:", err.message);
    }

    // --- 🧩 Context Guardrail (Post-trigger placement): correct false restart on first utterance ---
    try {
        const clientId = req.body?.client_id;
        const callId = req.body?.call_id;

        if (clientId && callId) {
            const orderRef = admin.firestore().collection("orders").doc(callId);
            const orderSnap = await orderRef.get();

            // 🧩 Diagnostic log
            console.log(`🧩 [detectUserIntent] Guardrail check: call_id=${callId} | order_exists=${orderSnap.exists}`);

            // Apply only if this is the very first utterance (no Firestore doc yet)
            if (!orderSnap.exists) {
                const normalizedInput = user_input.toLowerCase();
                const earlyOrderPhrases = [
                    "can i get", "can i do", "i'll take", "i want",
                    "i would like", "let me get", "give me", "i’ll do"
                ];

                if (earlyOrderPhrases.some(p => normalizedInput.includes(p))) {
                    console.log(`🧠 [detectUserIntent] Context guardrail override: forced start_order (first turn, no order doc)`);
                    user_intent = "start_order";
                }
            }
        }
    } catch (err) {
        console.warn("⚠️ [detectUserIntent] Guardrail check failed:", err.message);
    }

    // 🧩 Override: if sentence starts with a confirm word but includes order-related intent
    const orderTriggers = [
        "place an order", "to go", "order to go", "pickup", "pick up", "order for pickup",
        "can i order", "i’d like to order", "i want to order", "i wanna order",
        "i wanna do a pickup", "can i do a pickup", "carry out", "carryout", "takeout",
        "take out", "can i get", "let me get", "i’ll get", "want to get", "gonna get"
    ];

    const confirmAndOrder = confirmTriggers.some(trigger => user_input.startsWith(trigger))
        && orderTriggers.some(trigger => user_input.includes(trigger));

    if (confirmAndOrder) {
        user_intent = "start_order";
        console.log(`🧠 [detectUserIntent] Overrode confirm → start_order for input: "${user_input}"`);
    }

    // 🧠 Final override — opening phrases like "can I get" always mean start_order
    if (user_intent === "restart_order" || user_intent === "unknown") {
        const startOrderPatterns = [
            /\b(can i get|i'll take|i would like|give me|i want|let me get|order me)\b/i
        ];
        if (startOrderPatterns.some(p => p.test(user_input))) {
            user_intent = "start_order";
            console.log(`✅ [detectUserIntent] Overrode restart/unknown → start_order (opening phrase match)`);
        }
    }

    // 🧩 Distinguish between pickup/to-go inquiry vs direct menu order
    if (user_intent === "start_order") {
        const hasPickupPhrase = /\b(pick\s?up|to\s?go|carry\s?out|for\s?here)\b/i.test(user_input);
        const hasMenuPhrase = /\b(can i get|i'll take|i would like|give me|i want|let me get|order me)\b/i.test(user_input);

        if (hasPickupPhrase && !hasMenuPhrase) {
            user_intent = "start_order_inquiry";
            console.log("🟡 [detectUserIntent] Adjusted to start_order_inquiry (pickup/to-go phrase detected)");
        } else {
            console.log("✅ [detectUserIntent] Confirmed direct start_order (menu phrase detected)");
        }
    }

    console.log(`🔍 Intent Detected: "${user_input}" → ${user_intent}`);
    if (user_intent === "cancel_order") {
        console.log(`🛑 User cancelled order: "${user_input}"`);
    }

    user_intent = user_intent.trim();

    return res.status(200).json({
        success: true,
        user_intent,
        original_user_input: user_input
    });
});

exports.storeOrderDraft = functions.https.onRequest(async (req, res) => {
    const startTs = Date.now();
    try {
        const apiKey = req.get("x-api-key");
        if (!apiKey || apiKey !== "conversight_api_key_2025_NINI_f1n3gr41n3d_s3cur3") {
            console.warn("storeOrderDraft unauthorized: bad/missing x-api-key");
            return res.status(401).json({ success: false, message: "Unauthorized" });
        }

        if (req.method !== "POST") {
            return res.status(405).json({ success: false, message: "Method not allowed" });
        }

        const {
            client_id,
            call_id,
            original_user_input,
            items_ordered,
            user_intent
        } = req.body || {};

        if (!client_id || !call_id) {
            return res.status(400).json({ success: false, message: "Missing client_id or call_id" });
        }

        const ref = admin.firestore().collection("orders").doc(call_id);

        const payload = {
            client_id,
            raw_input: original_user_input || admin.firestore.FieldValue.delete(),
            items: Array.isArray(items_ordered) ? items_ordered : admin.firestore.FieldValue.delete(),
            user_intent: user_intent || admin.firestore.FieldValue.delete(),
            updatedAt: admin.firestore.FieldValue.serverTimestamp(),
            meta: {
                source: "storeOrderDraft",
                firstTurn: !!original_user_input,
            },
        };

        await ref.set(payload, { merge: true });

        console.log(
            `🧠 [storeOrderDraft] call_id=${call_id} | firstTurn=${!!original_user_input} | items=${Array.isArray(items_ordered) ? items_ordered.length : 0}`
        );

        return res.status(200).json({ success: true });
    } catch (err) {
        console.error("❌ [storeOrderDraft] failed:", err);
        return res.status(500).json({ success: false, message: "Internal error" });
    } finally {
        console.log(`⏱️ [storeOrderDraft] ${Date.now() - startTs}ms`);
    }
});


exports.debugModifiers = functions.https.onRequest(async (req, res) => {
    try {
        const client_id = req.query.client_id; // or hardcode one for now
        const snapshot = await admin.firestore()
            .collection("clients")
            .doc(client_id)
            .collection("modifiers")
            .limit(5)
            .get();

        const results = [];
        snapshot.forEach(doc => results.push({ id: doc.id, ...doc.data() }));

        console.log("🔎 Modifier sample:", results);
        res.status(200).json({ success: true, results });
    } catch (err) {
        console.error("❌ Debug modifiers failed:", err.message);
        res.status(500).json({ success: false, error: err.message });
    }
});

// 🧩 Diagnostic: check modifier metadata safely (read-only)
exports.checkModifierMetadata = functions.https.onRequest(async (req, res) => {
    try {
        const clientId = req.query.client_id || "MLGFXWAYKSXM6"; // replace with your sandbox client if needed
        const snapshot = await admin.firestore()
            .collection(`clients/${clientId}/modifiers`)
            .limit(5)
            .get();

        const result = snapshot.docs.map(d => ({
            id: d.id,
            name: d.data().name,
            list_id: d.data().modifier_list_id || d.data().modifier_data?.modifier_list_id,
            modifier_list_name: d.data().modifier_list_name,
            allowed_parent_types: d.data().allowed_parent_types,
            category_hint: d.data().category_name || d.data().item_category,
        }));

        console.log("🧠 Sample modifier metadata:", result);
        return res.status(200).json(result);
    } catch (err) {
        console.error("🔥 checkModifierMetadata failed:", err.message);
        return res.status(500).json({ error: err.message });
    }
});

// 🆕 --- Clone Production Catalog to Sandbox ---
exports.cloneProductionCatalogToSandbox = functions.https.onRequest(async (req, res) => {
    console.log("🧩 [CloneCatalog] Incoming request");

    // 1️⃣ --- API Key Authentication ---
    const apiKey = req.headers["x-api-key"];
    const expectedKey = functions.config().security?.apikey;
    if (!apiKey || apiKey !== expectedKey) {
        console.error("❌ [CloneCatalog] Unauthorized request — invalid API key");
        return res.status(401).send("Unauthorized");
    }

    // 2️⃣ --- Input Validation ---
    const clientId = req.query.client_id;
    if (!clientId) {
        console.error("❌ [CloneCatalog] Missing client_id query parameter");
        return res.status(400).send("Missing client_id parameter");
    }

    console.log(`🔑 [CloneCatalog] Starting clone for client_id: ${clientId}`);

    // 3️⃣ --- Retrieve Access Tokens ---
    const prodToken = await getAccessTokenForClient(clientId, "production");
    const sandboxToken = await getAccessTokenForClient(clientId, "sandbox");

    if (!prodToken || !sandboxToken) {
        console.error("❌ [CloneCatalog] Missing tokens for production or sandbox");
        return res.status(400).send("Missing tokens for one or both environments");
    }

    // 4️⃣ --- Fetch Production Catalog ---
    console.log("🌐 [CloneCatalog] Fetching catalog from production...");

    try {
        const prodResponse = await axios.get(
            "https://connect.squareup.com/v2/catalog/list",
            { headers: { Authorization: `Bearer ${prodToken}` } }
        );

        const objects = prodResponse.data.objects || [];
        console.log(`🧾 [CloneCatalog] Retrieved ${objects.length} objects from production catalog`);

        // ⚠️ Empty catalog guard
        if (objects.length === 0) {
            console.warn("⚠️ [CloneCatalog] Production catalog is empty — nothing to clone.");
            return res
                .status(200)
                .send("Production catalog empty — no items cloned (valid token, no objects).");
        }

        // 5️⃣ --- Push to Sandbox ---
        console.log("🚀 [CloneCatalog] Uploading catalog to sandbox...");
        const upsertPayload = {
            idempotency_key: uuidv4(),
            batches: [{ objects }],
        };

        const sandboxResponse = await axios.post(
            "https://connect.squareupsandbox.com/v2/catalog/batch-upsert",
            upsertPayload,
            { headers: { Authorization: `Bearer ${sandboxToken}` } }
        );

        console.log("✅ [CloneCatalog] Catalog copied successfully to sandbox");
        return res.status(200).json({
            message: "Catalog cloned successfully",
            result_count: objects.length,
            sandbox_response: sandboxResponse.data,
        });

    } catch (err) {
        const status = err.response?.status || 500;
        const detail = err.response?.data?.errors?.[0]?.detail || err.message;
        console.error(`❌ [CloneCatalog] Failed to fetch production catalog — ${status}: ${detail}`);

        if (status === 401) {
            console.error("🚨 [CloneCatalog] Production token invalid or expired — reauthorization required.");
        }

        return res.status(status).send(`Error cloning catalog: ${detail}`);
    }
});

// 🧭 --- Get Client Status (Plug-and-Play Dual Environment) ---
exports.getClientStatus = functions.https.onRequest(async (req, res) => {
    console.log("🧩 [ClientStatus] Incoming request");

    try {
        // 1️⃣ --- API Key Authentication ---
        const apiKey = req.headers["x-api-key"];
        const expectedKey = functions.config().security?.apikey;
        if (!apiKey || apiKey !== expectedKey) {
            console.error("❌ [ClientStatus] Unauthorized request — invalid API key");
            return res.status(401).send("Unauthorized");
        }

        // 2️⃣ --- Input Validation ---
        const clientId = req.query.client_id;
        if (!clientId) {
            console.error("❌ [ClientStatus] Missing client_id query parameter");
            return res.status(400).send("Missing client_id parameter");
        }

        console.log(`🔍 [ClientStatus] Checking dual-env status for client_id: ${clientId}`);

        const db = admin.firestore();

        // 3️⃣ --- Get env info (sandbox or production) ---
        const envDoc = await db.collection("clients").doc(clientId).collection("config").doc("env").get();
        const envData = envDoc.exists ? envDoc.data() : {};
        const currentEnv = envData.square_environment || "sandbox";

        // Helper to find merchant_id for a given environment
        const getMerchantIdForEnv = async (env) => {
            const mappingSnap = await db.collection("mappings").get();
            let merchantId = null;

            mappingSnap.forEach((doc) => {
                const data = doc.data();
                if (data.clientId === clientId) merchantId = doc.id;
            });

            console.log(`🔗 [ClientStatus:${env}] Resolved merchant_id=${merchantId || "not found"}`);
            return merchantId;
        };

        // Helper to get token + catalog status (enhanced)
        const getEnvStatus = async (env) => {
            const merchantId = await getMerchantIdForEnv(env);
            if (!merchantId) return { token_present: false, catalog_items: 0, status: "missing" };

            const tokenDoc = await db.collection("tokens").doc(merchantId).get();
            const tokenExists = tokenDoc.exists;
            let tokenAgeDays = null;

            if (tokenExists) {
                const data = tokenDoc.data();
                const createdAt = data.created_at ? new Date(data.created_at).getTime() : null;
                if (createdAt) {
                    tokenAgeDays = Math.floor((Date.now() - createdAt) / (1000 * 60 * 60 * 24));
                }
            }

            const catalogSnap = await db
                .collection("clients")
                .doc(clientId)
                .collection("catalog")
                .doc("catalog_items")
                .get();
            const itemCount = catalogSnap.exists ? Object.keys(catalogSnap.data()).length : 0;

            // 🧩 Simple readiness logic
            const status =
                tokenExists && itemCount > 0 ? "ready" : tokenExists ? "catalog_empty" : "needs_attention";

            console.log(`✅ [ClientStatus:${env}] Token: ${tokenExists}, Age: ${tokenAgeDays}d, Items: ${itemCount}, Status: ${status}`);
            return { token_present: tokenExists, token_age_days: tokenAgeDays, catalog_items: itemCount, status };
        };

        // 4️⃣ --- Fetch both environments
        const [sandboxStatus, productionStatus] = await Promise.all([
            getEnvStatus("sandbox"),
            getEnvStatus("production"),
        ]);

        const result = {
            client_id: clientId,
            sandbox: sandboxStatus,
            production: productionStatus,
            detected_environment: currentEnv,
        };

        console.log("🧾 [ClientStatus] Summary:", result);
        return res.status(200).json(result);
    } catch (err) {
        console.error("❌ [ClientStatus] Error:", err.message);
        return res.status(500).send(`Error retrieving client status: ${err.message}`);
    }
});



