/**
 * 🔁 Shared synonym logic for detectUserIntent + getAIResponse
 * -----------------------------------------------------------
 * This central helper ensures both functions share identical
 * synonym mappings for FAQ detection (e.g., “hours”, “wifi”).
 *
 * It supports future client-specific overrides so each restaurant
 * can have custom synonyms or topics in Firestore without changing code.
 */

const admin = require("firebase-admin");

// 🧠 Core default synonym map (used by all clients)
const defaultSynonymMap = {
  hours: ["hour", "hours", "open", "close", "closing", "opening", "what time"],
  wifi: ["wi-fi", "internet", "wifi access"],
  parking: ["parking", "park", "car", "lot", "garage"],
  delivery: ["delivery", "deliver", "door dash", "uber eats", "grubhub"],
  payment_methods: ["apple pay", "credit", "debit", "cash", "contactless"],
  location: ["address", "where are you", "location", "nearby"],
  takeout: ["takeout", "pick up", "to go", "carryout"],
  pet_policy: ["dog", "pet", "animal"],
  family_friendly: ["kids", "child", "family"],
  catering: ["catering", "large order", "event", "party", "bulk"]
};

/**
 * getSynonymMap(clientId)
 * ------------------------
 * Loads the shared synonym map.
 * If Firestore overrides exist under:
 *   /clients/{clientId}/intents_config.custom_synonyms
 * they will be merged into the base map.
 */
exports.getSynonymMap = async (clientId = null) => {
  try {
    // Base map
    let merged = { ...defaultSynonymMap };

    // Optional: merge in client-specific overrides if clientId provided
    if (clientId && admin.apps.length) {
      const db = admin.firestore();
      const doc = await db.collection("clients").doc(clientId).get();
      const customSynonyms = doc.data()?.intents_config?.custom_synonyms;
      if (customSynonyms && typeof customSynonyms === "object") {
        merged = { ...merged, ...customSynonyms };
        console.log(`🧩 [getSynonymMap] Merged ${Object.keys(customSynonyms).length} custom synonyms for ${clientId}`);
      }
    }

    return merged;
  } catch (err) {
    console.error("❌ [getSynonymMap] Error loading synonyms:", err.message);
    return defaultSynonymMap; // fallback to defaults if anything fails
  }
};

