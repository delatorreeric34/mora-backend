// /functions/constants.js

// ✅ Global size alias normalization map
exports.sizeAliasMap = {
    "12ounce": "12oz", "12 oz": "12oz", "12oz": "12oz", "twelveounce": "12oz", "twelveoz": "12oz",
    "16ounce": "16oz", "16 oz": "16oz", "16oz": "16oz", "sixteenounce": "16oz", "sixteenoz": "16oz",
    "20ounce": "20oz", "20 oz": "20oz", "20oz": "20oz", "twentyounce": "20oz", "twentyoz": "20oz",
    "24ounce": "24oz", "24 oz": "24oz", "24oz": "24oz", "twentyfourounce": "24oz", "twentyfouroz": "24oz",
    "small": "12oz", "medium": "16oz", "large": "20oz", "extralarge": "24oz"
  };
  
  // ✅ Item name alias map (fuzzy match helpers)
  exports.itemAliasMap = {
    "moco": "Mocha",
    "moca": "Mocha",
    "icemocha": "Iced Mocha",
    "capuccino": "Cappuccino",
    "capucino": "Cappuccino",
    "expresso": "Espresso",
    "expreso": "Espresso",
    "late": "Latte",
    "cappucino": "Cappuccino",
    "cappuccinoo": "Cappuccino"
  };
  
  // ✅ Common size phrases
  exports.commonSizePhrases = [ "half", "full", "small", "medium", "large", "extra large", "grande", "venti", "tall" ];
  
  // ✅ Variation alias map
  exports.variationAliasMap = {
    "half": "half",
    "full": "full",
    "small": "12oz",
    "medium": "16oz",
    "large": "20oz",
    "extra large": "24oz",
    "grande": "16oz",
    "venti": "20oz",
    "tall": "12oz"
  };
  
  // ✅ Modifier alias map
  exports.modifierAliasMap = {
    "almond": "Almond Milk",
    "almondmilk": "Almond Milk",
    "soy": "Soy Milk",
    "soymilk": "Soy Milk",
    "oat": "Oat Milk",
    "oatmilk": "Oat Milk",
    "whole": "Whole Milk",
    "2": "2% Milk",
    "2percent": "2% Milk",
    "skim": "Nonfat Milk",
    "nonfat": "Nonfat Milk",
  
    // Double aliases
    "double": "Double",
    "doubleshot": "Double",
    "double shot": "Double",
    "doubleespresso": "Double",
    "double espresso": "Double"
  };
  
  // ✅ Normalized modifier alias map
  exports.normalizedModifierAliasMap = (() => {
    const normalized = {};
    for (const [key, val] of Object.entries(exports.modifierAliasMap)) {
      const normKey = key.toLowerCase().replace(/[^a-z0-9]/g, "");
      normalized[normKey] = val;
    }
    return normalized;
  })();
  

