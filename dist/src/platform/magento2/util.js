"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const config_1 = __importDefault(require("config"));
const util_1 = require("../../lib/util");
/**
 * Adjust the config provided to the current store selected via request params
 * @param Object config configuration
 * @param Express request req
 */
function multiStoreConfig(apiConfig, req) {
    let confCopy = Object.assign({}, apiConfig);
    let storeCode = util_1.getCurrentStoreCode(req);
    if (storeCode && config_1.default.availableStores.indexOf(storeCode) >= 0) {
        if (config_1.default.magento2['api_' + storeCode]) {
            confCopy = Object.assign({}, config_1.default.magento2['api_' + storeCode]); // we're to use the specific api configuration - maybe even separate magento instance
        }
        confCopy.url = confCopy.url + '/' + storeCode;
    }
    else {
        if (storeCode) {
            console.error('Unavailable store code', storeCode);
        }
    }
    return confCopy;
}
exports.multiStoreConfig = multiStoreConfig;
//# sourceMappingURL=util.js.map