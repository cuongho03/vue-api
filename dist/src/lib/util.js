"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const config_1 = __importDefault(require("config"));
const crypto_1 = __importDefault(require("crypto"));
const algorithm = 'aes-256-ctr';
/**
 * Get current store code from parameter passed from the vue storefront frotnend app
 * @param {Express.Request} req
 */
function getCurrentStoreCode(req) {
    if (req.headers['x-vs-store-code']) {
        return req.headers['x-vs-store-code'];
    }
    if (req.query.storeCode) {
        return req.query.storeCode;
    }
    return null;
}
exports.getCurrentStoreCode = getCurrentStoreCode;
/**
 * Get the config.storeViews[storeCode]
 * @param {string} storeCode
 */
function getCurrentStoreView(storeCode = null) {
    let storeView = {
        tax: config_1.default.tax,
        i18n: config_1.default.i18n,
        elasticsearch: config_1.default.elasticsearch,
        storeCode: null,
        storeId: config_1.default.defaultStoreCode && config_1.default.defaultStoreCode !== '' ? config_1.default.storeViews[config_1.default.defaultStoreCode].storeId : 1
    };
    if (storeCode && config_1.default.storeViews[storeCode]) {
        storeView = config_1.default.storeViews[storeCode];
    }
    return storeView; // main config is used as default storeview
}
exports.getCurrentStoreView = getCurrentStoreView;
/**  Creates a callback that proxies node callback style arguments to an Express Response object.
 *  @param {express.Response} res  Express HTTP Response
 *  @param {number} [status=200]  Status code to send on success
 *
 *  @example
 *    list(req, res) {
 *      collection.find({}, toRes(res));
 *    }
 */
function toRes(res, status = 200) {
    return (err, thing) => {
        if (err)
            return res.status(500).send(err);
        if (thing && typeof thing.toObject === 'function') {
            thing = thing.toObject();
        }
        res.status(status).json(thing);
    };
}
exports.toRes = toRes;
function sgnSrc(sgnObj, item) {
    if (config_1.default.tax.alwaysSyncPlatformPricesOver) {
        sgnObj.id = item.id;
    }
    else {
        sgnObj.sku = item.sku;
    }
    // console.log(sgnObj)
    return sgnObj;
}
exports.sgnSrc = sgnSrc;
/**  Creates a api status call and sends it thru to Express Response object.
 *  @param {express.Response} res  Express HTTP Response
 *  @param {number} [code=200]    Status code to send on success
 *  @param {json} [result='OK']    Text message or result information object
 */
function apiStatus(res, result = 'OK', code = 200, meta = null) {
    let apiResult = { code: code, result: result };
    if (meta !== null) {
        apiResult.meta = meta;
    }
    res.status(code).json(apiResult);
    return result;
}
exports.apiStatus = apiStatus;
/**
 *  Creates an error for API status of Express Response object.
 *
 *  @param {express.Response} res   Express HTTP Response
 *  @param {object|string} error    Error object or error message
 *  @return {json} [result='OK']    Text message or result information object
 */
function apiError(res, error) {
    let errorCode = error.code || error.status || 500;
    let errorMessage = error.errorMessage || error;
    if (error instanceof Error) {
        // Class 'Error' is not serializable with JSON.stringify, extract data explicitly.
        errorCode = error.code || errorCode;
        errorMessage = error.message;
    }
    return apiStatus(res, errorMessage, errorCode);
}
exports.apiError = apiError;
function encryptToken(textToken, secret) {
    const cipher = crypto_1.default.createCipher(algorithm, secret);
    let crypted = cipher.update(textToken, 'utf8', 'hex');
    crypted += cipher.final('hex');
    return crypted;
}
exports.encryptToken = encryptToken;
function decryptToken(textToken, secret) {
    const decipher = crypto_1.default.createDecipher(algorithm, secret);
    let dec = decipher.update(textToken, 'hex', 'utf8');
    dec += decipher.final('utf8');
    return dec;
}
exports.decryptToken = decryptToken;
//# sourceMappingURL=util.js.map