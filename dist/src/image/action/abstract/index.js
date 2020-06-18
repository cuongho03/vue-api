"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const url_1 = __importDefault(require("url"));
class ImageAction {
    constructor(req, res, next, options) {
        this.SUPPORTED_ACTIONS = ['fit', 'resize', 'identify'];
        this.req = req;
        this.res = res;
        this.next = next;
        this.options = options;
    }
    isImageSourceHostAllowed() {
        if (!this._isUrlWhitelisted(this.getImageURL(), 'allowedHosts', true, this.whitelistDomain)) {
            return this.res.status(400).send({
                code: 400,
                result: `Host is not allowed`
            });
        }
    }
    _isUrlWhitelisted(url, whitelistType, defaultValue, whitelist) {
        if (arguments.length !== 4)
            throw new Error('params are not optional!');
        if (whitelist && whitelist.hasOwnProperty(whitelistType)) {
            const requestedHost = url_1.default.parse(url).host;
            const matches = whitelist[whitelistType].map(allowedHost => {
                allowedHost = allowedHost instanceof RegExp ? allowedHost : new RegExp(allowedHost);
                return !!requestedHost.match(allowedHost);
            });
            return matches.indexOf(true) > -1;
        }
        else {
            return defaultValue;
        }
    }
}
exports.default = ImageAction;
//# sourceMappingURL=index.js.map