"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const config_1 = __importDefault(require("config"));
function getBoosts(attribute = '') {
    let boosts = [];
    if (config_1.default.boost) {
        boosts = config_1.default.boost;
    }
    if (boosts.hasOwnProperty(attribute)) {
        return boosts[attribute];
    }
    return 1;
}
exports.default = getBoosts;
//# sourceMappingURL=boost.js.map