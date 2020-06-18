"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result["default"] = mod;
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
const syswide_cas_1 = __importDefault(require("syswide-cas"));
const fs = __importStar(require("fs"));
const CERTS_DIRECTORY = 'config/certs';
/**
 * load certificates from certs directory and consider them trusted
 */
exports.loadAdditionalCertificates = () => {
    if (fs.existsSync(CERTS_DIRECTORY)) {
        syswide_cas_1.default.addCAs(CERTS_DIRECTORY);
    }
};
//# sourceMappingURL=loadAdditionalCertificates.js.map