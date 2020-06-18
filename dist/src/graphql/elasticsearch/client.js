"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const config_1 = __importDefault(require("config"));
const elastic_1 = __importDefault(require("../../lib/elastic"));
exports.default = elastic_1.default.getClient(config_1.default);
//# sourceMappingURL=client.js.map