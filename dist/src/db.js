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
const config_1 = __importDefault(require("config"));
const redis = __importStar(require("./lib/redis"));
const elastic = __importStar(require("./lib/elastic"));
exports.default = callback => {
    // connect to a database if needed, then pass it to `callback`:
    const dbContext = {
        getRedisClient: () => redis.getClient(config_1.default),
        getElasticClient: () => elastic.getClient(config_1.default)
    };
    callback(dbContext);
};
//# sourceMappingURL=db.js.map