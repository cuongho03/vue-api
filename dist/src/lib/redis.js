"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const redis_1 = __importDefault(require("redis"));
/**
 * Return Redis Client
 * @param {config} config
 */
function getClient(config) {
    let redisClient = redis_1.default.createClient(config.redis); // redis client
    redisClient.on('error', (err) => {
        redisClient = redis_1.default.createClient(config.redis); // redis client
    });
    if (config.redis.auth) {
        redisClient.auth(config.redis.auth);
    }
    return redisClient;
}
exports.getClient = getClient;
//# sourceMappingURL=redis.js.map