"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const util_1 = require("../lib/util");
const express_1 = require("express");
exports.default = ({ config, db }) => {
    let syncApi = express_1.Router();
    /**
     * GET get stock item
     */
    syncApi.get('/order/:order_id', (req, res) => {
        const redisClient = db.getRedisClient(config);
        redisClient.get('order$$id$$' + req.param('order_id'), (err, reply) => {
            const orderMetaData = JSON.parse(reply);
            if (orderMetaData) {
                orderMetaData.order = null; // for security reasons we're just clearing out the real order data as it's set by `order_2_magento2.js`
            }
            util_1.apiStatus(res, err || orderMetaData, err ? 500 : 200);
        });
    });
    return syncApi;
};
//# sourceMappingURL=sync.js.map