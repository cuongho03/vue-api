"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const user_1 = __importDefault(require("../abstract/user"));
const util_1 = require("./util");
class UserProxy extends user_1.default {
    constructor(config, req) {
        const Magento2Client = require('magento2-rest-client').Magento2Client;
        super(config, req);
        this.api = Magento2Client(util_1.multiStoreConfig(config.magento2.api, req));
    }
    register(userData) {
        return this.api.customers.create(userData);
    }
    login(userData) {
        return this.api.customers.token(userData);
    }
    me(requestToken) {
        console.log(this.api.customers.me(requestToken));
        return this.api.customers.me(requestToken);
    }
    orderHistory(requestToken, pageSize = 20, currentPage = 1) {
        return this.api.customers.orderHistory(requestToken, pageSize, currentPage);
    }
    resetPassword(emailData) {
        return this.api.customers.resetPassword(emailData);
    }
    update(userData) {
        return this.api.customers.update(userData);
    }
    changePassword(passwordData) {
        return this.api.customers.changePassword(passwordData);
    }
    resetPasswordUsingResetToken(resetData) {
        return this.api.customers.resetPasswordUsingResetToken(resetData);
    }
}
module.exports = UserProxy;
//# sourceMappingURL=user.js.map