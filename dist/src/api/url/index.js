"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const map_1 = __importDefault(require("./map"));
const url = ({ config }) => {
    const router = express_1.Router();
    router.use('/map', map_1.default({ config }));
    return router;
};
exports.default = url;
//# sourceMappingURL=index.js.map