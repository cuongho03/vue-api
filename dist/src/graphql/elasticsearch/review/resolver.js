"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const config_1 = __importDefault(require("config"));
const client_1 = __importDefault(require("../client"));
const queryBuilder_1 = require("../queryBuilder");
const mapping_1 = require("../mapping");
const elastic_1 = require("./../../../lib/elastic");
function list(search, filter, currentPage, pageSize = 200, sort, context, rootValue, _sourceInclude) {
    return __awaiter(this, void 0, void 0, function* () {
        let query = queryBuilder_1.buildQuery({ search, filter, currentPage, pageSize, sort, type: 'review' });
        const response = yield client_1.default.search(elastic_1.adjustQuery({
            index: mapping_1.getIndexName(context.req.url),
            body: query,
            _sourceInclude
        }, 'review', config_1.default));
        return response.body;
    });
}
const resolver = {
    Query: {
        reviews: (_, { search, filter, currentPage, pageSize, sort, _sourceInclude }, context, rootValue) => list(search, filter, currentPage, pageSize, sort, context, rootValue, _sourceInclude)
    }
};
exports.default = resolver;
//# sourceMappingURL=resolver.js.map