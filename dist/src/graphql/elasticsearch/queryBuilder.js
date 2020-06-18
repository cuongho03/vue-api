"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const bodybuilder_1 = __importDefault(require("bodybuilder"));
const storefront_query_builder_1 = require("storefront-query-builder");
const config_1 = __importDefault(require("config"));
function buildQuery({ filter = [], sort = '', currentPage = 1, pageSize = 10, search = '', type = 'product' }) {
    let queryChain = bodybuilder_1.default();
    storefront_query_builder_1.elasticsearch.buildQueryBodyFromFilterObject({ config: config_1.default, queryChain, filter, search });
    queryChain = storefront_query_builder_1.elasticsearch.applySort({ sort, queryChain });
    queryChain = queryChain.from((currentPage - 1) * pageSize).size(pageSize);
    let builtQuery = queryChain.build();
    if (search !== '') {
        builtQuery['min_score'] = config_1.default.get('elasticsearch.min_score');
    }
    return builtQuery;
}
exports.buildQuery = buildQuery;
//# sourceMappingURL=queryBuilder.js.map