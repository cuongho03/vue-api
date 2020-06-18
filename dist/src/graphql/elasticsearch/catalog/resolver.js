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
const processor_1 = __importDefault(require("./processor"));
const mapping_1 = require("../mapping");
const elastic_1 = require("./../../../lib/elastic");
const service_1 = __importDefault(require("./../../../api/attribute/service"));
const resolver = {
    Query: {
        products: (_, { search, filter, sort, currentPage, pageSize, _sourceInclude, _sourceExclude }, context, rootValue) => list(filter, sort, currentPage, pageSize, search, context, rootValue, _sourceInclude, _sourceExclude)
    }
};
function list(filter, sort, currentPage, pageSize, search, context, rootValue, _sourceInclude, _sourceExclude) {
    return __awaiter(this, void 0, void 0, function* () {
        let _req = {
            query: {
                _source_exclude: _sourceExclude,
                _source_include: _sourceInclude
            }
        };
        let query = queryBuilder_1.buildQuery({
            filter: filter,
            sort: sort,
            currentPage: currentPage,
            pageSize: pageSize,
            search: search,
            type: 'product'
        });
        let esIndex = mapping_1.getIndexName(context.req.url);
        let esResponse = yield client_1.default.search(elastic_1.adjustQuery({
            index: esIndex,
            body: query,
            _sourceInclude,
            _sourceExclude
        }, 'product', config_1.default));
        if (esResponse && esResponse.body.hits && esResponse.body.hits.hits) {
            // process response result (caluclate taxes etc...)
            esResponse.body.hits.hits = yield processor_1.default(esResponse, _req, config_1.default.elasticsearch.indexTypes[0], esIndex);
        }
        let response = {};
        // Process hits
        response.items = [];
        esResponse.body.hits.hits.forEach(hit => {
            let item = hit._source;
            item._score = hit._score;
            response.items.push(item);
        });
        response.total_count = esResponse.body.hits.total;
        // Process sort
        let sortOptions = [];
        for (var sortAttribute in sort) {
            sortOptions.push({
                label: sortAttribute,
                value: sortAttribute
            });
        }
        response.aggregations = esResponse.aggregations;
        if (response.aggregations && config_1.default.entities.attribute.loadByAttributeMetadata) {
            const attributeListParam = service_1.default.transformAggsToAttributeListParam(response.aggregations);
            const attributeList = yield service_1.default.list(attributeListParam, config_1.default, esIndex);
            response.attribute_metadata = attributeList.map(service_1.default.transformToMetadata);
        }
        response.sort_fields = {};
        if (sortOptions.length > 0) {
            response.sort_fields.options = sortOptions;
        }
        response.page_info = {
            page_size: pageSize,
            current_page: currentPage
        };
        return response;
    });
}
exports.default = resolver;
//# sourceMappingURL=resolver.js.map