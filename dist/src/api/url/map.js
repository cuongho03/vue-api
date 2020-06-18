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
const express_1 = require("express");
const util_1 = require("../../lib/util");
const elastic_1 = require("../../lib/elastic");
const factory_1 = __importDefault(require("../../processor/factory"));
const get_1 = __importDefault(require("lodash/get"));
const adjustQueryForOldES = ({ config }) => {
    const searchedEntities = get_1.default(config, 'urlModule.map.searchedEntities', [])
        .map((entity) => ({ type: { value: entity } }));
    if (parseInt(config.elasticsearch.apiVersion) < 6) {
        return {
            filter: {
                bool: {
                    should: searchedEntities
                }
            }
        };
    }
    else {
        return {};
    }
};
/**
 * Builds ES query based on config
 */
const buildQuery = ({ value, config }) => {
    const searchedFields = get_1.default(config, 'urlModule.map.searchedFields', [])
        .map((field) => ({ match_phrase: { [field]: { query: value } } }));
    return {
        query: {
            bool: {
                filter: {
                    bool: Object.assign({ should: searchedFields }, adjustQueryForOldES({ config }))
                }
            }
        },
        size: 1 // we need only one record
    };
};
const buildIndex = ({ indexName, config }) => {
    return parseInt(config.elasticsearch.apiVersion) < 6
        ? indexName
        : get_1.default(config, 'urlModule.map.searchedEntities', [])
            .map(entity => `${indexName}_${entity}`);
};
const adjustResultType = ({ result, config, indexName }) => {
    if (parseInt(config.elasticsearch.apiVersion) < 6)
        return result;
    // extract type from index for es 7
    const type = result._index.replace(new RegExp(`^(${indexName}_)|(_[^_]*)$`, 'g'), '');
    result._type = type;
    return result;
};
/**
 * checks result equality because ES can return record even if searched value is not EXACLY what we want (check `match_phrase` in ES docs)
 */
const checkFieldValueEquality = ({ config, result, value }) => {
    const isEqualValue = get_1.default(config, 'urlModule.map.searchedFields', [])
        .find((field) => result._source[field] === value);
    return Boolean(isEqualValue);
};
const map = ({ config }) => {
    const router = express_1.Router();
    router.post('/', (req, res) => __awaiter(void 0, void 0, void 0, function* () {
        const { url, excludeFields, includeFields } = req.body;
        if (!url) {
            return util_1.apiStatus(res, 'Missing url', 500);
        }
        const indexName = util_1.getCurrentStoreView(util_1.getCurrentStoreCode(req)).elasticsearch.index;
        const esQuery = {
            index: buildIndex({ indexName, config }),
            _source_includes: includeFields ? includeFields.concat(get_1.default(config, 'urlModule.map.includeFields', [])) : [],
            _source_excludes: excludeFields,
            body: buildQuery({ value: url, config })
        };
        try {
            const esResponse = yield elastic_1.getClient(config).search(esQuery);
            let result = get_1.default(esResponse, 'body.hits.hits[0]', null);
            if (result && checkFieldValueEquality({ config, result, value: req.body.url })) {
                result = adjustResultType({ result, config, indexName });
                if (result._type === 'product') {
                    const factory = new factory_1.default(config);
                    let resultProcessor = factory.getAdapter('product', indexName, req, res);
                    if (!resultProcessor) {
                        resultProcessor = factory.getAdapter('default', indexName, req, res);
                    }
                    resultProcessor
                        .process(esResponse.body.hits.hits, null)
                        .then(pResult => {
                        pResult = pResult.map(h => Object.assign(h, { _score: h._score }));
                        return res.json(pResult[0]);
                    }).catch((err) => {
                        console.error(err);
                        return res.json();
                    });
                }
                else {
                    return res.json(result);
                }
            }
            else {
                return res.json(null);
            }
        }
        catch (err) {
            console.error(err);
            return util_1.apiStatus(res, new Error('ES search error'), 500);
        }
    }));
    return router;
};
exports.default = map;
//# sourceMappingURL=map.js.map