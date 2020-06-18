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
const get_1 = __importDefault(require("lodash/get"));
const cache_instance_1 = __importDefault(require("../../lib/cache-instance"));
const elastic_1 = require("./../../lib/elastic");
const bodybuilder_1 = __importDefault(require("bodybuilder"));
/**
 * Transforms ES aggregates into valid format for AttributeService - {[attribute_code]: [bucketId1, bucketId2]}
 * @param body - products response body
 * @param config - global config
 * @param indexName - current indexName
 */
function transformAggsToAttributeListParam(aggregations) {
    const attributeListParam = Object.keys(aggregations)
        .filter(key => aggregations[key].buckets.length) // leave only buckets with values
        .reduce((acc, key) => {
        const attributeCode = key.replace(/^(agg_terms_|agg_range_)|(_options)$/g, '');
        const bucketsIds = aggregations[key].buckets.map(bucket => bucket.key);
        if (!acc[attributeCode]) {
            acc[attributeCode] = [];
        }
        // there can be more then one attributes for example 'agg_terms_color' and 'agg_terms_color_options'
        // we need to get buckets from both
        acc[attributeCode] = [...new Set([...acc[attributeCode], ...bucketsIds])];
        return acc;
    }, {});
    return attributeListParam;
}
/**
 * Returns attributes from cache
 */
function getAttributeFromCache(attributeCode, config) {
    return __awaiter(this, void 0, void 0, function* () {
        if (config.server.useOutputCache && cache_instance_1.default) {
            try {
                const res = yield cache_instance_1.default.get('api:attribute-list' + attributeCode);
                return res;
            }
            catch (err) {
                console.error(err);
                return null;
            }
        }
    });
}
/**
 * Save attributes in cache
 */
function setAttributeInCache(attributeList, config) {
    return __awaiter(this, void 0, void 0, function* () {
        if (config.server.useOutputCache && cache_instance_1.default) {
            try {
                yield Promise.all(attributeList.map(attribute => cache_instance_1.default.set('api:attribute-list' + attribute.attribute_code, attribute)));
            }
            catch (err) {
                console.error(err);
            }
        }
    });
}
/**
 * Returns attribute with only needed options
 * @param attribute - attribute object
 * @param optionsIds - list of only needed options ids
 */
function clearAttributeOpitons(attribute, optionsIds) {
    const stringOptionsIds = optionsIds.map(String);
    return Object.assign(Object.assign({}, attribute), { options: (attribute.options || []).filter(option => stringOptionsIds.includes(String(option.value))) });
}
function list(attributesParam, config, indexName) {
    return __awaiter(this, void 0, void 0, function* () {
        // we start with all attributeCodes that are requested
        let attributeCodes = Object.keys(attributesParam);
        // here we check if some of attribute are in cache
        const rawCachedAttributeList = yield Promise.all(attributeCodes.map(attributeCode => getAttributeFromCache(attributeCode, config)));
        const cachedAttributeList = rawCachedAttributeList
            .map((cachedAttribute, index) => {
            if (cachedAttribute) {
                const attributeOptionsIds = attributesParam[cachedAttribute.attribute_code];
                // side effect - we want to reduce starting 'attributeCodes' if some of them are in cache
                attributeCodes.splice(index, 1);
                // clear unused options
                return clearAttributeOpitons(cachedAttribute, attributeOptionsIds);
            }
        })
            // remove empty results from cache.get
            // this needs to be after .map because we want to have same indexes as are in attributeCodes
            .filter(Boolean);
        // if all requested attributes are in cache then we can return here
        if (!attributeCodes.length) {
            return cachedAttributeList;
        }
        // fetch attributes for rest attributeCodes
        try {
            const query = elastic_1.adjustQuery({
                index: indexName,
                type: 'attribute',
                body: bodybuilder_1.default().filter('terms', 'attribute_code', attributeCodes).build()
            }, 'attribute', config);
            const response = yield elastic_1.getClient(config).search(query);
            const fetchedAttributeList = get_1.default(response.body, 'hits.hits', []).map(hit => hit._source);
            // save atrributes in cache
            yield setAttributeInCache(fetchedAttributeList, config);
            // cached and fetched attributes
            const allAttributes = [
                ...cachedAttributeList,
                ...fetchedAttributeList.map(fetchedAttribute => {
                    const attributeOptionsIds = attributesParam[fetchedAttribute.attribute_code];
                    // clear unused options
                    return clearAttributeOpitons(fetchedAttribute, attributeOptionsIds);
                })
            ];
            return allAttributes;
        }
        catch (err) {
            console.error(err);
            return [];
        }
    });
}
/**
 * Returns only needed data for filters in vsf
 */
function transformToMetadata({ is_visible_on_front, is_visible, default_frontend_label, attribute_id, entity_type_id, id, is_user_defined, is_comparable, attribute_code, slug, options = [] }) {
    return {
        is_visible_on_front,
        is_visible,
        default_frontend_label,
        attribute_id,
        entity_type_id,
        id,
        is_user_defined,
        is_comparable,
        attribute_code,
        slug,
        options
    };
}
exports.default = {
    list,
    transformToMetadata,
    transformAggsToAttributeListParam
};
//# sourceMappingURL=service.js.map