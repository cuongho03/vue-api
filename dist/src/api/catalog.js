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
const jwt_simple_1 = __importDefault(require("jwt-simple"));
const request_1 = __importDefault(require("request"));
const factory_1 = __importDefault(require("../processor/factory"));
const elastic_1 = require("../lib/elastic");
const cache_instance_1 = __importDefault(require("../lib/cache-instance"));
const js_sha3_1 = require("js-sha3");
const service_1 = __importDefault(require("./attribute/service"));
const bodybuilder_1 = __importDefault(require("bodybuilder"));
const loadCustomFilters_1 = __importDefault(require("../helpers/loadCustomFilters"));
const storefront_query_builder_1 = require("storefront-query-builder");
const util_1 = require("../lib/util");
function _cacheStorageHandler(config, result, hash, tags) {
    return __awaiter(this, void 0, void 0, function* () {
        if (config.server.useOutputCache && cache_instance_1.default) {
            return cache_instance_1.default.set('api:' + hash, result, tags).catch((err) => {
                console.error(err);
            });
        }
    });
}
function _outputFormatter(responseBody, format = 'standard') {
    if (format === 'compact') { // simple formatter
        delete responseBody.took;
        delete responseBody.timed_out;
        delete responseBody._shards;
        if (responseBody.hits) {
            delete responseBody.hits.max_score;
            responseBody.total = responseBody.hits.total;
            responseBody.hits = responseBody.hits.hits.map(hit => {
                return Object.assign(hit._source, { _score: hit._score });
            });
        }
    }
    return responseBody;
}
exports.default = ({ config, db }) => function (req, res, body) {
    return __awaiter(this, void 0, void 0, function* () {
        let groupId = null;
        // Request method handling: exit if not GET or POST
        // Other metods - like PUT, DELETE etc. should be available only for authorized users or not available at all)
        if (!(req.method === 'GET' || req.method === 'POST' || req.method === 'OPTIONS')) {
            throw new Error('ERROR: ' + req.method + ' request method is not supported.');
        }
        let responseFormat = 'standard';
        let requestBody = req.body;
        if (req.method === 'GET') {
            if (req.query.request) { // this is in fact optional
                try {
                    requestBody = JSON.parse(decodeURIComponent(req.query.request));
                }
                catch (err) {
                    throw new Error(err);
                }
            }
        }
        if (req.query.request_format === 'search-query') { // search query and not Elastic DSL - we need to translate it
            const customFilters = yield loadCustomFilters_1.default(config);
            requestBody = yield storefront_query_builder_1.elasticsearch.buildQueryBodyFromSearchQuery({ config, queryChain: bodybuilder_1.default(), searchQuery: new storefront_query_builder_1.SearchQuery(requestBody), customFilters });
        }
        if (req.query.response_format)
            responseFormat = req.query.response_format;
        const urlSegments = req.url.split('/');
        let indexName = '';
        let entityType = '';
        if (urlSegments.length < 2) {
            throw new Error('No index name given in the URL. Please do use following URL format: /api/catalog/<index_name>/<entity_type>_search');
        }
        else {
            indexName = urlSegments[1];
            if (urlSegments.length > 2) {
                entityType = urlSegments[2];
            }
            if (config.elasticsearch.indices.indexOf(indexName) < 0) {
                throw new Error('Invalid / inaccessible index name given in the URL. Please do use following URL format: /api/catalog/<index_name>/_search');
            }
            if (urlSegments[urlSegments.length - 1].indexOf('_search') !== 0) {
                throw new Error('Please do use following URL format: /api/catalog/<index_name>/_search');
            }
        }
        // pass the request to elasticsearch
        const elasticBackendUrl = elastic_1.adjustBackendProxyUrl(req, indexName, entityType, config);
        const userToken = requestBody.groupToken;
        // Decode token and get group id
        if (userToken && userToken.length > 10) {
            const decodeToken = jwt_simple_1.default.decode(userToken, config.authHashSecret ? config.authHashSecret : config.objHashSecret);
            groupId = decodeToken.group_id || groupId;
        }
        else if (requestBody.groupId) {
            groupId = requestBody.groupId || groupId;
        }
        delete requestBody.groupToken;
        delete requestBody.groupId;
        let auth = null;
        // Only pass auth if configured
        if (config.elasticsearch.user || config.elasticsearch.password) {
            auth = {
                user: config.elasticsearch.user,
                pass: config.elasticsearch.password
            };
        }
        const s = Date.now();
        const reqHash = js_sha3_1.sha3_224(`${JSON.stringify(requestBody)}${req.url}`);
        const dynamicRequestHandler = () => {
            request_1.default({
                uri: elasticBackendUrl,
                method: req.method,
                body: requestBody,
                json: true,
                auth: auth
            }, (_err, _res, _resBody) => __awaiter(this, void 0, void 0, function* () {
                if (_err || _resBody.error) {
                    util_1.apiError(res, _err || _resBody.error);
                    return;
                }
                try {
                    if (_resBody && _resBody.hits && _resBody.hits.hits) { // we're signing up all objects returned to the client to be able to validate them when (for example order)
                        const factory = new factory_1.default(config);
                        const tagsArray = [];
                        if (config.server.useOutputCache && cache_instance_1.default) {
                            const tagPrefix = entityType[0].toUpperCase(); // first letter of entity name: P, T, A ...
                            tagsArray.push(entityType);
                            _resBody.hits.hits.map(item => {
                                if (item._source.id) { // has common identifier
                                    tagsArray.push(`${tagPrefix}${item._source.id}`);
                                }
                            });
                            const cacheTags = tagsArray.join(' ');
                            res.setHeader('X-VS-Cache-Tags', cacheTags);
                        }
                        let resultProcessor = factory.getAdapter(entityType, indexName, req, res);
                        if (!resultProcessor) {
                            resultProcessor = factory.getAdapter('default', indexName, req, res);
                        } // get the default processor
                        const productGroupId = entityType === 'product' ? groupId : undefined;
                        const result = yield resultProcessor.process(_resBody.hits.hits, productGroupId);
                        _resBody.hits.hits = result;
                        if (entityType === 'product' && _resBody.aggregations && config.entities.attribute.loadByAttributeMetadata) {
                            const attributeListParam = service_1.default.transformAggsToAttributeListParam(_resBody.aggregations);
                            // find attribute list
                            const attributeList = yield service_1.default.list(attributeListParam, config, indexName);
                            _resBody.attribute_metadata = attributeList.map(service_1.default.transformToMetadata);
                        }
                        _resBody = _outputFormatter(_resBody, responseFormat);
                        if (config.get('varnish.enabled')) {
                            // Add tags to cache, so we can display them in response headers then
                            _cacheStorageHandler(config, Object.assign(Object.assign({}, _resBody), { tags: tagsArray }), reqHash, tagsArray);
                        }
                        else {
                            _cacheStorageHandler(config, _resBody, reqHash, tagsArray);
                        }
                    }
                    res.json(_resBody);
                }
                catch (err) {
                    util_1.apiError(res, err);
                }
            }));
        };
        if (config.server.useOutputCache && cache_instance_1.default) {
            cache_instance_1.default.get('api:' + reqHash).then(output => {
                if (output !== null) {
                    res.setHeader('X-VS-Cache', 'Hit');
                    if (config.get('varnish.enabled')) {
                        const tagsHeader = output.tags.join(' ');
                        res.setHeader('X-VS-Cache-Tag', tagsHeader);
                        delete output.tags;
                    }
                    res.json(output);
                    console.log(`cache hit [${req.url}], cached request: ${Date.now() - s}ms`);
                }
                else {
                    res.setHeader('X-VS-Cache', 'Miss');
                    console.log(`cache miss [${req.url}], request: ${Date.now() - s}ms`);
                    dynamicRequestHandler();
                }
            }).catch(err => console.error(err));
        }
        else {
            dynamicRequestHandler();
        }
    });
};
//# sourceMappingURL=catalog.js.map