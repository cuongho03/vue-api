"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const util_1 = require("../../../lib/util");
const elastic_1 = require("../../../lib/elastic");
const express_1 = require("express");
const bodybuilder = require('bodybuilder');
module.exports = ({ config, db }) => {
    let api = express_1.Router();
    const getStockList = (storeCode, skus) => {
        let storeView = util_1.getCurrentStoreView(storeCode);
        const esQuery = elastic_1.adjustQuery({
            index: storeView.elasticsearch.index,
            type: 'product',
            _source_includes: ['stock'],
            body: bodybuilder().filter('term', 'status', 1).andFilter('terms', 'sku', skus).build()
        }, 'product', config);
        return elastic_1.getClient(config).search(esQuery).then((products) => {
            return elastic_1.getHits(products).map(el => { return el._source.stock; });
        }).catch(err => {
            console.error(err);
        });
    };
    /**
     * GET get stock item
     */
    api.get('/check/:sku', (req, res) => {
        if (!req.params.sku) {
            return util_1.apiStatus(res, 'sku parameter is required', 500);
        }
        getStockList(util_1.getCurrentStoreCode(req), [req.params.sku]).then((result) => {
            if (result && result.length > 0) {
                util_1.apiStatus(res, result[0], 200);
            }
            else {
                util_1.apiStatus(res, 'No stock information for given sku', 500);
            }
        }).catch(err => {
            util_1.apiStatus(res, err, 500);
        });
    });
    /**
    * GET get stock item - 2nd version with the query url parameter
    */
    api.get('/check', (req, res) => {
        if (!req.query.sku) {
            return util_1.apiStatus(res, 'sku parameter is required', 500);
        }
        getStockList(util_1.getCurrentStoreCode(req), [req.query.sku]).then((result) => {
            if (result && result.length > 0) {
                util_1.apiStatus(res, result[0], 200);
            }
            else {
                util_1.apiStatus(res, 'No stock information for given sku', 500);
            }
        }).catch(err => {
            util_1.apiStatus(res, err, 500);
        });
    });
    /**
    * GET get stock item list by skus (comma separated)
    */
    api.get('/list', (req, res) => {
        if (!req.query.skus) {
            return util_1.apiStatus(res, 'skus parameter is required', 500);
        }
        const skuArray = req.query.skus.split(',');
        getStockList(util_1.getCurrentStoreCode(req), skuArray).then((result) => {
            if (result && result.length > 0) {
                util_1.apiStatus(res, result, 200);
            }
            else {
                util_1.apiStatus(res, 'No stock information for given sku', 500);
            }
        }).catch(err => {
            util_1.apiStatus(res, err, 500);
        });
    });
    return api;
};
//# sourceMappingURL=index.js.map