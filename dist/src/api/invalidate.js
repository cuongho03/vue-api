"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const config_1 = __importDefault(require("config"));
const util_1 = require("../lib/util");
const cache_instance_1 = __importDefault(require("../lib/cache-instance"));
const request_1 = __importDefault(require("request"));
function invalidateCache(req, res) {
    if (config_1.default.get('server.useOutputCache')) {
        if (!req.query.key || req.query.key !== config_1.default.get('server.invalidateCacheKey')) {
            console.error('Invalid cache invalidation key');
            util_1.apiStatus(res, 'Invalid cache invalidation key', 500);
            return;
        }
        if (req.query.tag) { // clear cache pages for specific query tag
            console.log(`Clear cache request for [${req.query.tag}]`);
            let tags = [];
            if (req.query.tag === '*') {
                tags = config_1.default.get('server.availableCacheTags');
            }
            else {
                tags = req.query.tag.split(',');
            }
            const subPromises = [];
            tags.forEach(tag => {
                if (config_1.default.get('server.availableCacheTags').indexOf(tag) >= 0 || config_1.default.get('server.availableCacheTags').find(t => {
                    return tag.indexOf(t) === 0;
                })) {
                    subPromises.push(cache_instance_1.default.invalidate(tag).then(() => {
                        console.log(`Tags invalidated successfully for [${tag}]`);
                        if (config_1.default.get('varnish.enabled')) {
                            request_1.default({
                                uri: `http://${config_1.default.get('varnish.host')}:${config_1.default.get('varnish.port')}/`,
                                method: 'BAN',
                                headers: {
                                    // I should change Tags -> tag
                                    'X-VS-Cache-Tag': tag
                                }
                            }, (err, res, body) => {
                                if (body && body.includes('200 Ban added')) {
                                    console.log(`Tags invalidated successfully for [${tag}] in the Varnish`);
                                }
                                else {
                                    console.log(body);
                                    console.error(`Couldn't ban tag: ${tag} in the Varnish`);
                                }
                            });
                        }
                    }));
                }
                else {
                    console.error(`Invalid tag name ${tag}`);
                }
            });
            Promise.all(subPromises).then(r => {
                util_1.apiStatus(res, `Tags invalidated successfully [${req.query.tag}]`, 200);
            }).catch(error => {
                util_1.apiStatus(res, error, 500);
                console.error(error);
            });
            if (config_1.default.get('server.invalidateCacheForwarding')) { // forward invalidate request to the next server in the chain
                if (!req.query.forwardedFrom && config_1.default.get('server.invalidateCacheForwardUrl')) { // don't forward forwarded requests
                    request_1.default(config_1.default.get('server.invalidateCacheForwardUrl') + req.query.tag + '&forwardedFrom=vs', {}, (err, res, body) => {
                        if (err) {
                            console.error(err);
                        }
                        try {
                            if (body && JSON.parse(body).code !== 200)
                                console.log(body);
                        }
                        catch (e) {
                            console.error('Invalid Cache Invalidation response format', e);
                        }
                    });
                }
            }
        }
        else if (config_1.default.get('varnish.enabled') && req.query.ext) {
            const exts = req.query.ext.split(',');
            for (let ext of exts) {
                request_1.default({
                    uri: `http://${config_1.default.get('varnish.host')}:${config_1.default.get('varnish.port')}/`,
                    method: 'BAN',
                    headers: {
                        'X-VS-Cache-Ext': ext
                    }
                }, (err, res, body) => {
                    if (body && body.includes('200 Ban added')) {
                        console.log(`Cache invalidated successfully for [${ext}] in the Varnish`);
                    }
                    else {
                        console.error(`Couldn't ban extension: ${ext} in the Varnish`);
                    }
                });
            }
            util_1.apiStatus(res, 'Cache invalidation succeed', 200);
        }
        else {
            util_1.apiStatus(res, 'Invalid parameters for Clear cache request', 500);
            console.error('Invalid parameters for Clear cache request');
        }
    }
    else {
        util_1.apiStatus(res, 'Cache invalidation is not required, output cache is disabled', 200);
    }
}
exports.default = invalidateCache;
//# sourceMappingURL=invalidate.js.map