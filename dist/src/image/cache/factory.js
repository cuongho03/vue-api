'use strict';
Object.defineProperty(exports, "__esModule", { value: true });
class CacheFactory {
    constructor(app_config, req) {
        this.config = app_config;
        this.request = req;
    }
    getAdapter(type, ...constructorParams) {
        let AdapterClass = require(`./${type}`).default;
        if (!AdapterClass) {
            throw new Error(`Invalid adapter ${type}`);
        }
        else {
            const adapterInstance = new AdapterClass(this.config, this.request);
            if ((typeof adapterInstance.isValidFor === 'function') && !adapterInstance.isValidFor(type)) {
                throw new Error(`Not valid adapter class or adapter is not valid for ${type}`);
            }
            return adapterInstance;
        }
    }
}
exports.default = CacheFactory;
exports.CacheFactory = CacheFactory;
//# sourceMappingURL=factory.js.map