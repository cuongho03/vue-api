'use strict';
Object.defineProperty(exports, "__esModule", { value: true });
class ActionFactory {
    constructor(req, res, next, app_config) {
        this.request = req;
        this.response = res;
        this.next = next;
        this.config = app_config;
    }
    getAdapter(type) {
        let AdapterClass = require(`./${type}`).default;
        if (!AdapterClass) {
            throw new Error(`Invalid adapter ${type}`);
        }
        else {
            let adapter_instance = new AdapterClass(this.request, this.response, this.next, this.config);
            if ((typeof adapter_instance.isValidFor === 'function') && !adapter_instance.isValidFor(type)) {
                throw new Error(`Not valid adapter class or adapter is not valid for ${type}`);
            }
            return adapter_instance;
        }
    }
}
exports.default = ActionFactory;
exports.ActionFactory = ActionFactory;
//# sourceMappingURL=factory.js.map