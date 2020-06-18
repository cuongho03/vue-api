"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const config_1 = __importDefault(require("config"));
const factory_1 = __importDefault(require("../../../processor/factory"));
function esResultsProcessor(response, esRequest, entityType, indexName) {
    return new Promise((resolve, reject) => {
        const factory = new factory_1.default(config_1.default);
        let resultProcessor = factory.getAdapter(entityType, indexName, esRequest, response);
        if (!resultProcessor) {
            resultProcessor = factory.getAdapter('default', indexName, esRequest, response); // get the default processor
        }
        resultProcessor.process(response.body.hits.hits)
            .then((result) => {
            resolve(result);
        })
            .catch((err) => {
            console.error(err);
        });
    });
}
exports.default = esResultsProcessor;
//# sourceMappingURL=processor.js.map