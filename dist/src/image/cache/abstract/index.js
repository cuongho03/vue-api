"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
class ImageCache {
    constructor(config, req) {
        this.config = config;
        this.req = req;
        this.key = this.createKey();
    }
}
exports.default = ImageCache;
exports.ImageCache = ImageCache;
//# sourceMappingURL=index.js.map