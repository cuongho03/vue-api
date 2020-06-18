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
// @ts-check
const factory_1 = __importDefault(require("../image/cache/factory"));
const factory_2 = __importDefault(require("../image/action/factory"));
const asyncMiddleware = fn => (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
};
exports.default = ({ config, db }) => asyncMiddleware((req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
    if (!(req.method === 'GET')) {
        res.set('Allow', 'GET');
        return res.status(405).send('Method Not Allowed');
    }
    const cacheFactory = new factory_1.default(config, req);
    req.socket.setMaxListeners(config.imageable.maxListeners || 50);
    let imageBuffer;
    const actionFactory = new factory_2.default(req, res, next, config);
    const imageAction = actionFactory.getAdapter(config.imageable.action.type);
    imageAction.getOption();
    imageAction.validateOptions();
    imageAction.isImageSourceHostAllowed();
    imageAction.validateMIMEType();
    const cache = cacheFactory.getAdapter(config.imageable.caching.type);
    if (config.imageable.caching.active && (yield cache.check())) {
        yield cache.getImageFromCache();
        imageBuffer = cache.image;
    }
    else {
        yield imageAction.prossesImage();
        if (config.imageable.caching.active) {
            cache.image = imageAction.imageBuffer;
            yield cache.save();
        }
        imageBuffer = imageAction.imageBuffer;
    }
    if (res.headersSent) {
        return;
    }
    return res
        .type(imageAction.mimeType)
        .set({ 'Cache-Control': `max-age=${imageAction.maxAgeForResponse}` })
        .send(imageBuffer);
}));
//# sourceMappingURL=img.js.map