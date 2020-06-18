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
const sharp_1 = __importDefault(require("sharp"));
const request_promise_native_1 = __importDefault(require("request-promise-native"));
const config_1 = __importDefault(require("config"));
sharp_1.default.cache(config_1.default.imageable.cache);
sharp_1.default.concurrency(config_1.default.imageable.concurrency);
sharp_1.default.counters(config_1.default.imageable.counters);
sharp_1.default.simd(config_1.default.imageable.simd);
function downloadImage(url) {
    return __awaiter(this, void 0, void 0, function* () {
        const response = yield request_promise_native_1.default.get(url, { encoding: null });
        return response;
    });
}
exports.downloadImage = downloadImage;
function identify(buffer) {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            const transformer = sharp_1.default(buffer);
            return transformer.metadata();
        }
        catch (err) {
            console.log(err);
        }
    });
}
exports.identify = identify;
function resize(buffer, width, height) {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            const transformer = sharp_1.default(buffer);
            if (width || height) {
                const options = {
                    withoutEnlargement: true,
                    fit: sharp_1.default.fit.inside
                };
                transformer.resize(width, height, options);
            }
            return transformer.toBuffer();
        }
        catch (err) {
            console.log(err);
        }
    });
}
exports.resize = resize;
function fit(buffer, width, height) {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            const transformer = sharp_1.default(buffer);
            if (width || height) {
                transformer.resize(width, height, { fit: sharp_1.default.fit.cover });
            }
            return transformer.toBuffer();
        }
        catch (err) {
            console.log(err);
        }
    });
}
exports.fit = fit;
function crop(buffer, width, height, x, y) {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            const transformer = sharp_1.default(buffer);
            if (width || height || x || y) {
                transformer.extract({ left: x, top: y, width, height });
            }
            return transformer.toBuffer();
        }
        catch (err) {
            console.log(err);
        }
    });
}
exports.crop = crop;
//# sourceMappingURL=image.js.map