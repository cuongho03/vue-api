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
const abstract_1 = __importDefault(require("../abstract"));
const fs_extra_1 = __importDefault(require("fs-extra"));
const crypto_1 = require("crypto");
class FileImageCache extends abstract_1.default {
    getImageFromCache() {
        return __awaiter(this, void 0, void 0, function* () {
            this.image = yield fs_extra_1.default.readFile(`${this.config.imageable.caching.file.path}/${this.path}`);
        });
    }
    save() {
        return __awaiter(this, void 0, void 0, function* () {
            yield fs_extra_1.default.outputFile(`${this.config.imageable.caching.file.path}/${this.path}`, this.image);
        });
    }
    check() {
        return __awaiter(this, void 0, void 0, function* () {
            const response = yield fs_extra_1.default.pathExists(`${this.config.imageable.caching.file.path}/${this.path}`);
            return response;
        });
    }
    get path() {
        return `${this.key.substring(0, 2)}/${this.key.substring(2, 4)}/${this.key}`;
    }
    createKey() {
        console.log(crypto_1.createHash('md5').update(this.req.url).digest('hex'));
        return crypto_1.createHash('md5').update(this.req.url).digest('hex');
    }
    isValidFor(type) {
        return type === 'file';
    }
}
exports.default = FileImageCache;
//# sourceMappingURL=index.js.map