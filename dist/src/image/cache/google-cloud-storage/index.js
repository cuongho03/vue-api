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
const crypto_1 = require("crypto");
const storage_1 = require("@google-cloud/storage");
class GoogleCloudStorageImageCache extends abstract_1.default {
    constructor(config, req) {
        super(config, req);
        if (GoogleCloudStorageImageCache.storage === undefined) {
            GoogleCloudStorageImageCache.storage = new storage_1.Storage(this.moduleConfig.libraryOptions);
        }
        if (GoogleCloudStorageImageCache.bucket === undefined) {
            GoogleCloudStorageImageCache.bucket = GoogleCloudStorageImageCache.storage.bucket(this.bucketName);
        }
    }
    get bucketName() {
        return this.moduleConfig.bucket;
    }
    get moduleConfig() {
        return this.config.imageable.caching[`google-cloud-storage`];
    }
    getImageFromCache() {
        return __awaiter(this, void 0, void 0, function* () {
            const donwload = yield GoogleCloudStorageImageCache.bucket.file('testing/cache/image/' + this.key).download();
            this.image = donwload[0];
        });
    }
    save() {
        return __awaiter(this, void 0, void 0, function* () {
            yield GoogleCloudStorageImageCache.bucket.file('testing/cache/image/' + this.key).save(this.image, {
                gzip: true
            });
        });
    }
    check() {
        return __awaiter(this, void 0, void 0, function* () {
            const response = yield GoogleCloudStorageImageCache.bucket.file('testing/cache/image/' + this.key).exists();
            return response[0];
        });
    }
    createKey() {
        return crypto_1.createHash('md5').update(this.req.url).digest('hex');
    }
    isValidFor(type) {
        return type === 'google-cloud-storage';
    }
}
exports.default = GoogleCloudStorageImageCache;
//# sourceMappingURL=index.js.map