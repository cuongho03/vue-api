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
const mime_types_1 = __importDefault(require("mime-types"));
const image_1 = require("../../../lib/image");
class LocalImageAction extends abstract_1.default {
    constructor() {
        super(...arguments);
        this.SUPPORTED_MIMETYPES = ['image/gif', 'image/png', 'image/jpeg', 'image/webp', 'image/svg+xml'];
    }
    get whitelistDomain() {
        return this.options.imageable.whitelist;
    }
    get maxAgeForResponse() {
        return 31557600000;
    }
    getImageURL() {
        return this.imageOptions.imgUrl;
    }
    getOption() {
        let imgUrl;
        let width;
        let height;
        let action;
        if (this.req.query.url) { // url provided as the query param
            imgUrl = decodeURIComponent(this.req.query.url);
            width = parseInt(this.req.query.width);
            height = parseInt(this.req.query.height);
            action = this.req.query.action;
        }
        else {
            let urlParts = this.req.url.split('/');
            width = parseInt(urlParts[1]);
            height = parseInt(urlParts[2]);
            action = urlParts[3];
            imgUrl = `${this.options[this.options.platform].imgUrl}/${urlParts.slice(4).join('/')}`; // full original image url
            if (urlParts.length < 5) {
                this.res.status(400).send({
                    code: 400,
                    result: 'Please provide following parameters: /img/<type>/<width>/<height>/<action:fit,resize,identify>/<relative_url>'
                });
                this.next();
            }
        }
        this.imageOptions = {
            imgUrl,
            width,
            height,
            action
        };
    }
    validateOptions() {
        const { width, height, action } = this.imageOptions;
        if (isNaN(width) || isNaN(height) || !this.SUPPORTED_ACTIONS.includes(action)) {
            return this.res.status(400).send({
                code: 400,
                result: 'Please provide following parameters: /img/<type>/<width>/<height>/<action:fit,resize,identify>/<relative_url> OR ?url=&width=&height=&action='
            });
        }
        if (width > this.options.imageable.imageSizeLimit || width < 0 || height > this.options.imageable.imageSizeLimit || height < 0) {
            return this.res.status(400).send({
                code: 400,
                result: `Width and height must have a value between 0 and ${this.options.imageable.imageSizeLimit}`
            });
        }
    }
    validateMIMEType() {
        const mimeType = mime_types_1.default.lookup(this.imageOptions.imgUrl);
        if (mimeType === false || !this.SUPPORTED_MIMETYPES.includes(mimeType)) {
            return this.res.status(400).send({
                code: 400,
                result: 'Unsupported file type'
            });
        }
        this.mimeType = mimeType;
    }
    prossesImage() {
        return __awaiter(this, void 0, void 0, function* () {
            const { imgUrl } = this.imageOptions;
            try {
                this.imageBuffer = yield image_1.downloadImage(imgUrl);
            }
            catch (err) {
                return this.res.status(400).send({
                    code: 400,
                    result: `Unable to download the requested image ${imgUrl}`
                });
            }
            const { action, width, height } = this.imageOptions;
            switch (action) {
                case 'resize':
                    this.imageBuffer = yield image_1.resize(this.imageBuffer, width, height);
                    break;
                case 'fit':
                    this.imageBuffer = yield image_1.fit(this.imageBuffer, width, height);
                    break;
                case 'identify':
                    this.imageBuffer = yield image_1.identify(this.imageBuffer);
                    break;
                default:
                    throw new Error('Unknown action');
            }
        });
    }
}
exports.default = LocalImageAction;
//# sourceMappingURL=index.js.map