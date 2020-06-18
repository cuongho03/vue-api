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
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result["default"] = mod;
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
const path_1 = __importDefault(require("path"));
function loadModuleCustomFilters(config, type = 'catalog') {
    return __awaiter(this, void 0, void 0, function* () {
        let filters = {};
        let filterPromises = [];
        for (const mod of config.registeredExtensions) {
            if (config.extensions.hasOwnProperty(mod) && config.extensions[mod].hasOwnProperty(type + 'Filter') && Array.isArray(config.extensions[mod][type + 'Filter'])) {
                const moduleFilter = config.extensions[mod][type + 'Filter'];
                const dirPath = [__dirname, '../api/extensions/' + mod + '/filter/', type];
                for (const filterName of moduleFilter) {
                    const filePath = path_1.default.resolve(...dirPath, filterName);
                    filterPromises.push(Promise.resolve().then(() => __importStar(require(filePath))).then(module => {
                        filters[filterName] = module.default;
                    })
                        .catch(e => {
                        console.log(e);
                    }));
                }
            }
        }
        return Promise.all(filterPromises).then((e) => filters);
    });
}
exports.default = loadModuleCustomFilters;
//# sourceMappingURL=loadCustomFilters.js.map