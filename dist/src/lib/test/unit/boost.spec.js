"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const boost_1 = __importDefault(require("../../boost"));
describe('getBoosts method', () => {
    describe('with empty boost config', () => {
        beforeEach(() => {
            jest.mock('config', () => ({}));
        });
        it('Should return 1', () => {
            const result = boost_1.default('color');
            expect(result).toEqual(1);
        });
    });
    describe('with boost config', () => {
        beforeEach(() => {
            jest.mock('config', () => ({
                boost: {
                    name: 3
                }
            }));
        });
        it('color not in config and should be 1', () => {
            const result = boost_1.default('color');
            expect(result).toEqual(1);
        });
        it('name is in config and should be 3', () => {
            const result = boost_1.default('name');
            expect(result).toEqual(3);
        });
    });
});
//# sourceMappingURL=boost.spec.js.map