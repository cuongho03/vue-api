"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const filter = {
    priority: 1,
    check: ({ operator, value, attribute, queryChain }) => attribute === 'custom-filter-name',
    filter({ value, attribute, operator, queryChain }) {
        // Do you custom filter logic like: queryChain.filter('terms', attribute, value)
        return queryChain;
    },
    mutator: (value) => typeof value !== 'object' ? { 'in': [value] } : value
};
exports.default = filter;
//# sourceMappingURL=SampleFilter.js.map