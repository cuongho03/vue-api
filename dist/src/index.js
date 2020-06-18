"use strict";
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
const express_1 = __importDefault(require("express"));
const cors_1 = __importDefault(require("cors"));
const morgan_1 = __importDefault(require("morgan"));
const body_parser_1 = __importDefault(require("body-parser"));
const db_1 = __importDefault(require("./db"));
const middleware_1 = __importDefault(require("./middleware"));
const loadAdditionalCertificates_1 = require("./helpers/loadAdditionalCertificates");
const api_1 = __importDefault(require("./api"));
const config_1 = __importDefault(require("config"));
const img_1 = __importDefault(require("./api/img"));
const invalidate_1 = __importDefault(require("./api/invalidate"));
const apollo_server_express_1 = require("apollo-server-express");
const graphql_tools_1 = require("graphql-tools");
const resolvers_1 = __importDefault(require("./graphql/resolvers"));
const schema_1 = __importDefault(require("./graphql/schema"));
const path = __importStar(require("path"));
const app = express_1.default();
// logger
app.use(morgan_1.default('dev'));
app.use('/media', express_1.default.static(path.join(__dirname, config_1.default.get(`${config_1.default.get('platform')}.assetPath`))));
// 3rd party middleware
app.use(cors_1.default({
    exposedHeaders: config_1.default.get('corsHeaders')
}));
app.use(body_parser_1.default.json({
    limit: config_1.default.get('bodyLimit')
}));
loadAdditionalCertificates_1.loadAdditionalCertificates();
// connect to db
db_1.default(db => {
    // internal middleware
    app.use(middleware_1.default({ config: config_1.default, db }));
    // api router
    app.use('/api', api_1.default({ config: config_1.default, db }));
    app.use('/img', img_1.default({ config: config_1.default, db }));
    app.use('/img/:width/:height/:action/:image', (req, res, next) => {
        console.log(req.params);
    });
    app.post('/invalidate', invalidate_1.default);
    app.get('/invalidate', invalidate_1.default);
    const port = process.env.PORT || config_1.default.get('server.port');
    const host = process.env.HOST || config_1.default.get('server.host');
    app.listen(parseInt(port), host, () => {
        console.log(`Vue Storefront API started at http://${host}:${port}`);
    });
});
// graphQl Server part
const schema = graphql_tools_1.makeExecutableSchema({
    typeDefs: schema_1.default,
    resolvers: resolvers_1.default
});
app.use(body_parser_1.default.urlencoded({ extended: true }));
app.use(body_parser_1.default.json());
app.use('/graphql', apollo_server_express_1.graphqlExpress(req => ({
    schema,
    context: { req: req },
    rootValue: global
})));
app.use('/graphiql', apollo_server_express_1.graphiqlExpress({ endpointURL: '/graphql' }));
app.use((err, req, res, next) => {
    const { statusCode = 500, message = '', stack = '' } = err;
    const stackTrace = stack
        .split(/\r?\n/)
        .map(string => string.trim())
        .filter(string => string !== '');
    res.status(statusCode).json(Object.assign({ code: statusCode, result: message }, (config_1.default.get('server.showErrorStack') ? { stack: stackTrace } : {})));
});
exports.default = app;
//# sourceMappingURL=index.js.map