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
const clipanion_1 = require("clipanion");
const inquirer_1 = __importDefault(require("inquirer"));
const jsonwebtoken_1 = require("jsonwebtoken");
const fs_1 = require("fs");
const write_yaml_file_1 = __importDefault(require("write-yaml-file"));
// @ts-ignore
const load_yaml_file_1 = __importDefault(require("load-yaml-file"));
const url_1 = require("url");
class ConfigCommand extends clipanion_1.Command {
    constructor() {
        super(...arguments);
        this.config = clipanion_1.Option.String('-c,--config');
    }
    execute() {
        var _a;
        return __awaiter(this, void 0, void 0, function* () {
            if (this.config !== undefined && !(0, fs_1.existsSync)(this.config)) {
                this.context.stdout.write(`Error reading config. Ensure the file exists and try again.\n`);
                return 1;
            }
            const { hasJWT } = yield inquirer_1.default.prompt({
                type: 'confirm',
                name: 'hasJWT',
                default: false,
                message: 'Do you have a sample JWT?',
            });
            let algorithm = 'none';
            let keyID;
            let symmetric = false;
            let jwksUrl = '';
            // 
            // 
            if (hasJWT) {
                const { jwt } = yield inquirer_1.default.prompt({
                    type: 'input',
                    name: 'jwt',
                    message: 'Enter sample JWT here:',
                    validate: (jwtInput) => __awaiter(this, void 0, void 0, function* () {
                        if ((0, jsonwebtoken_1.decode)(jwtInput, { complete: true })) {
                            return true;
                        }
                        throw new Error('Invalid JWT');
                    }),
                });
                // we already validated that the token was successfully decoded, but coercing TS to respect that
                //@ts-ignore
                const decoded = (0, jsonwebtoken_1.decode)(jwt, { complete: true });
                const { alg, kid } = decoded.header;
                keyID = kid;
                algorithm = alg;
                if (decoded.payload.iss) {
                    let { iss } = decoded.payload;
                    if (!isAlgorithmSymmetric(algorithm)[0] && iss) {
                        // let's handle the common IdPs to make it real easy for folks
                        if (iss.includes('auth0')) {
                            jwksUrl = iss += '.well-known/jwks.json';
                            this.context.stdout.write(`It appears you are using Auth0, so we've set your JWKS URL to ${jwksUrl}\n`);
                        }
                        else if (iss.includes('okta')) {
                            // https://developer.okta.com/docs/guides/validate-access-tokens/dotnet/main/
                            jwksUrl = iss += "/v1/keys";
                            this.context.stdout.write(`It appears you are using Okta, so we've set your JWKS URL to ${jwksUrl}\n`);
                        }
                    }
                }
            }
            if (algorithm === 'none') {
                const { alg } = yield inquirer_1.default.prompt({
                    type: 'list',
                    name: 'alg',
                    message: 'What algorithm do you use to sign your tokens?',
                    choices: [
                        'HS256',
                        'HS384',
                        'HS512',
                        'RS256',
                        'RS384',
                        'RS512',
                        'ES256',
                        'ES384',
                        'ES512',
                        'PS256',
                        'PS384',
                        'PS512',
                    ],
                });
                algorithm = alg;
            }
            let message = "";
            [symmetric, message] = isAlgorithmSymmetric(algorithm);
            this.context.stdout.write(message);
            let hasJWKSEndpoint = !!jwksUrl;
            if (!jwksUrl) {
                this.context.stdout.write("In the router, you'll be given an option to either use a local file or hosted JWKS. For asymmetric key signing, we'd recommend using a hosted JWKS, such as those provided by IdPs such as Auth0 or Okta. For symmetric tokens, we'd recommend a local file which can be crafted with this tool. To do so, select no and have the signing key available to paste.\n");
                let res = yield inquirer_1.default.prompt({
                    type: 'confirm',
                    name: 'hasJWKSEndpoint',
                    message: 'Do you have the JWKS endpoint that can validate your token? If you do not have a JWKS endpoint, enter no.',
                });
                hasJWKSEndpoint = res.hasJWKSEndpoint;
            }
            if (symmetric && !jwksUrl) {
                const { hasKey } = yield inquirer_1.default.prompt({
                    type: 'confirm',
                    name: 'hasKey',
                    message: 'Do you have the signing key available?',
                });
                if (!hasKey) {
                    this.context.stdout.write(`To create a valid JWKS file for a symmetric key, you will need either a JWKS endpoint or token signing key.\n`);
                    return 1;
                }
                // eslint-disable-next-line
                let { isBase64Encoded, signingKey } = yield inquirer_1.default.prompt([
                    {
                        type: 'password',
                        name: 'signingKey',
                        message: 'Please provide the signing key here.',
                    },
                    {
                        type: 'confirm',
                        name: 'isBase64Encoded',
                        message: 'Is the key base64 encoded?',
                    },
                ]);
                if (!isBase64Encoded) {
                    signingKey = Buffer.from(signingKey).toString('base64');
                }
                const jwk = {
                    alg: algorithm,
                    k: signingKey,
                    use: 'sig',
                    kty: 'oct',
                };
                if (!keyID) {
                    this.context.stdout.write("No key ID identified, will omit 'kid' from resulting JWKS file.\n");
                }
                else {
                    jwk.kid = keyID;
                }
                const jwks = {
                    keys: [jwk],
                };
                (0, fs_1.writeFileSync)('jwks.json', JSON.stringify(jwks));
                // eslint-disable-next-line
                jwksUrl = 'file://${env.PWD}/jwks.json';
            }
            else if (!symmetric && !jwksUrl) {
                // currently unsupported, so throw error with message
                this.context.stdout.write('Asymmetric keys using a local JWKS file not currently supported by this tool, however it is possible to craft one manually\n');
                return 1;
            }
            else if (!jwksUrl) {
                const { userJwksUrl } = yield inquirer_1.default.prompt({
                    type: 'input',
                    name: 'userJwksUrl',
                    message: 'Enter JWKS endpoint here:',
                    validate: (userJwksUrlInput) => new Promise((res, rej) => {
                        try {
                            // eslint-disable-next-line
                            new url_1.URL(userJwksUrlInput);
                            res(true);
                        }
                        catch (error) {
                            rej(new Error('Invalid URL'));
                        }
                    }),
                });
                jwksUrl = userJwksUrl;
            }
            if (!jwksUrl) {
                this.context.stdout.write('Missing JWKS URL (local file or hosted)- exiting.\n');
                return 1;
            }
            let yaml = {};
            if (this.config) {
                yaml = (yield (0, load_yaml_file_1.default)(this.config));
            }
            (0, write_yaml_file_1.default)((_a = this.config) !== null && _a !== void 0 ? _a : 'router.yaml', Object.assign(Object.assign({}, yaml), { authentication: {
                    experimental: {
                        jwt: {
                            jwks_urls: [jwksUrl],
                        },
                    },
                } }));
            this.context.stdout.write(`Finished creating file${!hasJWKSEndpoint ? 's' : ''}. Output to router.yaml${!hasJWKSEndpoint ? ' and jwks.json' : ''}\n`);
            return 0;
        });
    }
}
exports.default = ConfigCommand;
ConfigCommand.paths = [['configure']];
ConfigCommand.usage = clipanion_1.Command.Usage({
    category: 'Create',
    description: 'Guides you through creation of JWKS via either explicit configuration or by using a sample JWT',
    examples: [['Basic usage', '$0 configure'], ['Modifying existing configuration file', '$0 configure --config <config_path>']],
});
const isAlgorithmSymmetric = (algorithm) => {
    switch (algorithm) {
        case 'HS256':
        case 'HS384':
        case 'HS512':
            return [true, `It appears you are using an HMAC hash for symmetric token signing.\n`];
        case 'ES256':
        case 'ES384':
        case 'ES512':
            return [false, `It appears you are using an Elliptic Curve Digital Signature Algorithm (ECDSA) signing key for asymmetric token signing.\n`,];
        case 'RS256':
        case 'RS384':
        case 'RS512':
            return [false, `It appears you are using an RSA-based signing key for asymmetric token signing.\n`];
        case 'PS256':
        case 'PS384':
        case 'PS512':
            return [false, `It appears you are using an RSASSA-PSS signing key for asymmetric token signing.\n`];
        default:
            return [false, `Unable to determine JWT algorithm. Please ensure the JWT is formatted correctly and try again.\n`];
    }
};
