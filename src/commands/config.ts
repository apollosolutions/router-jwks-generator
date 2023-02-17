import { Command, Option } from 'clipanion';
import { JsonWebKey } from 'crypto';
import inquirer from 'inquirer';
import { decode, Jwt, Algorithm, JwtPayload } from 'jsonwebtoken';
import { writeFileSync, existsSync } from 'fs';
import writeYamlFile from 'write-yaml-file';
// @ts-ignore
import loadYamlFile from 'load-yaml-file';
import { URL } from 'url';

export default class ConfigCommand extends Command {
  static paths = [['configure']];
  config = Option.String('-c,--config')

  static usage = Command.Usage({
    category: 'Create',
    description:
      'Guides you through creation of JWKS via either explicit configuration or by using a sample JWT',
    examples: [['Basic usage', '$0 configure'], ['Modifying existing configuration file', '$0 configure --config <config_path>']],
  });

  async execute(): Promise<number | void> {
    if (this.config !== undefined && !existsSync(this.config)) {
      this.context.stdout.write(`Error reading config. Ensure the file exists and try again.\n`)
      return 1
    }

    const { hasJWT } = await inquirer.prompt({
      type: 'confirm',
      name: 'hasJWT',
      default: false,
      message: 'Do you have a sample JWT?',
    });

    let algorithm: Algorithm = 'none';
    let keyID: String | undefined;
    let symmetric = false;
    let jwksUrl = '';

    // 

    // 
    if (hasJWT) {
      const { jwt } = await inquirer.prompt({
        type: 'input',
        name: 'jwt',
        message: 'Enter sample JWT here:',
        validate: async (jwtInput) => {
          if (decode(jwtInput, { complete: true })) {
            return true;
          }
          throw new Error('Invalid JWT');
        },
      });

      // we already validated that the token was successfully decoded, but coercing TS to respect that
      //@ts-ignore
      const decoded: Jwt = decode(jwt, { complete: true });

      const { alg, kid } = decoded.header;
      keyID = kid;
      algorithm = alg as Algorithm;

      if ((decoded.payload as JwtPayload).iss) {
        let { iss } = decoded.payload as JwtPayload

        if (!isAlgorithmSymmetric(algorithm)[0] && iss) {
          // let's handle the common IdPs to make it real easy for folks
          if (iss.includes('auth0')) {
            jwksUrl = iss += '.well-known/jwks.json'
            this.context.stdout.write(`It appears you are using Auth0, so we've set your JWKS URL to ${jwksUrl}\n`)
          } else if (iss.includes('okta')) {
            // https://developer.okta.com/docs/guides/validate-access-tokens/dotnet/main/
            jwksUrl = iss += "/v1/keys"
            this.context.stdout.write(`It appears you are using Okta, so we've set your JWKS URL to ${jwksUrl}\n`)
          }
        }

      }
    }

    if (algorithm === 'none') {
      const { alg } = await inquirer.prompt({
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
    [symmetric, message] = isAlgorithmSymmetric(algorithm)

    this.context.stdout.write(message)

    let hasJWKSEndpoint = !!jwksUrl

    if (!jwksUrl) {
      this.context.stdout.write("In the router, you'll be given an option to either use a local file or hosted JWKS. For asymmetric key signing, we'd recommend using a hosted JWKS, such as those provided by IdPs such as Auth0 or Okta. For symmetric tokens, we'd recommend a local file which can be crafted with this tool. To do so, select no and have the signing key available to paste.\n")
      let res = await inquirer.prompt({
        type: 'confirm',
        name: 'hasJWKSEndpoint',
        message:
          'Do you have the JWKS endpoint that can validate your token? If you do not have a JWKS endpoint, enter no.',
      });
      hasJWKSEndpoint = res.hasJWKSEndpoint
    }


    if (symmetric && !jwksUrl) {
      const { hasKey } = await inquirer.prompt({
        type: 'confirm',
        name: 'hasKey',
        message: 'Do you have the signing key available?',
      });
      if (!hasKey) {
        this.context.stdout.write(
          `To create a valid JWKS file for a symmetric key, you will need either a JWKS endpoint or token signing key.\n`,
        );
        return 1;
      }
      // eslint-disable-next-line
      let { isBase64Encoded, signingKey } = await inquirer.prompt([
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

      const jwk: JsonWebKey = {
        alg: algorithm,
        k: signingKey,
        use: 'sig',
        kty: 'oct',
      };
      if (!keyID) {
        this.context.stdout.write(
          "No key ID identified, will omit 'kid' from resulting JWKS file.\n",
        );
      } else {
        jwk.kid = keyID;
      }
      const jwks = {
        keys: [jwk],
      };

      writeFileSync('jwks.json', JSON.stringify(jwks));
      // eslint-disable-next-line
      jwksUrl = 'file://${env.PWD}/jwks.json';
    } else if (!symmetric && !jwksUrl) {
      // currently unsupported, so throw error with message
      this.context.stdout.write(
        'Asymmetric keys using a local JWKS file not currently supported by this tool, however it is possible to craft one manually\n',
      );
      return 1;
    } else if (!jwksUrl) {
      const { userJwksUrl } = await inquirer.prompt({
        type: 'input',
        name: 'userJwksUrl',
        message: 'Enter JWKS endpoint here:',
        validate: (userJwksUrlInput) =>
          new Promise((res, rej) => {
            try {
              // eslint-disable-next-line
              new URL(userJwksUrlInput);
              res(true);
            } catch (error) {
              rej(new Error('Invalid URL'));
            }
          }),
      });

      jwksUrl = userJwksUrl;
    }
    if (!jwksUrl) {
      this.context.stdout.write(
        'Missing JWKS URL (local file or hosted)- exiting.\n',
      );
      return 1;
    }

    let yaml: object = {}
    if (this.config) {
      yaml = await loadYamlFile(this.config) as object
    }

    writeYamlFile(this.config ?? 'router.yaml', {
      ...yaml,
      authentication: {
        experimental: {
          jwt: {
            jwks_urls: [jwksUrl],
          },
        },
      },
    });

    this.context.stdout.write(
      `Finished creating file${!hasJWKSEndpoint ? 's' : ''
      }. Output to router.yaml${!hasJWKSEndpoint ? ' and jwks.json' : ''}\n`,
    );
    return 0;
  }
}

const isAlgorithmSymmetric = (algorithm: Algorithm): [boolean, string] => {
  switch (algorithm) {
    case 'HS256':
    case 'HS384':
    case 'HS512':
      return [true, `It appears you are using an HMAC hash for symmetric token signing.\n`]
    case 'ES256':
    case 'ES384':
    case 'ES512':
      return [false, `It appears you are using an Elliptic Curve Digital Signature Algorithm (ECDSA) signing key for asymmetric token signing.\n`,]
    case 'RS256':
    case 'RS384':
    case 'RS512':
      return [false, `It appears you are using an RSA-based signing key for asymmetric token signing.\n`]
    case 'PS256':
    case 'PS384':
    case 'PS512':
      return [false, `It appears you are using an RSASSA-PSS signing key for asymmetric token signing.\n`]
    default:
      return [false, `Unable to determine JWT algorithm. Please ensure the JWT is formatted correctly and try again.\n`]
  }
}