# router-jwks-generator

**The code in this repository is experimental and has been provided for reference purposes only. Community feedback is welcome but this project may not be supported in the same way that repositories in the official [Apollo GraphQL GitHub organization](https://github.com/apollographql) are. If you need help you can file an issue on this repository, [contact Apollo](https://www.apollographql.com/contact-sales) to talk to an expert, or create a ticket directly in Apollo Studio.**

# Usage

### Requirements

- Knowledge of token signing algorithms 
- Sample JWT, if available


### Basic Usage

The tool will guide you through creating a router configuration file used with the new authentication plugin.

```sh
npx github:@apollosolutions/router-jwks-generator create-config
```

## Known Limitations

- Published only as source code to Github. Not available on NPM.
- Doesn't support the creation of local JWKS with asymmetric signing