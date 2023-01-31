import { Builtins, Cli } from 'clipanion';
import { CreateCommand } from './commands';

const cli = new Cli({
  binaryLabel: 'Apollo Operation Collection Tester',
  binaryName: 'npx github:@apollosolutions/router-jwks-generator',
  binaryVersion: '0.0.1',
});

/* eslint-disable no-unused-vars */
const [_, __, ...args] = process.argv;

cli.register(CreateCommand);
cli.register(Builtins.HelpCommand);
cli.runExit(args);
