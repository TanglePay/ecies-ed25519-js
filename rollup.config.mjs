import {createRollupConfig, decorateIifeExternal} from "./template/rollup.config.mjs";
import pkg from './package.json' assert { type: "json" }

const config = createRollupConfig(pkg)
decorateIifeExternal(config[0],{
    '@iota/crypto.js':'IotaCrypto'
})
  export default config