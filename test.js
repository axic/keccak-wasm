const fs = require('fs')
const wasm = fs.readFileSync('./keccak.wasm')

WebAssembly.compile(wasm).then(module => {
  // memory imports still don't work correctly
  // const toHash = new Buffer(2000).fill(0)
  // const memory = new WebAssembly.Memory(toHash.buffer)
  // const importObj = {
  //     memory: memory
  // }

  const instance = new WebAssembly.Instance(module)
  instance.exports.keccak(168, 0, 136, 136)
  // instance.exports.init(0)
  const buffer = instance.exports.memory.buffer
  const result = Buffer.from(buffer, 136, 32)
  // output (keccak-256): 3a5912a7c5faa06ee4fe906253e339467a9ce87d533c65be3c15cb231cdb25f9
  console.log(result.toString('hex'))
})

