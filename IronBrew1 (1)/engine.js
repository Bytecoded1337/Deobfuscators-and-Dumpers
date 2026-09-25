const fs = require('fs');
const { detect, extractRootChunk } = require('./Utils/io');
const { reconProg } = require('./Utils/out');

const OUT_HDR = '--ironbrew1 ezz lox\n--nigalllah ALLAH ALLAHHHHH\n\n';

function deobf(source) {
  const rootChunk = extractRootChunk(source);
  const code = reconProg(rootChunk);
  const full = OUT_HDR + code;
  return {
    lua: full,
    constants: rootChunk.constants,
    instructions: rootChunk.instructions,
    chunk: rootChunk,
  };
}

if (require.main === module) {
  const filePath = process.argv[2];
  const action = process.argv[3] || 'decompile';
  if (!filePath) {
    console.error('Usage: node engine.js <file> [decompile|constants]');
    process.exit(1);
  }
  const source = fs.readFileSync(filePath, 'utf8');
  try {
    const res = deobf(source);
    if (action === 'constants') {
      console.log(JSON.stringify(res.constants));
    } else {
      process.stdout.write(res.lua);
    }
  } catch (err) {
    console.error(err);
    process.exit(1);
  }
}

module.exports = {
  detect,
  deobf,
};