import ts from "typescript";

// Vitest's ordinary transformation launches esbuild. Keep compilation in
// process, without changing the sandbox's rejection of UNIX socket pairs.
export default {
  esbuild: false,
  server: { host: "127.0.0.1" },
  resolve: { alias: { "@": new URL("./src", import.meta.url).pathname } },
  plugins: [{
    name: "local-defense-transpile",
    enforce: "post",
    configResolved(config) {
      for (const env of Object.values(config.environments)) {
        env.keepProcessEnv = true;
        if (env.define?.["process.env.NODE_ENV"] === "process.env.NODE_ENV") {
          delete env.define["process.env.NODE_ENV"];
        }
      }
    },
    transform(source, file) {
      if (!file.endsWith(".ts") && !file.endsWith(".tsx")) return null;
      return ts.transpileModule(source, {
        fileName: file,
        compilerOptions: {
          module: ts.ModuleKind.ESNext,
          target: ts.ScriptTarget.ES2022,
          jsx: ts.JsxEmit.ReactJSX,
        },
      }).outputText;
    },
  }],
};
