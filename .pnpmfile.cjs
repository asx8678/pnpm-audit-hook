const { createAuditHooks } = require("./src/audit-hook.cjs");

module.exports = {
  hooks: createAuditHooks(),
};
