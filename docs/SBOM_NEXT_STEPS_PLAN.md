# 🐶 SBOM Next Steps Plan — pnpm-audit-hook

**Created**: May 2025  
**Status**: All 8 phases complete, SBOM feature implemented  
**Test Suite**: 825 tests passing  
**Current State**: 10 modified files + 8 untracked SBOM files ready to commit  

---

## 📊 Current State Summary

| Metric | Value |
|--------|-------|
| **Phases Complete** | 8/8 ✅ |
| **Test Count** | 825 (all passing) |
| **Modified Files** | 10 (ready to commit) |
| **New SBOM Files** | 8 (ready to commit) |
| **SBOM Formats** | CycloneDX 1.5, SPDX 2.3 |
| **Build Status** | ✅ Clean |

---

## 📋 Phase 1: Commit SBOM Changes

**Estimated Time**: 15-30 minutes  
**Priority**: 🔴 Critical (immediate)

### Tasks

#### 1.1 Stage All Changes
- [ ] Stage modified files:
  - `README.md` (57 lines added - SBOM documentation)
  - `bin/cli.js` (65 lines - CLI SBOM support)
  - `bin/parse-args.js` (16 lines - argument parsing)
  - `docs/api/README.md` (1 line - SBOM API reference)
  - `src/audit.ts` (41 lines - SBOM integration)
  - `src/config.ts` (21 lines - SBOM config options)
  - `src/index.ts` (7 lines - exports)
  - `src/types.ts` (26 lines - SBOM types)
  - `src/utils/http.ts` (4 lines - utilities)
  - `test/cli.test.ts` (57 lines - SBOM CLI tests)
  
- [ ] Stage new untracked files:
  - `docs/api/sbom.md` (9.5KB - comprehensive SBOM API docs)
  - `src/sbom/cyclonedx-generator.ts` (9.1KB)
  - `src/sbom/index.ts` (953B - barrel export)
  - `src/sbom/spdx-generator.ts` (8.0KB)
  - `src/sbom/types.ts` (5.9KB - SBOM types)
  - `test/integration/cli/sbom.test.ts` (5.7KB - CLI integration)
  - `test/sbom/sbom.test.ts` (16.3KB - unit tests)
  - `test/sbom/schema-validator.test.ts` (7.1KB - validator tests)

#### 1.2 Verify Tests Pass
```bash
pnpm test
# Verify all 825 tests pass
```

#### 1.3 Create Commit
```bash
git add -A
git commit -m "feat(sbom): add CycloneDX and SPDX SBOM generation

- Add SBOM module with CycloneDX 1.5 and SPDX 2.3 support
- Implement CLI flags: --sbom, --sbom-format, --sbom-output
- Add comprehensive unit and integration tests (23.1KB)
- Add SBOM API documentation (9.5KB)
- Update README with SBOM generation examples
- All 825 tests passing

Closes #XXX"
```

#### 1.4 Push to Remote
```bash
git push origin main
# Push 25+ commits including SBOM feature
```

### Files Modified/Created
| File | Type | Size | Purpose |
|------|------|------|---------|
| `src/sbom/types.ts` | New | 5.9KB | SBOM type definitions |
| `src/sbom/cyclonedx-generator.ts` | New | 9.1KB | CycloneDX format |
| `src/sbom/spdx-generator.ts` | New | 8.0KB | SPDX format |
| `src/sbom/index.ts` | New | 953B | Module exports |
| `docs/api/sbom.md` | New | 9.5KB | API documentation |
| `test/sbom/sbom.test.ts` | New | 16.3KB | Unit tests |
| `test/sbom/schema-validator.test.ts` | New | 7.1KB | Validation tests |
| `test/integration/cli/sbom.test.ts` | New | 5.7KB | CLI integration tests |
| `README.md` | Modified | +57 lines | SBOM docs |
| `bin/cli.js` | Modified | +65 lines | CLI implementation |
| `bin/parse-args.js` | Modified | +16 lines | Arg parsing |
| `docs/api/README.md` | Modified | +1 line | API index |
| `src/audit.ts` | Modified | +41 lines | SBOM integration |
| `src/config.ts` | Modified | +21 lines | Config support |
| `src/index.ts` | Modified | +7 lines | Exports |
| `src/types.ts` | Modified | +26 lines | Type additions |
| `src/utils/http.ts` | Modified | +4 lines | Utilities |
| `test/cli.test.ts` | Modified | +57 lines | CLI tests |

### Success Criteria
- [ ] All 825 tests pass
- [ ] All SBOM files committed
- [ ] No TypeScript errors
- [ ] Commit message follows conventional commits
- [ ] Push successful to remote

---

## 📋 Phase 2: SBOM Integration Tests

**Estimated Time**: 3-5 hours  
**Priority**: 🟡 High

### Tasks

#### 2.1 CI/CD Integration Tests
- [ ] **GitHub Actions Test**
  - Create `.github/workflows/sbom-test.yml`
  - Test SBOM generation in CI environment
  - Verify output formats
  - Test with matrix strategy (Node 18, 20, 22)
  
  ```yaml
  name: SBOM Integration Test
  on: [push, pull_request]
  jobs:
    sbom-test:
      runs-on: ubuntu-latest
      strategy:
        matrix:
          node-version: [18, 20, 22]
      steps:
        - uses: actions/checkout@v4
        - name: Use Node.js ${{ matrix.node-version }}
          uses: actions/setup-node@v4
          with:
            node-version: ${{ matrix.node-version }}
        - run: pnpm install
        - run: pnpm test
        - name: Test SBOM Generation
          run: |
            node bin/cli.js --sbom --sbom-format cyclonedx > sbom-cdx.json
            node bin/cli.js --sbom --sbom-format spdx > sbom-spdx.json
            # Validate output
            node -e "const sbom = require('./sbom-cdx.json'); console.log('CycloneDX:', sbom.bomFormat)"
  ```

- [ ] **GitLab CI Test**
  - Create `.gitlab-ci.yml` with SBOM job
  - Test in Docker container
  - Verify artifacts

- [ ] **Jenkins Test**
  - Create `Jenkinsfile` with SBOM pipeline
  - Test in Jenkins environment

#### 2.2 End-to-End Testing
- [ ] **Real Project Testing**
  - Test with actual `pnpm-lock.yaml` files
  - Test with different dependency depths
  - Test with monorepo structures
  - Test with workspace dependencies

  ```bash
  # Create test fixture
  mkdir -p test/fixtures/projects/real-project
  cd test/fixtures/projects/real-project
  pnpm init
  pnpm add express lodash axios
  # Generate lockfile
  cd ../../..
  
  # Test SBOM generation
  node bin/cli.js --lockfile test/fixtures/projects/real-project/pnpm-lock.yaml --sbom
  ```

- [ ] **Performance Testing**
  - Benchmark SBOM generation for large projects
  - Test memory usage with 1000+ dependencies
  - Profile generation time

- [ ] **Edge Case Testing**
  - Empty lockfile handling
  - Malformed lockfile recovery
  - Circular dependency handling
  - Missing package metadata

#### 2.3 Validation Testing
- [ ] **CycloneDX Schema Validation**
  - Validate against CycloneDX 1.5 JSON Schema
  - Test BOM-Link compliance
  - Verify component metadata

- [ ] **SPDX Schema Validation**
  - Validate against SPDX 2.3 specification
  - Test license expression format
  - Verify package checksums

### Files to Create/Modify
| File | Purpose |
|------|---------|
| `.github/workflows/sbom-test.yml` | CI workflow |
| `.gitlab-ci.yml` | GitLab CI config |
| `Jenkinsfile` | Jenkins pipeline |
| `test/integration/sbom/ci-cd.test.ts` | CI/CD integration tests |
| `test/integration/sbom/e2e.test.ts` | End-to-end tests |
| `test/fixtures/projects/real-project/` | Test fixtures |
| `test/sbom/performance.test.ts` | Performance benchmarks |

### Success Criteria
- [ ] CI/CD pipelines pass for all platforms
- [ ] SBOM generation works in CI environments
- [ ] End-to-end tests with real projects pass
- [ ] Performance benchmarks meet targets (<2s for 1000 deps)
- [ ] Schema validation passes for both formats

---

## 📋 Phase 3: Enhance SBOM Features

**Estimated Time**: 8-12 hours  
**Priority**: 🟢 Medium

### Tasks

#### 3.1 Additional SBOM Formats
- [ ] **SWID Tags (ISO/IEC 19770-2)**
  - Create `src/sbom/swid-generator.ts`
  - Support Software Identification tags
  - Useful for enterprise compliance

- [ ] **CycloneDX XML Format**
  - Add XML serialization to CycloneDX generator
  - Support both JSON and XML outputs
  - Update CLI: `--sbom-format cyclonedx-xml`

- [ ] **PDF Report Generation**
  - Create human-readable PDF SBOM
  - Include dependency tree visualization
  - Add vulnerability summary charts

#### 3.2 Enhanced Validation
- [ ] **Schema Validator Improvements**
  - Add CycloneDX 1.5 JSON Schema validation
  - Add SPDX 2.3 JSON Schema validation
  - Create validation CLI command
  - Support remote schema fetching

  ```bash
  # Validate existing SBOM
  pnpm-audit-scan --validate-sbom sbom.json --format cyclonedx
  ```

- [ ] **Cross-Format Validation**
  - Compare CycloneDX vs SPDX outputs
  - Detect discrepancies
  - Generate conversion reports

#### 3.3 Dependency Graph Visualization
- [ ] **ASCII Art Dependency Tree**
  - Create `src/sbom/dependency-tree.ts`
  - Generate ASCII visualization
  - Highlight vulnerable paths

  ```
  my-project@1.0.0
  ├── express@4.18.2
  │   ├── body-parser@1.20.0
  │   │   └── bytes@3.1.2
  │   ├── cookie@0.5.0
  │   └── debug@2.6.9 ⚠️ VULNERABLE
  ├── lodash@4.17.21
  └── axios@1.4.0
      └── follow-redirects@1.15.2
  ```

- [ ] **Mermaid Diagram Support**
  - Generate Mermaid.js graphs
  - Include in Markdown documentation
  - Support GitHub/GitLab rendering

  ```bash
  pnpm-audit-scan --sbom --graph-format mermaid > dependency-graph.md
  ```

- [ ] **DOT Format for Graphviz**
  - Generate DOT language output
  - Support rendering to PNG/SVG
  - Include in CI artifacts

#### 3.4 SBOM Diffing
- [ ] **Compare SBOM Versions**
  - Create `src/sbom/diff.ts`
  - Detect added/removed/updated dependencies
  - Generate change reports

  ```bash
  # Compare two SBOMs
  pnpm-audit-scan --sbom-diff old-sbom.json new-sbom.json
  ```

### Files to Create/Modify
| File | Purpose |
|------|---------|
| `src/sbom/swid-generator.ts` | SWID Tags format |
| `src/sbom/xml-serializer.ts` | XML serialization |
| `src/sbom/pdf-reporter.ts` | PDF generation |
| `src/sbom/dependency-tree.ts` | ASCII tree |
| `src/sbom/mermaid-generator.ts` | Mermaid graphs |
| `src/sbom/dot-generator.ts` | Graphviz DOT |
| `src/sbom/diff.ts` | SBOM diffing |
| `src/sbom/schema-validator.ts` | Enhanced validation |
| `bin/cli.js` | New CLI flags |
| `test/sbom/swid.test.ts` | SWID tests |
| `test/sbom/xml.test.ts` | XML tests |
| `test/sbom/pdf.test.ts` | PDF tests |
| `test/sbom/dependency-tree.test.ts` | Tree tests |
| `test/sbom/diff.test.ts` | Diff tests |

### Success Criteria
- [ ] SWID Tags generation works
- [ ] XML format outputs valid XML
- [ ] Dependency tree renders correctly
- [ ] Mermaid diagrams are valid
- [ ] SBOM diffing detects changes
- [ ] All new tests pass

---

## 📋 Phase 4: Documentation & Examples

**Estimated Time**: 4-6 hours  
**Priority**: 🟢 Medium

### Tasks

#### 4.1 Update README
- [ ] **SBOM Quick Start Section**
  - Add prominent SBOM section to top
  - Include copy-paste examples
  - Link to detailed docs

- [ ] **SBOM Use Cases**
  - Compliance documentation
  - Security auditing
  - License management
  - Supply chain security

#### 4.2 Create Comprehensive Examples
- [ ] **Basic Examples**
  ```markdown
  ## SBOM Examples
  
  ### Generate CycloneDX SBOM
  ```bash
  pnpm-audit-scan --sbom
  ```
  
  ### Generate SPDX SBOM
  ```bash
  pnpm-audit-scan --sbom --sbom-format spdx
  ```
  
  ### Write to File
  ```bash
  pnpm-audit-scan --sbom --sbom-output sbom.json
  ```
  
  ### Include Vulnerabilities
  ```bash
  pnpm-audit-scan --sbom --include-vulnerabilities
  ```
  ```

- [ ] **Programmatic API Examples**
  ```typescript
  // examples/basic-usage.ts
  import { generateSbom, SbomFormat } from 'pnpm-audit-hook';
  
  const packages = [
    { name: 'express', version: '4.18.2' },
    { name: 'lodash', version: '4.17.21' },
  ];
  
  const findings = [
    {
      package: 'debug',
      version: '2.6.9',
      severity: 'high',
      advisory: 'GHSA-gxpj-cx7g-858c',
    },
  ];
  
  const sbom = generateSbom(packages, findings, {
    format: 'cyclonedx',
    projectName: 'my-app',
    projectVersion: '1.0.0',
  });
  
  console.log(`Generated ${sbom.componentCount} components`);
  ```

- [ ] **CI/CD Integration Examples**
  ```markdown
  ## GitHub Actions Example
  
  ```yaml
  - name: Generate SBOM
    run: pnpm-audit-scan --sbom --sbom-output sbom.json
  
  - name: Upload SBOM Artifact
    uses: actions/upload-artifact@v4
    with:
      name: sbom
      path: sbom.json
  ```
  ```

#### 4.3 Create Tutorial
- [ ] **SBOM Tutorial Document**
  - Create `docs/tutorials/sbom-quickstart.md`
  - Step-by-step guide for beginners
  - Include troubleshooting section

- [ ] **Video Script** (Optional)
  - Outline for video tutorial
  - Key points to cover
  - Demo walkthrough

#### 4.4 API Documentation Enhancements
- [ ] **Update TypeDoc Configuration**
  - Add SBOM modules to `typedoc.json`
  - Generate API reference

- [ ] **Add JSDoc Comments**
  - Document all public functions
  - Include usage examples
  - Add @param and @returns

### Files to Create/Modify
| File | Purpose |
|------|---------|
| `README.md` | Updated SBOM section |
| `examples/basic-usage.ts` | Basic example |
| `examples/ci-integration.ts` | CI/CD example |
| `examples/custom-formatter.ts` | Advanced usage |
| `docs/tutorials/sbom-quickstart.md` | Tutorial |
| `docs/guides/compliance.md` | Compliance guide |
| `docs/guides/license-management.md` | License guide |
| `typedoc.json` | Updated config |

### Success Criteria
- [ ] README has prominent SBOM section
- [ ] Examples are copy-paste ready
- [ ] Tutorial is beginner-friendly
- [ ] API docs are comprehensive
- [ ] All examples work correctly

---

## 🎯 Overall Success Metrics

| Phase | Tasks | Estimated Time | Priority |
|-------|-------|----------------|----------|
| Phase 1: Commit SBOM | 8 | 15-30 min | 🔴 Critical |
| Phase 2: Integration Tests | 12 | 3-5 hours | 🟡 High |
| Phase 3: Enhance Features | 14 | 8-12 hours | 🟢 Medium |
| Phase 4: Documentation | 10 | 4-6 hours | 🟢 Medium |
| **Total** | **44** | **15-24 hours** | - |

### Final Deliverables
- [ ] SBOM feature committed and pushed
- [ ] CI/CD integration working
- [ ] Multiple format support (CycloneDX, SPDX, SWID)
- [ ] Dependency visualization
- [ ] Comprehensive documentation
- [ ] Tutorial and examples
- [ ] All tests passing (825+)

---

## 🚀 Next Steps

1. **Immediately**: Execute Phase 1 (commit SBOM changes)
2. **Today**: Begin Phase 2 (integration tests)
3. **This Week**: Complete Phase 3 (enhance features)
4. **Next Week**: Finish Phase 4 (documentation)

---

*Plan created by Max 🐶 — Your loyal code puppy!*
