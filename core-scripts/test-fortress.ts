import { ClaudeProvenanceRenderer } from "./new/pact.js";
import { VisionConnector } from "./vision.js";
import { ContextResult } from "./types.js";

async function testProvenance() {
  console.log("Testing ClaudeProvenanceRenderer...");
  const mockContext: ContextResult = {
    query: "test",
    chunks: [
      { text: "Fact A", _src: "source1" },
      { text: "Fact B", _src: "source2" }
    ],
    tokensUsed: 100,
    sources: ["source1", "source2"],
    totalRows: 2,
    packedRows: 2,
    citations: [
      { hash: "hash1", dbPath: "/path1", recency: 1.0, originalIndex: 0 },
      { hash: "hash2", dbPath: "/path2", recency: 0.9, originalIndex: 1 }
    ]
  };

  const answer = "According to [1], Fact A is true. Also [2] says Fact B.";
  const provenance = ClaudeProvenanceRenderer.render(answer, mockContext);

  if (provenance["[1]"] && provenance["[1]"].hash === "hash1") {
    console.log("  ✓ Citation [1] mapped correctly.");
  } else {
    console.error("  ✖ Citation [1] mapping failed:", provenance["[1]"]);
    throw new Error("Citation [1] mapping failed");
  }

  if (provenance["[2]"] && provenance["[2]"].hash === "hash2") {
    console.log("  ✓ Citation [2] mapped correctly.");
  } else {
    console.error("  ✖ Citation [2] mapping failed:", provenance["[2]"]);
    throw new Error("Citation [2] mapping failed");
  }
}

async function testVision() {
  console.log("Testing VisionConnector...");
  const vision = new VisionConnector();
  if (await vision.discover()) {
    console.log("  ✓ Vision discovery success (macOS)");
    const rows = await vision.read("test scan");
    console.log(`  ✓ Vision read: ${rows.length} rows found.`);
    if (rows.length > 0) {
      console.log("    Sample row:", rows[0].ocr_result);
    }
  } else {
    console.log("  ~ Vision discovery skipped (non-macOS)");
  }
}

async function main() {
  console.log("--- LDP Fortress Hardening: Unit Tests ---\n");
  try {
    await testProvenance();
    await testVision();
    console.log("\nLDP Fortress Unit Tests Passed.");
  } catch (e) {
    console.error("\nLDP Fortress Unit Tests Failed:", e);
    process.exit(1);
  }
}

main();
