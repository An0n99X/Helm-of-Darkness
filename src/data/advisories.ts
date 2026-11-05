export interface PublishedAdvisory {
  id: string;
  name: string;
  context: string;
  severity: "High" | "Moderate" | "Low";
  cvss: string;
  credit: "Finder" | "Reporter";
}

export interface AdvisoryGroup {
  title: string;
  description: string;
  articleSlug: string;
  advisories: PublishedAdvisory[];
}

const advisory = (
  id: string,
  name: string,
  context: string,
  severity: PublishedAdvisory["severity"],
  cvss: string,
  credit: PublishedAdvisory["credit"],
): PublishedAdvisory => ({ id, name, context, severity, cvss, credit });

export const advisoryGroups: AdvisoryGroup[] = [
  {
    title: "Gas, copies, and host-side work",
    description: "The VM accepted work the gas meter could not stop in time, or charged nothing for a state snapshot.",
    articleSlug: "the-bill-comes-after-the-body",
    advisories: [
      advisory("GHSA-cg9c-gcgh-qgc3", "MBufferSetRandom", "Caller-sized allocation before an unbounded gas record", "High", "7.7", "Reporter"),
      advisory("GHSA-3xw3-gjh2-5j94", "readKDATransfers", "Repeated handle references cloned a buffer once per vector entry", "High", "7.5", "Finder"),
      advisory("GHSA-qqr9-92pp-89p7", "ReadManagedVecOfManagedBuffers", "Repeated handles amplified buffer clones in a managed vector", "High", "7.5", "Reporter"),
      advisory("GHSA-r2gq-244g-h8p2", "BigIntShl", "The shift result was allocated before its size-based charge", "High", "7.5", "Reporter"),
      advisory("GHSA-gjm9-w2m6-rmp9", "PushState", "Nested execution deep-copied bigint handles without clone gas", "Moderate", "5.3", "Reporter"),
    ],
  },
  {
    title: "Integer overflow at managed-buffer boundaries",
    description: "Three byte-slice imports checked offsets with signed 32-bit addition before converting to the host index type.",
    articleSlug: "the-addition-overflowed-before-the-bounds-check",
    advisories: [
      advisory("GHSA-2m22-3m34-2qxf", "MBufferCopyByteSlice", "An overflowing end offset passed validation and panicked during slicing", "High", "7.5", "Finder"),
      advisory("GHSA-vxf6-vgpv-822h", "MBufferGetByteSlice", "The read path used the same narrowing end-offset check", "High", "7.5", "Reporter"),
      advisory("GHSA-wjrx-39g9-j97q", "MBufferSetByteSlice", "A large start offset wrapped even with the 16 MiB length cap", "High", "7.5", "Finder"),
    ],
  },
  {
    title: "Transfer rules and asset controls",
    description: "Some paths moved restricted balances through direct accounting calls; other update paths forgot a stop flag already enforced by a sibling path.",
    articleSlug: "the-rule-was-set-the-operation-still-went-through",
    advisories: [
      advisory("GHSA-3rvr-m2w2-ggqj", "Marketplace Buy and settlement", "Order-currency balance moves skipped pause and transfer-policy checks", "Moderate", "4.3", "Reporter"),
      advisory("GHSA-vjj9-8392-w5hw", "ITO purchases", "ITO payment and royalty paths moved paused or restricted currencies", "Moderate", "4.3", "Finder"),
      advisory("GHSA-h45p-mxgj-59f8", "FPR deposit and claim", "Staking deposits and matured rewards bypassed reward-currency policy", "Moderate", "4.3", "Reporter"),
      advisory("GHSA-344r-g6cw-g546", "Royalty receiver updates", "The receiver could still be rewritten after royalty changes were stopped", "Moderate", "6.5", "Reporter"),
      advisory("GHSA-54v2-fp39-5w66", "SFT metadata updates", "The SFT update path ignored the metadata-stop flag", "Moderate", "6.5", "Reporter"),
    ],
  },
  {
    title: "Supply, rewards, and rounding",
    description: "Integer overflow and floating-point conversion broke different invariants in supply caps, validator fee allocation, and missed-slot penalties.",
    articleSlug: "overflow-rounding-and-a-cap-that-stopped-being-a-cap",
    advisories: [
      advisory("GHSA-wx97-fhvf-42vg", "Staking-claim supply cap", "An int64 addition wrapped before the MaxSupply comparison", "Moderate", "6.5", "Finder"),
      advisory("GHSA-w99g-8m9m-jrf7", "DecreaseAll penalty rounding", "An attempted ceiling division added a penalty on exact divisions", "Moderate", "4.8", "Reporter"),
      advisory("GHSA-x5mg-959h-f66v", "Validator fee split", "Float64 truncation shifted integer fee units from validators to the leader", "Low", "3.7", "Reporter"),
    ],
  },
  {
    title: "Node liveness and resource cleanup",
    description: "A startup-time nil dereference, a peer-held stream, and nested output merging each left a node vulnerable to a different form of availability failure.",
    articleSlug: "the-work-that-outlives-the-request",
    advisories: [
      advisory("GHSA-v8j2-98j2-rqv2", "P2P direct stream read deadline", "A connected peer could pin a goroutine by opening a stream and sending nothing", "High", "7.5", "Reporter"),
      advisory("GHSA-hw69-3fg8-wrmm", "Nested DeletedAccounts growth", "Successful sibling calls repeatedly duplicated inherited output entries", "High", "7.5", "Reporter"),
      advisory("GHSA-g797-9c85-644m", "Available allowance query", "A nil block header dereference in a helper goroutine terminated the process", "Moderate", "5.9", "Reporter"),
    ],
  },
];

export const publishedAdvisoryCount = advisoryGroups.reduce(
  (count, group) => count + group.advisories.length,
  0,
);
