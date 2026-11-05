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
    title: "Pay After the Work",
    description: "Gas could not stop expensive VM work in time, or a nested state snapshot was copied without a clone charge.",
    articleSlug: "the-bill-comes-after-the-body",
    advisories: [
      advisory("GHSA-cg9c-gcgh-qgc3", "MBufferSetRandom", "Two Gigs on a Thousand Gas — caller-sized allocation before an unbounded gas record", "High", "7.7", "Reporter"),
      advisory("GHSA-3xw3-gjh2-5j94", "readKDATransfers", "The Photocopier Tax — repeated handle references cloned a buffer once per vector entry", "High", "7.5", "Finder"),
      advisory("GHSA-r2gq-244g-h8p2", "BigIntShl", "Shift Happens — the result was allocated before its size-based charge", "High", "7.5", "Reporter"),
      advisory("GHSA-gjm9-w2m6-rmp9", "PushState", "Handle With Care — nested execution deep-copied bigints without clone gas", "Moderate", "5.3", "Reporter"),
    ],
  },
  {
    title: "Wraparound",
    description: "Four advisories show how narrow addition can turn an invalid range or oversized supply into a value that passes its check.",
    articleSlug: "the-addition-overflowed-before-the-bounds-check",
    advisories: [
      advisory("GHSA-2m22-3m34-2qxf", "MBufferCopyByteSlice", "An overflowing end offset passed validation and panicked during slicing", "High", "7.5", "Finder"),
      advisory("GHSA-vxf6-vgpv-822h", "MBufferGetByteSlice", "The read path used the same narrowing end-offset check", "High", "7.5", "Reporter"),
      advisory("GHSA-wjrx-39g9-j97q", "MBufferSetByteSlice", "A large start offset wrapped even with the 16 MiB length cap", "High", "7.5", "Finder"),
      advisory("GHSA-wx97-fhvf-42vg", "Staking-claim supply cap", "Larger Is Smaller — an int64 addition wrapped before the MaxSupply comparison", "Moderate", "6.5", "Finder"),
    ],
  },
  {
    title: "Paused, Except When Shopping",
    description: "Some paths moved restricted balances through direct accounting calls; other update paths forgot a stop flag already enforced by a sibling path.",
    articleSlug: "the-rule-was-set-the-operation-still-went-through",
    advisories: [
      advisory("GHSA-3rvr-m2w2-ggqj", "Marketplace Buy and settlement", "The Back Door Bazaar — order settlement skipped pause and transfer-policy checks", "Moderate", "4.3", "Reporter"),
      advisory("GHSA-vjj9-8392-w5hw", "ITO purchases", "Launchpad Loophole — ITO payments moved paused or restricted currencies", "Moderate", "4.3", "Finder"),
      advisory("GHSA-h45p-mxgj-59f8", "FPR deposit and claim", "Rewards Without Rules — deposits and matured rewards bypassed currency policy", "Moderate", "4.3", "Reporter"),
    ],
  },
  {
    title: "Stop Buttons That Weren’t",
    description: "Two authorized asset-update paths ignored stop flags that neighboring update paths enforced.",
    articleSlug: "the-rule-was-set-the-operation-still-went-through",
    advisories: [
      advisory("GHSA-344r-g6cw-g546", "Royalty receiver updates", "Frozen, Allegedly — the receiver could still change after royalty updates were stopped", "Moderate", "6.5", "Reporter"),
      advisory("GHSA-54v2-fp39-5w66", "SFT metadata updates", "Sealed, Then Edited — the SFT update path ignored the metadata-stop flag", "Moderate", "6.5", "Reporter"),
    ],
  },
  {
    title: "Exponential",
    description: "Repeated references and nested calls multiplied host-side allocation and output growth beyond the apparent input size.",
    articleSlug: "the-work-that-outlives-the-request",
    advisories: [
      advisory("GHSA-qqr9-92pp-89p7", "ReadManagedVecOfManagedBuffers", "Mirror, Mirror, 256 MiB — repeated handles amplified managed-buffer clones", "High", "7.5", "Reporter"),
      advisory("GHSA-hw69-3fg8-wrmm", "Nested DeletedAccounts growth", "Doubling the Dead — successful sibling calls repeatedly duplicated inherited output entries", "High", "7.5", "Reporter"),
    ],
  },
  {
    title: "Network Edge",
    description: "A peer could hold a stream open, while a startup-time request could reach a missing block header.",
    articleSlug: "the-work-that-outlives-the-request",
    advisories: [
      advisory("GHSA-v8j2-98j2-rqv2", "P2P direct stream read deadline", "Waiting for Godot (ReadMsg) — a connected peer could pin a goroutine with a silent stream", "High", "7.5", "Reporter"),
      advisory("GHSA-g797-9c85-644m", "Available allowance query", "Nil Is Not a Block — a missing header dereference in a helper goroutine terminated the process", "Moderate", "5.9", "Reporter"),
    ],
  },
  {
    title: "Rounding Dust",
    description: "Floating-point rounding shifted integer fees and added validator penalties on exact division.",
    articleSlug: "overflow-rounding-and-a-cap-that-stopped-being-a-cap",
    advisories: [
      advisory("GHSA-w99g-8m9m-jrf7", "DecreaseAll penalty rounding", "The Ceiling Tax — attempted ceiling division added a penalty on exact divisions", "Moderate", "4.8", "Reporter"),
      advisory("GHSA-x5mg-959h-f66v", "Validator fee split", "Loose Change — float64 truncation shifted fee units from validators to the leader", "Low", "3.7", "Reporter"),
    ],
  },
];

export const publishedAdvisoryCount = advisoryGroups.reduce(
  (count, group) => count + group.advisories.length,
  0,
);
