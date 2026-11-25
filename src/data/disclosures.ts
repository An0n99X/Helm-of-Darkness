export type DisclosureKind = "GHSA" | "Accepted fix" | "Accepted report";
export type Severity = "High" | "Moderate" | "Low" | "Accepted";

export interface Disclosure {
  id: string;
  project: "Klever Go" | "FFmpeg";
  kind: DisclosureKind;
  severity: Severity;
  category: string;
  title: string;
  summary: string;
  impact: string;
  credit?: "Finder" | "Reporter";
  date: string;
  url?: string;
  cvss?: string;
  cvssVector?: string;
  programStatus?: string;
  sourceProgram?: string;
}

const kleverAdvisory = (
  id: string,
  title: string,
  category: string,
  severity: Exclude<Severity, "Accepted">,
  credit: "Finder" | "Reporter",
  summary: string,
  impact: string,
  date = "2026-10",
): Disclosure => ({
  id,
  project: "Klever Go",
  kind: "GHSA",
  severity,
  category,
  title,
  summary,
  impact,
  credit,
  date,
  url: `https://github.com/klever-io/klever-go/security/advisories/${id}`,
});

export const disclosures: Disclosure[] = [
  kleverAdvisory("GHSA-cg9c-gcgh-qgc3", "Caller-sized allocation before gas is recorded", "VM & gas accounting", "High", "Reporter", "MBufferSetRandom allocated from caller-controlled size before bounded gas accounting could stop the work.", "A crafted call can force excessive validator memory use.", "2026-09"),
  kleverAdvisory("GHSA-3xw3-gjh2-5j94", "Repeated handles multiply buffer clones", "VM & gas accounting", "High", "Finder", "readKDATransfers cloned a buffer once per vector entry before the cost was bounded.", "Repeated references can amplify work and exhaust node resources."),
  kleverAdvisory("GHSA-qqr9-92pp-89p7", "Managed-vector reads amplify clone work", "VM & gas accounting", "High", "Reporter", "Repeated managed-buffer handles caused exponential clone amplification in a managed-vector read.", "A smart-contract call can drive validator and node resource exhaustion."),
  kleverAdvisory("GHSA-r2gq-244g-h8p2", "Big integer allocation happens before its charge", "VM & gas accounting", "High", "Reporter", "BigIntShl allocated the shift result before gas was charged for the result size.", "Large intermediate values can consume host resources before metering catches up."),
  kleverAdvisory("GHSA-gjm9-w2m6-rmp9", "Nested state snapshots bypass clone gas", "VM & gas accounting", "Moderate", "Reporter", "PushState deep-copied bigint handles during nested execution without charging for the clones.", "Nested calls can impose unmetered host-side copying."),
  kleverAdvisory("GHSA-2m22-3m34-2qxf", "Copy bounds check can wrap before slicing", "Integer bounds", "High", "Finder", "MBufferCopyByteSlice used signed 32-bit addition for the end offset before converting it to a host index.", "An overflowing range passes validation and panics during slicing.", "2026-09"),
  kleverAdvisory("GHSA-vxf6-vgpv-822h", "Read bounds check can wrap before slicing", "Integer bounds", "High", "Reporter", "MBufferGetByteSlice used the same narrowing end-offset check on the read path.", "A crafted range can bypass validation and panic the VM.", "2026-09"),
  kleverAdvisory("GHSA-wjrx-39g9-j97q", "Set bounds check can wrap at a large offset", "Integer bounds", "High", "Finder", "MBufferSetByteSlice allowed the start offset to wrap despite a 16 MiB length cap.", "An invalid write range can pass the check and panic during slicing.", "2026-09"),
  kleverAdvisory("GHSA-3rvr-m2w2-ggqj", "Marketplace settlement skips transfer policy", "Protocol controls", "Moderate", "Reporter", "Marketplace buy and settlement paths moved order-currency balances without pause and transfer-policy checks.", "Restricted balances can move through a path that bypasses the currency controls."),
  kleverAdvisory("GHSA-vjj9-8392-w5hw", "ITO purchases bypass currency restrictions", "Protocol controls", "Moderate", "Finder", "ITO payment and royalty paths moved paused or transfer-restricted currencies.", "A purchase can route balances around the expected transfer rules."),
  kleverAdvisory("GHSA-h45p-mxgj-59f8", "FPR deposits and claims skip reward policy", "Protocol controls", "Moderate", "Reporter", "FPR staking deposits and matured rewards bypassed reward-currency transfer policy.", "Restricted reward balances can be routed through staking paths."),
  kleverAdvisory("GHSA-344r-g6cw-g546", "Royalty receiver stays editable after the stop flag", "Protocol controls", "Moderate", "Reporter", "updateRoyaltiesReceiver did not check whether royalty changes had been stopped.", "The receiver can still be rewritten after the protocol disables royalty changes."),
  kleverAdvisory("GHSA-54v2-fp39-5w66", "SFT metadata update ignores its stop flag", "Protocol controls", "Moderate", "Reporter", "updateMetadataV2 omitted the metadata-change stop check enforced by a sibling path.", "SFT metadata remains mutable after updates are meant to be frozen."),
  kleverAdvisory("GHSA-wx97-fhvf-42vg", "Supply-cap addition overflows before comparison", "Token economics", "Moderate", "Finder", "The staking-claim path added two int64 values before comparing the result with MaxSupply.", "Integer wraparound can bypass the supply cap and permit excess minting."),
  kleverAdvisory("GHSA-w99g-8m9m-jrf7", "Exact division adds an unintended penalty", "Token economics", "Moderate", "Reporter", "DecreaseAll used a ceiling-division adjustment that added a penalty even when division was exact.", "Validator penalties can be overstated on exact divisions."),
  kleverAdvisory("GHSA-x5mg-959h-f66v", "Float rounding shifts fee units", "Token economics", "Low", "Reporter", "Float64 truncation changed the integer split between validators and the block leader.", "Fee units can be misallocated during validator reward distribution."),
  kleverAdvisory("GHSA-v8j2-98j2-rqv2", "A peer can hold a stream open indefinitely", "P2P & node liveness", "High", "Reporter", "directStreamHandler did not set a read deadline before waiting for peer data.", "A connected peer can pin a goroutine per open stream.", "2026-09"),
  kleverAdvisory("GHSA-hw69-3fg8-wrmm", "Nested output merges grow deleted-account data", "P2P & node liveness", "High", "Reporter", "Successful sibling calls repeatedly duplicated inherited DeletedAccounts entries during output merging.", "Nested VM execution can amplify memory and delay validators."),
  kleverAdvisory("GHSA-g797-9c85-644m", "Missing block header crashes allowance lookup", "P2P & node liveness", "Moderate", "Reporter", "GetAvailableClaim dereferenced a nil current block header in a helper goroutine.", "An API allowance query can terminate the node process.", "2026-09"),
  {
    id: "YWH-PGM40646-17",
    project: "FFmpeg",
    kind: "Accepted report",
    severity: "High",
    category: "Native memory safety",
    title: "Odd-sized frames trigger an over-read in downscale()",
    summary: "In vf_find_rect.c, downscale() rounds odd input dimensions up for the output mipmap, then reads every output sample as a full 2×2 input block. The final sample can cross the valid input data by one byte.",
    impact: "Processing a crafted frame can read adjacent heap data or crash the process.",
    date: "2025-12-14",
    cvss: "8.2",
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H",
    programStatus: "Accepted · fix confirmed",
    sourceProgram: "FFmpeg Bug Bounty Program",
  },
  {
    id: "YWH-PGM40646-15",
    project: "FFmpeg",
    kind: "Accepted report",
    severity: "High",
    category: "Native memory safety",
    title: "find_rect compare() reads past the haystack frame",
    summary: "In vf_find_rect.c, search bounds can extend beyond the haystack dimensions. compare() then walks the object width without checking each read against the remaining haystack row.",
    impact: "An out-of-bounds heap read can expose adjacent data or crash FFmpeg while comparing pixels.",
    date: "2025-12-13",
    cvss: "8.2",
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H",
    programStatus: "Accepted · fix confirmed",
    sourceProgram: "FFmpeg Bug Bounty Program",
  },
  {
    id: "YWH-PGM40646-14",
    project: "FFmpeg",
    kind: "Accepted report",
    severity: "Low",
    category: "Integer bounds",
    title: "Scale expression division by zero feeds overflowing dimensions",
    summary: "A scale expression can divide by zero in expression evaluation. The resulting extreme value is not rejected before ff_scale_adjust_dimensions() performs further dimension arithmetic at scale_eval.c:144.",
    impact: "The chained signed integer overflow can produce invalid scale dimensions and a processing failure.",
    date: "2025-12-13",
    cvss: "3.7",
    cvssVector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
    programStatus: "Accepted · fix confirmed",
    sourceProgram: "FFmpeg Bug Bounty Program",
  },
  {
    id: "Klever Go · v1.7.22",
    project: "Klever Go",
    kind: "Accepted fix",
    severity: "Accepted",
    category: "Protocol controls",
    title: "FPR epoch trim handles the boundary cleanly",
    summary: "An accepted upstream fix for FPR epoch trimming shipped without a separate advisory.",
    impact: "The epoch-boundary cleanup is recorded as an upstream contribution.",
    date: "2026-10",
    url: "https://github.com/klever-io/klever-go/releases/tag/v1.7.22",
  },
  {
    id: "Klever Go · v1.7.22",
    project: "Klever Go",
    kind: "Accepted fix",
    severity: "Accepted",
    category: "Protocol controls",
    title: "Expired FPR residuals route correctly",
    summary: "An accepted upstream fix corrected residual routing after FPR expiration.",
    impact: "Expired rewards follow the intended protocol accounting path.",
    date: "2026-10",
    url: "https://github.com/klever-io/klever-go/releases/tag/v1.7.22",
  },
  {
    id: "Klever Go · v1.7.22",
    project: "Klever Go",
    kind: "Accepted fix",
    severity: "Accepted",
    category: "VM & gas accounting",
    title: "BigInt setter and getter gas ordering fixed",
    summary: "An accepted fix corrected gas-charging order around BigInt setter and getter work.",
    impact: "Metering now accounts for the operation in the intended order.",
    date: "2026-10",
    url: "https://github.com/klever-io/klever-go/releases/tag/v1.7.22",
  },
  {
    id: "Klever Go · v1.7.22",
    project: "Klever Go",
    kind: "Accepted fix",
    severity: "Accepted",
    category: "VM & gas accounting",
    title: "Managed-vector charging happens per item",
    summary: "An accepted fix moved managed-vector charging to a per-item basis.",
    impact: "Metering tracks repeated vector work instead of charging only once for the whole operation.",
    date: "2026-10",
    url: "https://github.com/klever-io/klever-go/releases/tag/v1.7.22",
  },
];

export const publishedAdvisoryCount = disclosures.filter((item) => item.kind === "GHSA").length;
export const acceptedFixCount = disclosures.filter((item) => item.kind === "Accepted fix").length;
export const acceptedReportCount = disclosures.filter((item) => item.kind === "Accepted report").length;
