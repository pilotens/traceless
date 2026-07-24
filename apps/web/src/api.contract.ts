/** Compile-time checks preventing handwritten UI contracts from drifting from OpenAPI. */

import type {
  ArchitectureGraphInput as GeneratedArchitectureGraphInput,
  ArchitectureRiskContextInput as GeneratedArchitectureRiskContextInput,
  CurrentPrincipalResponse,
  ExternalIntelligenceCheckpointView,
  ExternalIntelligenceConnectorUpdate as GeneratedExternalIntelligenceConnectorUpdate,
  ExternalIntelligenceConnectorView as GeneratedExternalIntelligenceConnectorView,
  ExternalIntelligencePullResult as GeneratedExternalIntelligencePullResult,
  ExternalIntelligenceSyncRunList as GeneratedExternalIntelligenceSyncRunList,
  ExternalIntelligenceSyncRunView,
  ExternalIntelligenceSyncStatus as GeneratedExternalIntelligenceSyncStatus,
  FindingSummaryView,
  FindingView,
  GlobalIntelRecordView,
  IntelReviewResult as GeneratedIntelReviewResult,
  PageFindingSummaryView,
  PageRiskSummaryView,
  PageVulnerabilityObservationSummaryView,
  PipelineOverview as GeneratedPipelineOverview,
  ReportView,
  RiskSummaryView,
  VulnerabilityObservationSummaryView,
} from './generated/traceless-api/contracts';
import type {
  ArchitectureGraphInput,
  ArchitectureRiskContextInput,
  ExternalIntelligenceCheckpoint,
  ExternalIntelligenceConnectorUpdate,
  ExternalIntelligenceConnectorView,
  ExternalIntelligencePullResult,
  ExternalIntelligenceSyncRun,
  ExternalIntelligenceSyncRunList,
  ExternalIntelligenceSyncStatus,
  Finding,
  FindingSummary,
  GlobalIntelRecord,
  IntelReviewResult,
  OperationalPrincipal,
  Page,
  PipelineOverview,
  Report,
  RiskSummary,
  VulnerabilityObservationSummary,
} from './api';

type Equivalent<Left, Right> = [Left] extends [Right]
  ? [Right] extends [Left]
    ? true
    : false
  : false;
type Assert<Value extends true> = Value;

type PrincipalContract = Assert<Equivalent<OperationalPrincipal, CurrentPrincipalResponse>>;
type ArchitectureGraphContract = Assert<
  ArchitectureGraphInput extends GeneratedArchitectureGraphInput ? true : false
>;
type ArchitectureRiskContextContract = Assert<
  ArchitectureRiskContextInput extends GeneratedArchitectureRiskContextInput ? true : false
>;
type ConnectorUpdateContract = Assert<
  ExternalIntelligenceConnectorUpdate extends GeneratedExternalIntelligenceConnectorUpdate
    ? true
    : false
>;
type ConnectorViewContract = Assert<
  Equivalent<ExternalIntelligenceConnectorView, GeneratedExternalIntelligenceConnectorView>
>;
type ConnectorCheckpointContract = Assert<
  Equivalent<ExternalIntelligenceCheckpoint, ExternalIntelligenceCheckpointView>
>;
type ConnectorRunContract = Assert<
  Equivalent<ExternalIntelligenceSyncRun, ExternalIntelligenceSyncRunView>
>;
type ConnectorRunListContract = Assert<
  Equivalent<ExternalIntelligenceSyncRunList, GeneratedExternalIntelligenceSyncRunList>
>;
type ConnectorStatusContract = Assert<
  Equivalent<ExternalIntelligenceSyncStatus, GeneratedExternalIntelligenceSyncStatus>
>;
type ConnectorPullContract = Assert<
  ExternalIntelligencePullResult extends GeneratedExternalIntelligencePullResult ? true : false
>;
type GlobalIntelRecordContract = Assert<Equivalent<GlobalIntelRecord, GlobalIntelRecordView>>;
type IntelReviewContract = Assert<
  IntelReviewResult extends GeneratedIntelReviewResult ? true : false
>;
type FindingContract = Assert<Equivalent<Finding, FindingView>>;
type FindingSummaryContract = Assert<Equivalent<FindingSummary, FindingSummaryView>>;
type RiskSummaryContract = Assert<Equivalent<RiskSummary, RiskSummaryView>>;
type ObservationSummaryContract = Assert<
  Equivalent<VulnerabilityObservationSummary, VulnerabilityObservationSummaryView>
>;
type OverviewContract = Assert<
  GeneratedPipelineOverview extends PipelineOverview ? true : false
>;
type ReportContract = Assert<Equivalent<Report, ReportView>>;
type FindingPageContract = Assert<Equivalent<Page<FindingSummary>, PageFindingSummaryView>>;
type RiskPageContract = Assert<Equivalent<Page<RiskSummary>, PageRiskSummaryView>>;
type ObservationPageContract = Assert<
  Equivalent<Page<VulnerabilityObservationSummary>, PageVulnerabilityObservationSummaryView>
>;

export type ApiContractAssertions = [
  PrincipalContract,
  ArchitectureGraphContract,
  ArchitectureRiskContextContract,
  ConnectorUpdateContract,
  ConnectorViewContract,
  ConnectorCheckpointContract,
  ConnectorRunContract,
  ConnectorRunListContract,
  ConnectorStatusContract,
  ConnectorPullContract,
  GlobalIntelRecordContract,
  IntelReviewContract,
  FindingContract,
  FindingSummaryContract,
  RiskSummaryContract,
  ObservationSummaryContract,
  OverviewContract,
  ReportContract,
  FindingPageContract,
  RiskPageContract,
  ObservationPageContract,
];
