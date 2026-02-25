using System;
using System.Collections.Generic;

namespace Tuteliq
{
    // =========================================================================
    // Context
    // =========================================================================

    /// <summary>
    /// Optional context for analysis.
    /// </summary>
    [Serializable]
    public class AnalysisContext
    {
        public string Language;
        public string AgeGroup;
        public string Relationship;
        public string Platform;
    }

    // =========================================================================
    // Messages
    // =========================================================================

    /// <summary>
    /// Message for grooming detection.
    /// </summary>
    [Serializable]
    public class GroomingMessage
    {
        public MessageRole Role;
        public string Content;

        public GroomingMessage() { }

        public GroomingMessage(MessageRole role, string content)
        {
            Role = role;
            Content = content;
        }
    }

    /// <summary>
    /// Message for emotion analysis.
    /// </summary>
    [Serializable]
    public class EmotionMessage
    {
        public string Sender;
        public string Content;

        public EmotionMessage() { }

        public EmotionMessage(string sender, string content)
        {
            Sender = sender;
            Content = content;
        }
    }

    /// <summary>
    /// Message for incident reports.
    /// </summary>
    [Serializable]
    public class ReportMessage
    {
        public string Sender;
        public string Content;

        public ReportMessage() { }

        public ReportMessage(string sender, string content)
        {
            Sender = sender;
            Content = content;
        }
    }

    // =========================================================================
    // Input Types
    // =========================================================================

    /// <summary>
    /// Input for bullying detection.
    /// </summary>
    public class DetectBullyingInput
    {
        public string Content;
        public AnalysisContext Context;
        public string ExternalId;
        /// <summary>Your end-customer identifier for multi-tenant / B2B2C routing (max 255 chars).</summary>
        public string CustomerId;
        public Dictionary<string, object> Metadata;
    }

    /// <summary>
    /// Input for grooming detection.
    /// </summary>
    public class DetectGroomingInput
    {
        public List<GroomingMessage> Messages;
        public int? ChildAge;
        public AnalysisContext Context;
        public string ExternalId;
        /// <summary>Your end-customer identifier for multi-tenant / B2B2C routing (max 255 chars).</summary>
        public string CustomerId;
        public Dictionary<string, object> Metadata;
    }

    /// <summary>
    /// Input for unsafe content detection.
    /// </summary>
    public class DetectUnsafeInput
    {
        public string Content;
        public AnalysisContext Context;
        public string ExternalId;
        /// <summary>Your end-customer identifier for multi-tenant / B2B2C routing (max 255 chars).</summary>
        public string CustomerId;
        public Dictionary<string, object> Metadata;
    }

    /// <summary>
    /// Input for quick analysis.
    /// </summary>
    public class AnalyzeInput
    {
        public string Content;
        public AnalysisContext Context;
        public List<string> Include;
        public string ExternalId;
        /// <summary>Your end-customer identifier for multi-tenant / B2B2C routing (max 255 chars).</summary>
        public string CustomerId;
        public Dictionary<string, object> Metadata;
    }

    /// <summary>
    /// Input for emotion analysis.
    /// </summary>
    public class AnalyzeEmotionsInput
    {
        public string Content;
        public List<EmotionMessage> Messages;
        public AnalysisContext Context;
        public string ExternalId;
        /// <summary>Your end-customer identifier for multi-tenant / B2B2C routing (max 255 chars).</summary>
        public string CustomerId;
        public Dictionary<string, object> Metadata;
    }

    /// <summary>
    /// Input for action plan generation.
    /// </summary>
    public class GetActionPlanInput
    {
        public string Situation;
        public int? ChildAge;
        public Audience? Audience;
        public Severity? Severity;
        public string ExternalId;
        /// <summary>Your end-customer identifier for multi-tenant / B2B2C routing (max 255 chars).</summary>
        public string CustomerId;
        public Dictionary<string, object> Metadata;
    }

    /// <summary>
    /// Input for incident report generation.
    /// </summary>
    public class GenerateReportInput
    {
        public List<ReportMessage> Messages;
        public int? ChildAge;
        public string IncidentType;
        public string ExternalId;
        /// <summary>Your end-customer identifier for multi-tenant / B2B2C routing (max 255 chars).</summary>
        public string CustomerId;
        public Dictionary<string, object> Metadata;
    }

    // =========================================================================
    // Result Types
    // =========================================================================

    /// <summary>
    /// Result of bullying detection.
    /// </summary>
    [Serializable]
    public class BullyingResult
    {
        public bool IsBullying;
        public Severity Severity;
        public List<string> BullyingType;
        public float Confidence;
        public string Rationale;
        public float RiskScore;
        public string RecommendedAction;
        public string Language;
        public string LanguageStatus;
        public int? CreditsUsed;
        public string ExternalId;
        public string CustomerId;
        public Dictionary<string, object> Metadata;
    }

    /// <summary>
    /// Result of grooming detection.
    /// </summary>
    [Serializable]
    public class GroomingResult
    {
        public GroomingRisk GroomingRisk;
        public List<string> Flags;
        public float Confidence;
        public string Rationale;
        public float RiskScore;
        public string RecommendedAction;
        public List<MessageAnalysis> MessageAnalysis;
        public string Language;
        public string LanguageStatus;
        public int? CreditsUsed;
        public string ExternalId;
        public string CustomerId;
        public Dictionary<string, object> Metadata;
    }

    /// <summary>
    /// Result of unsafe content detection.
    /// </summary>
    [Serializable]
    public class UnsafeResult
    {
        public bool Unsafe;
        public List<string> Categories;
        public Severity Severity;
        public float Confidence;
        public string Rationale;
        public float RiskScore;
        public string RecommendedAction;
        public string Language;
        public string LanguageStatus;
        public int? CreditsUsed;
        public string ExternalId;
        public string CustomerId;
        public Dictionary<string, object> Metadata;
    }

    /// <summary>
    /// Result of quick analysis.
    /// </summary>
    [Serializable]
    public class AnalyzeResult
    {
        public RiskLevel RiskLevel;
        public float RiskScore;
        public string Summary;
        public string RecommendedAction;
        public BullyingResult Bullying;
        public UnsafeResult Unsafe;
        public int? CreditsUsed;
        public string ExternalId;
        public string CustomerId;
        public Dictionary<string, object> Metadata;
    }

    /// <summary>
    /// Result of emotion analysis.
    /// </summary>
    [Serializable]
    public class EmotionsResult
    {
        public List<string> DominantEmotions;
        public EmotionTrend Trend;
        public float Intensity;
        public List<string> ConcerningPatterns;
        public string RecommendedFollowup;
        public int? CreditsUsed;
        public string ExternalId;
        public string CustomerId;
        public Dictionary<string, object> Metadata;
    }

    /// <summary>
    /// Result of action plan generation.
    /// </summary>
    [Serializable]
    public class ActionPlanResult
    {
        public List<string> Steps;
        public string Tone;
        public List<string> Resources;
        public string Urgency;
        public int? CreditsUsed;
        public string ExternalId;
        public string CustomerId;
        public Dictionary<string, object> Metadata;
    }

    /// <summary>
    /// Result of incident report generation.
    /// </summary>
    [Serializable]
    public class ReportResult
    {
        public string Summary;
        public RiskLevel RiskLevel;
        public List<string> Timeline;
        public List<string> KeyEvidence;
        public List<string> RecommendedNextSteps;
        public int? CreditsUsed;
        public string ExternalId;
        public string CustomerId;
        public Dictionary<string, object> Metadata;
    }

    // =========================================================================
    // Account Management (GDPR)
    // =========================================================================

    /// <summary>
    /// Result of account data deletion (GDPR Article 17).
    /// </summary>
    [Serializable]
    public class AccountDeletionResult
    {
        public string Message;
        public int DeletedCount;
    }

    /// <summary>
    /// Result of account data export (GDPR Article 20).
    /// </summary>
    [Serializable]
    public class AccountExportResult
    {
        public string UserId;
        public string ExportedAt;
        public Dictionary<string, object> Data;
    }

    // =========================================================================
    // Consent Management (GDPR Article 7)
    // =========================================================================

    [Serializable]
    public class ConsentRecord
    {
        public string Id;
        public string UserId;
        public string ConsentType;
        public string Status;
        public string Version;
        public string CreatedAt;
    }

    [Serializable]
    public class ConsentActionResult
    {
        public string Message;
        public ConsentRecord Consent;
    }

    [Serializable]
    public class ConsentStatusResult
    {
        public List<ConsentRecord> Consents;
    }

    public class RecordConsentInput
    {
        public string ConsentType;
        public string Version;
    }

    public class RectifyDataInput
    {
        public string Collection;
        public string DocumentId;
        public Dictionary<string, object> Fields;
    }

    [Serializable]
    public class RectifyDataResult
    {
        public string Message;
        public List<string> UpdatedFields;
    }

    [Serializable]
    public class AuditLogEntry
    {
        public string Id;
        public string UserId;
        public string Action;
        public string CreatedAt;
        public Dictionary<string, object> Details;
    }

    [Serializable]
    public class AuditLogsResult
    {
        public List<AuditLogEntry> AuditLogs;
    }

    /// <summary>
    /// API usage information.
    /// </summary>
    [Serializable]
    public class Usage
    {
        public int Limit;
        public int Used;
        public int Remaining;
    }

    // =========================================================================
    // Breach Management (GDPR Article 33/34)
    // =========================================================================

    public class LogBreachInput
    {
        public string Title;
        public string Description;
        public string Severity;
        public List<string> AffectedUserIds;
        public List<string> DataCategories;
        public string ReportedBy;
    }

    public class UpdateBreachInput
    {
        public string Status;
        public string NotificationStatus;
        public string Notes;
    }

    [Serializable]
    public class BreachRecord
    {
        public string Id;
        public string Title;
        public string Description;
        public string Severity;
        public string Status;
        public string NotificationStatus;
        public List<string> AffectedUserIds;
        public List<string> DataCategories;
        public string ReportedBy;
        public string NotificationDeadline;
        public string CreatedAt;
        public string UpdatedAt;
    }

    [Serializable]
    public class LogBreachResult
    {
        public string Message;
        public BreachRecord Breach;
    }

    [Serializable]
    public class BreachListResult
    {
        public List<BreachRecord> Breaches;
    }

    [Serializable]
    public class BreachResult
    {
        public BreachRecord Breach;
    }

    // =========================================================================
    // Voice Analysis
    // =========================================================================

    [Serializable]
    public class TranscriptionSegment
    {
        public double Start;
        public double End;
        public string Text;
    }

    [Serializable]
    public class TranscriptionResult
    {
        public string Text;
        public string Language;
        public double? Duration;
        public List<TranscriptionSegment> Segments;
    }

    [Serializable]
    public class VoiceAnalysisResult
    {
        public string FileId;
        public TranscriptionResult Transcription;
        public Dictionary<string, object> Analysis;
        public double? OverallRiskScore;
        public string OverallSeverity;
        public int? CreditsUsed;
        public string ExternalId;
        public string CustomerId;
        public Dictionary<string, object> Metadata;
    }

    // =========================================================================
    // Image Analysis
    // =========================================================================

    [Serializable]
    public class VisionResult
    {
        public string ExtractedText;
        public List<string> VisualCategories;
        public string VisualSeverity;
        public double? VisualConfidence;
        public string VisualDescription;
        public bool? ContainsText;
        public bool? ContainsFaces;
    }

    [Serializable]
    public class ImageAnalysisResult
    {
        public string FileId;
        public VisionResult Vision;
        public Dictionary<string, object> TextAnalysis;
        public double? OverallRiskScore;
        public string OverallSeverity;
        public int? CreditsUsed;
        public string ExternalId;
        public string CustomerId;
        public Dictionary<string, object> Metadata;
    }

    // =========================================================================
    // Fraud / Extended Detection
    // =========================================================================

    /// <summary>
    /// Input for fraud and extended detection endpoints.
    /// </summary>
    public class DetectionInput
    {
        public string Content;
        public AnalysisContext Context;
        public bool IncludeEvidence;
        public string ExternalId;
        /// <summary>Your end-customer identifier for multi-tenant / B2B2C routing (max 255 chars).</summary>
        public string CustomerId;
        public Dictionary<string, object> Metadata;
    }

    /// <summary>
    /// Input for multi-endpoint analysis.
    /// </summary>
    public class AnalyseMultiInput
    {
        public string Content;
        public List<Detection> Detections;
        public AnalysisContext Context;
        public bool IncludeEvidence;
        public string ExternalId;
        /// <summary>Your end-customer identifier for multi-tenant / B2B2C routing (max 255 chars).</summary>
        public string CustomerId;
        public Dictionary<string, object> Metadata;
    }

    /// <summary>
    /// Per-message analysis from conversation-aware detection.
    /// </summary>
    [Serializable]
    public class MessageAnalysis
    {
        public int MessageIndex;
        public float RiskScore;
        public List<string> Flags;
        public string Summary;
    }

    /// <summary>
    /// A detected category within a detection result.
    /// </summary>
    [Serializable]
    public class DetectionCategory
    {
        public string Tag;
        public string Label;
        public double Confidence;
    }

    /// <summary>
    /// Evidence supporting a detection result.
    /// </summary>
    [Serializable]
    public class DetectionEvidence
    {
        public string Text;
        public string Tactic;
        public double Weight;
    }

    /// <summary>
    /// Age calibration applied to detection scoring.
    /// </summary>
    [Serializable]
    public class AgeCalibration
    {
        public bool Applied;
        public string AgeGroup;
        public double? Multiplier;
    }

    /// <summary>
    /// Result from a single fraud/extended detection endpoint.
    /// </summary>
    [Serializable]
    public class DetectionResult
    {
        public string Endpoint;
        public bool Detected;
        public double Severity;
        public double Confidence;
        public double RiskScore;
        public string Level;
        public List<DetectionCategory> Categories;
        public string RecommendedAction;
        public string Rationale;
        public string Language;
        public string LanguageStatus;
        public List<DetectionEvidence> Evidence;
        public AgeCalibration AgeCalibration;
        public List<MessageAnalysis> MessageAnalysis;
        public int? CreditsUsed;
        public double? ProcessingTimeMs;
        public string ExternalId;
        public string CustomerId;
        public Dictionary<string, object> Metadata;
    }

    /// <summary>
    /// Summary of multi-endpoint analysis results.
    /// </summary>
    [Serializable]
    public class AnalyseMultiSummary
    {
        public int TotalEndpoints;
        public int DetectedCount;
        public Dictionary<string, object> HighestRisk;
        public string OverallRiskLevel;
    }

    /// <summary>
    /// Result of multi-endpoint analysis.
    /// </summary>
    [Serializable]
    public class AnalyseMultiResult
    {
        public List<DetectionResult> Results;
        public AnalyseMultiSummary Summary;
        public double? CrossEndpointModifier;
        public int? CreditsUsed;
        public string ExternalId;
        public string CustomerId;
        public Dictionary<string, object> Metadata;
    }

    // =========================================================================
    // Video Analysis
    // =========================================================================

    /// <summary>
    /// A safety finding from video frame analysis.
    /// </summary>
    [Serializable]
    public class VideoSafetyFinding
    {
        public int FrameIndex;
        public double Timestamp;
        public string Description;
        public List<string> Categories;
        public double Severity;
    }

    /// <summary>
    /// Result of video analysis.
    /// </summary>
    [Serializable]
    public class VideoAnalysisResult
    {
        public string FileId;
        public int FramesAnalyzed;
        public List<VideoSafetyFinding> SafetyFindings;
        public double OverallRiskScore;
        public string OverallSeverity;
        public int? CreditsUsed;
        public string ExternalId;
        public string CustomerId;
        public Dictionary<string, object> Metadata;
    }

    // =========================================================================
    // Webhooks
    // =========================================================================

    [Serializable]
    public class WebhookInfo
    {
        public string Id;
        public string Url;
        public List<string> Events;
        public bool Active;
        public string Secret;
        public string CreatedAt;
        public string UpdatedAt;
    }

    [Serializable]
    public class WebhookListResult
    {
        public List<WebhookInfo> Webhooks;
    }

    public class CreateWebhookInput
    {
        public string Url;
        public List<string> Events;
        public bool Active = true;
    }

    [Serializable]
    public class CreateWebhookResult
    {
        public string Message;
        public WebhookInfo Webhook;
    }

    public class UpdateWebhookInput
    {
        public string Url;
        public List<string> Events;
        public bool? Active;
    }

    [Serializable]
    public class UpdateWebhookResult
    {
        public string Message;
        public WebhookInfo Webhook;
    }

    [Serializable]
    public class DeleteWebhookResult
    {
        public string Message;
    }

    [Serializable]
    public class TestWebhookResult
    {
        public string Message;
        public int? StatusCode;
    }

    [Serializable]
    public class RegenerateSecretResult
    {
        public string Message;
        public string Secret;
    }

    // =========================================================================
    // Pricing
    // =========================================================================

    [Serializable]
    public class PricingPlan
    {
        public string Name;
        public string Price;
        public string Messages;
        public List<string> Features;
    }

    [Serializable]
    public class PricingResult
    {
        public List<PricingPlan> Plans;
    }

    [Serializable]
    public class PricingDetailPlan
    {
        public string Name;
        public string Tier;
        public Dictionary<string, object> Price;
        public Dictionary<string, object> Limits;
        public Dictionary<string, object> Features;
        public List<string> Endpoints;
    }

    [Serializable]
    public class PricingDetailsResult
    {
        public List<PricingDetailPlan> Plans;
    }

    // =========================================================================
    // Usage
    // =========================================================================

    [Serializable]
    public class UsageDay
    {
        public string Date;
        public int TotalRequests;
        public int SuccessRequests;
        public int ErrorRequests;
    }

    [Serializable]
    public class UsageHistoryResult
    {
        public string ApiKeyId;
        public List<UsageDay> Days;
    }

    [Serializable]
    public class UsageByToolResult
    {
        public string Date;
        public Dictionary<string, int> Tools;
        public Dictionary<string, int> Endpoints;
    }

    [Serializable]
    public class UsageMonthlyResult
    {
        public string Tier;
        public string TierDisplayName;
        public Dictionary<string, object> Billing;
        public Dictionary<string, object> UsageInfo;
        public Dictionary<string, object> RateLimit;
        public Dictionary<string, object> Recommendations;
        public Dictionary<string, object> Links;
    }
}
