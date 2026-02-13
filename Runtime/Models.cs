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
}
