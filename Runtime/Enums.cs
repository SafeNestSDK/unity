namespace Tuteliq
{
    /// <summary>
    /// Severity level for detected issues.
    /// </summary>
    public enum Severity
    {
        Low,
        Medium,
        High,
        Critical
    }

    /// <summary>
    /// Risk level for grooming detection.
    /// </summary>
    public enum GroomingRisk
    {
        None,
        Low,
        Medium,
        High,
        Critical
    }

    /// <summary>
    /// Overall risk level for content analysis.
    /// </summary>
    public enum RiskLevel
    {
        Safe,
        Low,
        Medium,
        High,
        Critical
    }

    /// <summary>
    /// Emotion trend direction.
    /// </summary>
    public enum EmotionTrend
    {
        Improving,
        Stable,
        Worsening
    }

    /// <summary>
    /// Target audience for action plans.
    /// </summary>
    public enum Audience
    {
        Child,
        Parent,
        Educator,
        Platform
    }

    /// <summary>
    /// Role of message sender in grooming detection.
    /// </summary>
    public enum MessageRole
    {
        Adult,
        Child,
        Unknown
    }

    internal static class EnumExtensions
    {
        public static string ToApiString(this Severity severity)
        {
            return severity.ToString().ToLowerInvariant();
        }

        public static string ToApiString(this GroomingRisk risk)
        {
            return risk.ToString().ToLowerInvariant();
        }

        public static string ToApiString(this RiskLevel level)
        {
            return level.ToString().ToLowerInvariant();
        }

        public static string ToApiString(this EmotionTrend trend)
        {
            return trend.ToString().ToLowerInvariant();
        }

        public static string ToApiString(this Audience audience)
        {
            return audience.ToString().ToLowerInvariant();
        }

        public static string ToApiString(this MessageRole role)
        {
            return role.ToString().ToLowerInvariant();
        }

        public static Severity ParseSeverity(string value)
        {
            return value?.ToLowerInvariant() switch
            {
                "low" => Severity.Low,
                "medium" => Severity.Medium,
                "high" => Severity.High,
                "critical" => Severity.Critical,
                _ => Severity.Low
            };
        }

        public static GroomingRisk ParseGroomingRisk(string value)
        {
            return value?.ToLowerInvariant() switch
            {
                "none" => GroomingRisk.None,
                "low" => GroomingRisk.Low,
                "medium" => GroomingRisk.Medium,
                "high" => GroomingRisk.High,
                "critical" => GroomingRisk.Critical,
                _ => GroomingRisk.None
            };
        }

        public static RiskLevel ParseRiskLevel(string value)
        {
            return value?.ToLowerInvariant() switch
            {
                "safe" => RiskLevel.Safe,
                "low" => RiskLevel.Low,
                "medium" => RiskLevel.Medium,
                "high" => RiskLevel.High,
                "critical" => RiskLevel.Critical,
                _ => RiskLevel.Safe
            };
        }

        public static EmotionTrend ParseEmotionTrend(string value)
        {
            return value?.ToLowerInvariant() switch
            {
                "improving" => EmotionTrend.Improving,
                "stable" => EmotionTrend.Stable,
                "worsening" => EmotionTrend.Worsening,
                _ => EmotionTrend.Stable
            };
        }
    }
}
